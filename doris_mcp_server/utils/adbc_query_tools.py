# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Apache Doris ADBC Query Tools
High-performance data querying using Apache Arrow Flight SQL protocol
"""

import asyncio
import os
import socket
import time
from datetime import datetime
from typing import Any

from ..result_limits import (
    ResultLimitError,
    ResultLimits,
    json_array_row_size,
    resolve_result_limits,
)
from ..utils.db import DorisConnectionManager
from ..utils.doris_http_client import database_config_for_request
from ..utils.logger import get_logger
from ..utils.security import AuthContext
from ..utils.sql_security_utils import get_auth_context

logger = get_logger(__name__)


def _convert_numpy_types(obj: Any) -> Any:
    """Convert numpy types to native Python types for JSON serialization"""
    try:
        # Import numpy only when needed
        import numpy as np
        import pandas as pd

        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, np.bool_):
            return bool(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, pd.Timestamp | pd.NaT.__class__):
            return str(obj)
        elif pd.isna(obj):
            return None
        else:
            return obj
    except ImportError:
        # If numpy/pandas not available, return as-is
        return obj


class DorisADBCQueryTools:
    """ADBC Query Tools for high-performance data transfer using Arrow Flight SQL"""

    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        self.adbc_client: Any | None = None
        self.flight_sql_module: Any | None = None
        self.adbc_manager_module: Any | None = None
        # ADBC connections and cursors are not safe to replace concurrently.
        self._query_lock = asyncio.Lock()

    def _token_bound_route_error(self) -> dict[str, Any] | None:
        auth_context = get_auth_context()
        if auth_context is not None and auth_context.auth_method == "doris_oauth":
            return {
                "success": False,
                "error": (
                    "ADBC is unavailable for token-bound database routes; use "
                    "doris_query.execute_query or a separately configured MCP process"
                ),
                "error_type": "token_bound_adbc_unsupported",
            }
        global_database_config = getattr(
            self.connection_manager.config,
            "database",
            None,
        )
        if global_database_config is None:
            return None
        selected = database_config_for_request(self.connection_manager)
        if selected is global_database_config:
            return None
        return {
            "success": False,
            "error": (
                "ADBC is unavailable for token-bound database routes; use "
                "doris_query.execute_query or a separately configured MCP process"
            ),
            "error_type": "token_bound_adbc_unsupported",
        }

    async def exec_adbc_query(
        self,
        sql: str,
        max_rows: int | None = None,
        timeout: int | None = None,
        return_format: str | None = None,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        """
        Execute SQL query using ADBC (Arrow Flight SQL) protocol

        Args:
            sql: SQL statement to execute
            max_rows: Maximum number of rows to return (uses config default if None)
            timeout: Query timeout in seconds (uses config default if None)
            return_format: Format for returned data ("arrow", "pandas", "dict", uses config default if None)
            max_bytes: Maximum UTF-8 JSON bytes for returned row data

        Returns:
            Query results in specified format with metadata
        """
        try:
            route_error = self._token_bound_route_error()
            if route_error is not None:
                return route_error
            # Use configuration defaults if parameters not specified
            adbc_config = self.connection_manager.config.adbc
            try:
                limits = resolve_result_limits(
                    self.connection_manager.config,
                    max_rows=(
                        max_rows
                        if max_rows is not None
                        else adbc_config.default_max_rows
                    ),
                    max_bytes=max_bytes,
                    timeout_seconds=(
                        timeout if timeout is not None else adbc_config.default_timeout
                    ),
                )
            except ResultLimitError as exc:
                return {
                    "success": False,
                    "error": str(exc),
                    "error_type": "invalid_result_limits",
                    "timestamp": datetime.now().isoformat(),
                }
            return_format = (
                return_format
                if return_format is not None
                else adbc_config.default_return_format
            )
            start_time = time.time()

            # Step 1: Check environment variables and port availability
            port_check_result = await self._check_arrow_flight_ports()
            if not port_check_result["success"]:
                return port_check_result

            # Step 2: Import required ADBC modules
            import_result = await self._import_adbc_modules()
            if not import_result["success"]:
                return import_result

            async with self._query_lock:
                # Step 3: Create a per-call ADBC connection.
                connection_result = await self._create_adbc_connection()
                if not connection_result["success"]:
                    return connection_result

                try:
                    # Step 4: Execute query using ADBC.
                    query_result = await self._execute_query_with_adbc(
                        sql,
                        limits,
                        return_format,
                    )
                finally:
                    await self._close_adbc_client()

            execution_time = time.time() - start_time

            if query_result["success"]:
                query_result["execution_time"] = round(execution_time, 3)
                query_result["protocol"] = "ADBC_Arrow_Flight_SQL"
                query_result["timestamp"] = datetime.now().isoformat()

            return query_result

        except Exception as e:
            logger.error(f"ADBC query execution failed: {str(e)}")
            return {
                "success": False,
                "error": f"ADBC query execution failed: {str(e)}",
                "error_type": "execution_error",
                "timestamp": datetime.now().isoformat(),
            }

    async def _close_adbc_client(self) -> None:
        """Close and clear the current ADBC connection without blocking MCP."""
        client, self.adbc_client = self.adbc_client, None
        if client is None:
            return
        try:
            await asyncio.to_thread(client.close)
        except Exception as exc:
            logger.debug(f"Failed to close ADBC client: {exc}")

    async def _check_arrow_flight_ports(
        self,
        *,
        connectivity_timeout: float | None = None,
    ) -> dict[str, Any]:
        """Check Arrow Flight SQL port configuration and availability"""
        try:
            # Check environment variables
            fe_port_raw = os.getenv("FE_ARROW_FLIGHT_SQL_PORT")
            be_port_raw = os.getenv("BE_ARROW_FLIGHT_SQL_PORT")

            if not fe_port_raw:
                return {
                    "success": False,
                    "error": "Missing environment variable FE_ARROW_FLIGHT_SQL_PORT, please configure Arrow Flight SQL FE port in .env file",
                    "error_type": "missing_fe_port_config",
                }

            if not be_port_raw:
                return {
                    "success": False,
                    "error": "Missing environment variable BE_ARROW_FLIGHT_SQL_PORT, please configure Arrow Flight SQL BE port in .env file",
                    "error_type": "missing_be_port_config",
                }

            # Convert to integer and validate
            try:
                fe_port = int(fe_port_raw)
                be_port = int(be_port_raw)
            except ValueError:
                return {
                    "success": False,
                    "error": "Invalid Arrow Flight SQL port configuration, please ensure FE_ARROW_FLIGHT_SQL_PORT and BE_ARROW_FLIGHT_SQL_PORT are valid numbers",
                    "error_type": "invalid_port_format",
                }

            # Get host address
            fe_host = self.connection_manager.host

            # Check FE Arrow Flight SQL port availability
            fe_available = await asyncio.to_thread(
                self._check_port_connectivity,
                fe_host,
                fe_port,
                connectivity_timeout,
            )
            if not fe_available:
                return {
                    "success": False,
                    "error": f"Cannot connect to FE Arrow Flight SQL port {fe_host}:{fe_port}, please check if service is running",
                    "error_type": "fe_port_unavailable",
                    "fe_host": fe_host,
                    "fe_port": fe_port,
                }

            # Get BE host list
            be_hosts = await self._get_be_hosts()
            if not be_hosts:
                return {
                    "success": False,
                    "error": "Cannot get BE node information, please check cluster status",
                    "error_type": "no_be_hosts",
                }

            # Check at least one BE Arrow Flight SQL port availability
            be_available_count = 0
            be_check_results = []

            for be_host in be_hosts[:3]:  # Check first 3 BE nodes
                be_available = await asyncio.to_thread(
                    self._check_port_connectivity,
                    be_host,
                    be_port,
                    connectivity_timeout,
                )
                be_check_results.append(
                    {"host": be_host, "port": be_port, "available": be_available}
                )
                if be_available:
                    be_available_count += 1

            if be_available_count == 0:
                return {
                    "success": False,
                    "error": f"Cannot connect to any BE Arrow Flight SQL port (port: {be_port}), please check if BE services are running",
                    "error_type": "no_be_ports_available",
                    "be_check_results": be_check_results,
                }

            return {
                "success": True,
                "fe_host": fe_host,
                "fe_port": fe_port,
                "be_port": be_port,
                "be_hosts": be_hosts,
                "be_available_count": be_available_count,
                "be_check_results": be_check_results,
            }

        except Exception as e:
            logger.error(f"Arrow Flight port check failed: {str(e)}")
            return {
                "success": False,
                "error": f"Arrow Flight port check failed: {str(e)}",
                "error_type": "port_check_error",
            }

    def _check_port_connectivity(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
    ) -> bool:
        """Check port connectivity"""
        try:
            # Use config timeout if not specified
            if timeout is None:
                timeout = self.connection_manager.config.adbc.connection_timeout

            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (TimeoutError, OSError):
            return False

    async def _get_be_hosts(self) -> list[str]:
        """Get BE host list"""
        connection = None
        try:
            db_config = self.connection_manager.config.database

            # Use configured BE hosts first
            if db_config.be_hosts:
                logger.info(f"Using configured BE hosts: {db_config.be_hosts}")
                return db_config.be_hosts

            # Get BE nodes via SHOW BACKENDS
            logger.info(
                "No BE hosts configured, getting BE node information via SHOW BACKENDS"
            )
            connection = await self.connection_manager.get_connection("query")
            auth_context = get_auth_context()
            result = await connection.execute(
                "SHOW BACKENDS", auth_context=auth_context
            )

            be_hosts = []
            for row in result.data:
                host = row.get("Host")
                alive = row.get("Alive", "").lower()
                if host and alive == "true":
                    be_hosts.append(host)

            logger.info(f"Got {len(be_hosts)} active BE nodes from SHOW BACKENDS")
            return be_hosts

        except Exception as e:
            logger.error(f"Failed to get BE hosts: {str(e)}")
            return []
        finally:
            if connection is not None:
                await self.connection_manager.release_connection(
                    "query",
                    connection,
                )

    async def _import_adbc_modules(self) -> dict[str, Any]:
        """Import ADBC related modules"""
        try:
            # Import ADBC Driver Manager
            try:
                import adbc_driver_manager

                self.adbc_manager_module = adbc_driver_manager
            except ImportError:
                return {
                    "success": False,
                    "error": "Missing adbc_driver_manager module, please install: pip install adbc_driver_manager",
                    "error_type": "missing_adbc_manager",
                }

            # Import ADBC Flight SQL Driver
            try:
                import adbc_driver_flightsql.dbapi as flight_sql

                self.flight_sql_module = flight_sql
            except ImportError:
                return {
                    "success": False,
                    "error": "Missing adbc_driver_flightsql module, please install: pip install adbc_driver_flightsql",
                    "error_type": "missing_flight_sql_driver",
                }

            return {
                "success": True,
                "adbc_manager_version": getattr(
                    adbc_driver_manager, "__version__", "unknown"
                ),
                "flight_sql_version": getattr(flight_sql, "__version__", "unknown"),
            }

        except Exception as e:
            logger.error(f"ADBC module import failed: {str(e)}")
            return {
                "success": False,
                "error": f"ADBC module import failed: {str(e)}",
                "error_type": "import_error",
            }

    async def _create_adbc_connection(self) -> dict[str, Any]:
        """Create ADBC connection"""
        try:
            if self.adbc_manager_module is None or self.flight_sql_module is None:
                return {
                    "success": False,
                    "error": "ADBC modules have not been loaded",
                    "error_type": "missing_adbc_modules",
                }

            db_config = self.connection_manager.config.database
            fe_port_raw = os.getenv("FE_ARROW_FLIGHT_SQL_PORT")
            if not fe_port_raw:
                return {
                    "success": False,
                    "error": "Missing environment variable FE_ARROW_FLIGHT_SQL_PORT",
                    "error_type": "missing_fe_port_config",
                }
            fe_port = int(fe_port_raw)

            # Build connection URI
            uri = f"grpc://{self.connection_manager.host}:{fe_port}"

            # Create database connection parameters
            db_kwargs = {
                self.adbc_manager_module.DatabaseOptions.USERNAME.value: db_config.user,
                self.adbc_manager_module.DatabaseOptions.PASSWORD.value: db_config.password,
            }

            # Create connection
            self.adbc_client = self.flight_sql_module.connect(
                uri=uri, db_kwargs=db_kwargs
            )

            return {"success": True, "uri": uri, "connection_established": True}

        except Exception as e:
            logger.error(f"Failed to create ADBC connection: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to create ADBC connection: {str(e)}",
                "error_type": "connection_error",
            }

    async def _execute_query_with_adbc(
        self,
        sql: str,
        limits: ResultLimits,
        return_format: str,
    ) -> dict[str, Any]:
        """Execute an ADBC query with bounded output and real cancellation."""
        try:
            if not self.adbc_client:
                return {
                    "success": False,
                    "error": "ADBC connection not established",
                    "error_type": "no_connection",
                }

            # SECURITY FIX: Perform SQL security validation before executing
            auth_context = get_auth_context() or AuthContext()
            if self.connection_manager.security_manager:
                # Always perform security validation, even without auth_context
                # Use a default context for basic SQL security checks
                validation_result = await self.connection_manager.security_manager.validate_sql_security(
                    sql, auth_context
                )
                if not validation_result.is_valid:
                    return {
                        "success": False,
                        "error": f"SQL security validation failed: {validation_result.error_message}",
                        "error_type": "security_violation",
                        "risk_level": validation_result.risk_level,
                    }

            cursor = self.adbc_client.cursor()
            worker = asyncio.create_task(
                asyncio.to_thread(
                    self._execute_query_with_adbc_sync,
                    cursor,
                    sql,
                    limits,
                    return_format,
                )
            )
            try:
                return await asyncio.wait_for(
                    asyncio.shield(worker),
                    timeout=limits.timeout_seconds,
                )
            except TimeoutError:
                await self._cancel_adbc_worker(cursor, worker)
                return {
                    "success": False,
                    "error": (
                        "ADBC query execution timed out after "
                        f"{limits.timeout_seconds} seconds"
                    ),
                    "error_type": "timeout",
                    "sql": sql,
                }
            except asyncio.CancelledError:
                await self._cancel_adbc_worker(cursor, worker)
                raise

        except Exception as e:
            logger.error(f"ADBC query execution failed: {str(e)}")
            return {
                "success": False,
                "error": f"ADBC query execution failed: {str(e)}",
                "error_type": "query_execution_error",
                "sql": sql,
            }

    async def _cancel_adbc_worker(
        self,
        cursor: Any,
        worker: asyncio.Task[dict[str, Any]],
    ) -> None:
        """Request driver cancellation and reap the worker thread."""
        try:
            await asyncio.wait_for(
                asyncio.to_thread(cursor.adbc_cancel),
                timeout=2,
            )
        except Exception as exc:
            logger.warning(f"Failed to cancel ADBC query: {exc}")

        try:
            await asyncio.wait_for(asyncio.shield(worker), timeout=5)
        except (asyncio.CancelledError, Exception) as exc:
            # The driver owns the worker thread.  Keep the result consumed even
            # if a non-cooperative implementation takes longer to unwind.
            logger.debug(f"ADBC query worker did not stop promptly: {exc}")
            worker.add_done_callback(self._consume_adbc_worker_result)

    @staticmethod
    def _consume_adbc_worker_result(worker: asyncio.Task[dict[str, Any]]) -> None:
        try:
            worker.result()
        except (asyncio.CancelledError, Exception):
            pass

    @staticmethod
    def _execute_query_with_adbc_sync(
        cursor: Any,
        sql: str,
        limits: ResultLimits,
        return_format: str,
    ) -> dict[str, Any]:
        """Run blocking ADBC calls in a worker and stream bounded batches."""
        start_time = time.time()
        rows: list[dict[str, Any]] = []
        result_bytes = 2  # JSON array brackets
        truncated = False
        truncation_reason: str | None = None

        try:
            cursor.execute(sql)
            description = cursor.description or []
            column_names = [str(column[0]) for column in description]
            column_types = [str(column[1]) for column in description]

            while not truncated:
                fetch_size = min(256, limits.max_rows + 1 - len(rows))
                batch = cursor.fetchmany(max(fetch_size, 1))
                if not batch:
                    break

                for raw_row in batch:
                    if len(rows) >= limits.max_rows:
                        truncated = True
                        truncation_reason = "max_rows"
                        break

                    if isinstance(raw_row, dict):
                        row = {
                            str(key): _convert_numpy_types(value)
                            for key, value in raw_row.items()
                        }
                    else:
                        row = {
                            name: _convert_numpy_types(value)
                            for name, value in zip(
                                column_names,
                                raw_row,
                                strict=False,
                            )
                        }

                    contribution = json_array_row_size(
                        row,
                        first=not rows,
                    )
                    if result_bytes + contribution > limits.max_bytes:
                        truncated = True
                        truncation_reason = "max_bytes"
                        break

                    rows.append(row)
                    result_bytes += contribution

            common_result = {
                "format": return_format,
                "num_rows": len(rows),
                "num_columns": len(column_names),
                "column_names": column_names,
                "column_types": column_types,
            }
            if return_format == "arrow":
                result_data = {
                    **common_result,
                    "data_preview": rows[:10],
                    "total_bytes": result_bytes,
                }
            elif return_format == "pandas":
                result_data = {
                    **common_result,
                    "data": rows,
                    "memory_usage": result_bytes,
                }
            else:
                result_data = {
                    **common_result,
                    "data": rows,
                }

            return {
                "success": True,
                "result": result_data,
                "execution_time": round(time.time() - start_time, 3),
                "sql": sql,
                "max_rows_applied": truncation_reason == "max_rows",
                "result_bytes": result_bytes,
                "truncated": truncated,
                "truncation_reason": truncation_reason,
                "limits": {
                    "max_rows": limits.max_rows,
                    "max_bytes": limits.max_bytes,
                    "timeout_seconds": limits.timeout_seconds,
                },
            }
        finally:
            cursor.close()

    async def get_adbc_connection_info(self) -> dict[str, Any]:
        """Get ADBC connection information and status"""
        try:
            route_error = self._token_bound_route_error()
            if route_error is not None:
                return {
                    **route_error,
                    "status": "not_ready",
                    "timestamp": datetime.now().isoformat(),
                }
            # Check port status
            port_status = await self._check_arrow_flight_ports()

            # Check module status
            module_status = await self._import_adbc_modules()

            # Get configuration information
            db_config = self.connection_manager.config.database
            fe_port = os.getenv("FE_ARROW_FLIGHT_SQL_PORT")
            be_port = os.getenv("BE_ARROW_FLIGHT_SQL_PORT")

            connection_info = {
                "adbc_available": module_status["success"],
                "ports_available": port_status["success"],
                "configuration": {
                    "fe_host": self.connection_manager.host,
                    "fe_arrow_flight_port": fe_port,
                    "be_arrow_flight_port": be_port,
                    "user": db_config.user,
                },
                "port_status": port_status,
                "module_status": module_status,
                "timestamp": datetime.now().isoformat(),
            }

            if port_status["success"] and module_status["success"]:
                connection_info["status"] = "ready"
                connection_info["message"] = "ADBC Arrow Flight SQL connection ready"
            else:
                connection_info["status"] = "not_ready"
                errors = []
                if not port_status["success"]:
                    errors.append(port_status["error"])
                if not module_status["success"]:
                    errors.append(module_status["error"])
                connection_info["message"] = "; ".join(errors)

            return connection_info

        except Exception as e:
            logger.error(f"Failed to get ADBC connection information: {str(e)}")
            return {
                "status": "error",
                "error": f"Failed to get ADBC connection information: {str(e)}",
                "timestamp": datetime.now().isoformat(),
            }

    def __del__(self) -> None:
        """Cleanup resources"""
        try:
            if self.adbc_client:
                self.adbc_client.close()
        except Exception as exc:
            logger.debug(f"Failed to close ADBC client during finalization: {exc}")

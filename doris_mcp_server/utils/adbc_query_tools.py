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

import os
import socket
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..utils.logger import get_logger
from ..utils.db import DorisConnectionManager
from ..utils.sql_security_utils import get_auth_context

logger = get_logger(__name__)


def _convert_numpy_types(obj):
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
        elif isinstance(obj, (pd.Timestamp, pd.NaT.__class__)):
            return str(obj)
        elif pd.isna(obj):
            return None
        else:
            return obj
    except ImportError:
        # If numpy/pandas not available, return as-is
        return obj


def _convert_dataframe_to_json_serializable(df):
    """Convert DataFrame to JSON serializable format"""
    try:
        import pandas as pd
        import numpy as np
        
        # Convert DataFrame to records
        records = df.to_dict('records')
        
        # Convert each record's values
        converted_records = []
        for record in records:
            converted_record = {}
            for key, value in record.items():
                converted_record[key] = _convert_numpy_types(value)
            converted_records.append(converted_record)
        
        return converted_records
    except ImportError:
        # Fallback to basic dict conversion
        return df.to_dict('records')


class DorisADBCQueryTools:
    """ADBC Query Tools for high-performance data transfer using Arrow Flight SQL"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        self.adbc_client = None
        self.flight_sql_module = None
        self.adbc_manager_module = None
        
    async def exec_adbc_query(
        self,
        sql: str,
        max_rows: int | None = None,
        timeout: int | None = None,
        return_format: str | None = None
    ) -> Dict[str, Any]:
        """
        Execute SQL query using ADBC (Arrow Flight SQL) protocol
        
        Args:
            sql: SQL statement to execute
            max_rows: Maximum number of rows to return (uses config default if None)
            timeout: Query timeout in seconds (uses config default if None)
            return_format: Format for returned data ("arrow", "pandas", "dict", uses config default if None)
            
        Returns:
            Query results in specified format with metadata
        """
        try:
            start_time = time.time()
            
            # Use configuration defaults if parameters not specified
            adbc_config = self.connection_manager.config.adbc
            max_rows = max_rows if max_rows is not None else adbc_config.default_max_rows
            timeout = timeout if timeout is not None else adbc_config.default_timeout
            return_format = return_format if return_format is not None else adbc_config.default_return_format
            
            # Step 1: Check environment variables and port availability
            port_check_result = await self._check_arrow_flight_ports()
            if not port_check_result["success"]:
                return port_check_result
                
            # Step 2: Import required ADBC modules
            import_result = await self._import_adbc_modules()
            if not import_result["success"]:
                return import_result
                
            # Step 3: Create ADBC connection
            connection_result = await self._create_adbc_connection()
            if not connection_result["success"]:
                return connection_result
                
            # Step 4: Execute query using ADBC
            query_result = await self._execute_query_with_adbc(
                sql, max_rows, timeout, return_format
            )
            
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
                "timestamp": datetime.now().isoformat()
            }
    
    async def _check_arrow_flight_ports(self) -> Dict[str, Any]:
        """Check Arrow Flight SQL port configuration and availability"""
        try:
            # Check environment variables
            fe_port = os.getenv("FE_ARROW_FLIGHT_SQL_PORT")
            be_port = os.getenv("BE_ARROW_FLIGHT_SQL_PORT")
            
            if not fe_port:
                return {
                    "success": False,
                    "error": "Missing environment variable FE_ARROW_FLIGHT_SQL_PORT, please configure Arrow Flight SQL FE port in .env file",
                    "error_type": "missing_fe_port_config"
                }
                
            if not be_port:
                return {
                    "success": False,
                    "error": "Missing environment variable BE_ARROW_FLIGHT_SQL_PORT, please configure Arrow Flight SQL BE port in .env file",
                    "error_type": "missing_be_port_config"
                }
            
            # Convert to integer and validate
            try:
                fe_port = int(fe_port)
                be_port = int(be_port)
            except ValueError:
                return {
                    "success": False,
                    "error": "Invalid Arrow Flight SQL port configuration, please ensure FE_ARROW_FLIGHT_SQL_PORT and BE_ARROW_FLIGHT_SQL_PORT are valid numbers",
                    "error_type": "invalid_port_format"
                }
            
            # Get host address
            db_config = self.connection_manager.config.database
            fe_host = db_config.host
            
            # Check FE Arrow Flight SQL port availability
            fe_available = self._check_port_connectivity(fe_host, fe_port)
            if not fe_available:
                return {
                    "success": False,
                    "error": f"Cannot connect to FE Arrow Flight SQL port {fe_host}:{fe_port}, please check if service is running",
                    "error_type": "fe_port_unavailable",
                    "fe_host": fe_host,
                    "fe_port": fe_port
                }
            
            # Get BE host list
            be_hosts = await self._get_be_hosts()
            if not be_hosts:
                return {
                    "success": False,
                    "error": "Cannot get BE node information, please check cluster status",
                    "error_type": "no_be_hosts"
                }
            
            # Check at least one BE Arrow Flight SQL port availability
            be_available_count = 0
            be_check_results = []
            
            for be_host in be_hosts[:3]:  # Check first 3 BE nodes
                be_available = self._check_port_connectivity(be_host, be_port)
                be_check_results.append({
                    "host": be_host,
                    "port": be_port,
                    "available": be_available
                })
                if be_available:
                    be_available_count += 1
            
            if be_available_count == 0:
                return {
                    "success": False,
                    "error": f"Cannot connect to any BE Arrow Flight SQL port (port: {be_port}), please check if BE services are running",
                    "error_type": "no_be_ports_available",
                    "be_check_results": be_check_results
                }
            
            return {
                "success": True,
                "fe_host": fe_host,
                "fe_port": fe_port,
                "be_port": be_port,
                "be_hosts": be_hosts,
                "be_available_count": be_available_count,
                "be_check_results": be_check_results
            }
            
        except Exception as e:
            logger.error(f"Arrow Flight port check failed: {str(e)}")
            return {
                "success": False,
                "error": f"Arrow Flight port check failed: {str(e)}",
                "error_type": "port_check_error"
            }
    
    def _check_port_connectivity(self, host: str, port: int, timeout: int | None = None) -> bool:
        """Check port connectivity"""
        try:
            # Use config timeout if not specified
            if timeout is None:
                timeout = self.connection_manager.config.adbc.connection_timeout
            
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, socket.error, OSError):
            return False
    
    async def _get_be_hosts(self) -> List[str]:
        """Get BE host list"""
        try:
            db_config = self.connection_manager.config.database
            
            # Use configured BE hosts first
            if db_config.be_hosts:
                logger.info(f"Using configured BE hosts: {db_config.be_hosts}")
                return db_config.be_hosts
            
            # Get BE nodes via SHOW BACKENDS
            logger.info("No BE hosts configured, getting BE node information via SHOW BACKENDS")
            connection = await self.connection_manager.get_connection("query")
            auth_context = get_auth_context()
            result = await connection.execute("SHOW BACKENDS", auth_context=auth_context)
            
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
    
    async def _import_adbc_modules(self) -> Dict[str, Any]:
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
                    "error_type": "missing_adbc_manager"
                }
            
            # Import ADBC Flight SQL Driver
            try:
                import adbc_driver_flightsql.dbapi as flight_sql
                self.flight_sql_module = flight_sql
            except ImportError:
                return {
                    "success": False,
                    "error": "Missing adbc_driver_flightsql module, please install: pip install adbc_driver_flightsql",
                    "error_type": "missing_flight_sql_driver"
                }
            
            return {
                "success": True,
                "adbc_manager_version": getattr(adbc_driver_manager, '__version__', 'unknown'),
                "flight_sql_version": getattr(flight_sql, '__version__', 'unknown')
            }
            
        except Exception as e:
            logger.error(f"ADBC module import failed: {str(e)}")
            return {
                "success": False,
                "error": f"ADBC module import failed: {str(e)}",
                "error_type": "import_error"
            }
    
    async def _create_adbc_connection(self) -> Dict[str, Any]:
        """Create ADBC connection"""
        try:
            db_config = self.connection_manager.config.database
            fe_port = int(os.getenv("FE_ARROW_FLIGHT_SQL_PORT"))
            
            # Build connection URI
            uri = f"grpc://{db_config.host}:{fe_port}"
            
            # Create database connection parameters
            db_kwargs = {
                self.adbc_manager_module.DatabaseOptions.USERNAME.value: db_config.user,
                self.adbc_manager_module.DatabaseOptions.PASSWORD.value: db_config.password,
            }
            
            # Create connection
            self.adbc_client = self.flight_sql_module.connect(
                uri=uri,
                db_kwargs=db_kwargs
            )
            
            return {
                "success": True,
                "uri": uri,
                "connection_established": True
            }
            
        except Exception as e:
            logger.error(f"Failed to create ADBC connection: {str(e)}")
            return {
                "success": False,
                "error": f"Failed to create ADBC connection: {str(e)}",
                "error_type": "connection_error"
            }
    
    async def _execute_query_with_adbc(
        self,
        sql: str,
        max_rows: int,
        timeout: int,
        return_format: str
    ) -> Dict[str, Any]:
        """Execute query using ADBC"""
        try:
            if not self.adbc_client:
                return {
                    "success": False,
                    "error": "ADBC connection not established",
                    "error_type": "no_connection"
                }
            
            # SECURITY FIX: Perform SQL security validation before executing
            auth_context = get_auth_context()
            if self.connection_manager.security_manager:
                # Always perform security validation, even without auth_context
                # Use a default context for basic SQL security checks
                validation_result = await self.connection_manager.security_manager.validate_sql_security(sql, auth_context)
                if not validation_result.is_valid:
                    return {
                        "success": False,
                        "error": f"SQL security validation failed: {validation_result.error_message}",
                        "error_type": "security_violation",
                        "risk_level": validation_result.risk_level
                    }
            
            cursor = self.adbc_client.cursor()
            start_time = time.time()
            
            # Execute query
            cursor.execute(sql)
            
            # Get results based on return format
            if return_format == "arrow":
                # Return Arrow format
                arrow_data = cursor.fetchallarrow()
                
                # Limit rows
                if len(arrow_data) > max_rows:
                    arrow_data = arrow_data.slice(0, max_rows)
                
                # Convert Arrow data to serializable format
                preview_df = arrow_data.to_pandas().head(10) if len(arrow_data) > 0 else None
                result_data = {
                    "format": "arrow",
                    "num_rows": len(arrow_data),
                    "num_columns": len(arrow_data.schema),
                    "column_names": arrow_data.schema.names,
                    "column_types": [str(field.type) for field in arrow_data.schema],
                    "data_preview": _convert_dataframe_to_json_serializable(preview_df) if preview_df is not None else [],
                    "total_bytes": arrow_data.nbytes if hasattr(arrow_data, 'nbytes') else 0
                }
                
            elif return_format == "pandas":
                # Return Pandas DataFrame
                df = cursor.fetch_df()
                
                # Limit rows
                if len(df) > max_rows:
                    df = df.head(max_rows)
                
                result_data = {
                    "format": "pandas",
                    "num_rows": len(df),
                    "num_columns": len(df.columns),
                    "column_names": df.columns.tolist(),
                    "column_types": df.dtypes.astype(str).tolist(),
                    "data": _convert_dataframe_to_json_serializable(df),
                    "memory_usage": int(df.memory_usage(deep=True).sum())
                }
                
            else:  # return_format == "dict"
                # Return dictionary format
                arrow_data = cursor.fetchallarrow()
                df = arrow_data.to_pandas()
                
                # Limit rows
                if len(df) > max_rows:
                    df = df.head(max_rows)
                
                result_data = {
                    "format": "dict",
                    "num_rows": len(df),
                    "num_columns": len(df.columns),
                    "column_names": df.columns.tolist(),
                    "column_types": df.dtypes.astype(str).tolist(),
                    "data": _convert_dataframe_to_json_serializable(df)
                }
            
            execution_time = time.time() - start_time
            
            cursor.close()
            
            return {
                "success": True,
                "result": result_data,
                "execution_time": round(execution_time, 3),
                "sql": sql,
                "max_rows_applied": len(result_data.get("data", [])) >= max_rows
            }
            
        except Exception as e:
            logger.error(f"ADBC query execution failed: {str(e)}")
            return {
                "success": False,
                "error": f"ADBC query execution failed: {str(e)}",
                "error_type": "query_execution_error",
                "sql": sql
            }
    
    async def get_adbc_connection_info(self) -> Dict[str, Any]:
        """Get ADBC connection information and status"""
        try:
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
                    "fe_host": db_config.host,
                    "fe_arrow_flight_port": fe_port,
                    "be_arrow_flight_port": be_port,
                    "user": db_config.user
                },
                "port_status": port_status,
                "module_status": module_status,
                "timestamp": datetime.now().isoformat()
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
                "timestamp": datetime.now().isoformat()
            }
    
    def __del__(self):
        """Cleanup resources"""
        try:
            if self.adbc_client:
                self.adbc_client.close()
        except:
            pass 
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
Apache Doris MCP Resources Manager
Provides standardized abstraction and access interface for database metadata
"""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from hashlib import sha256
from typing import Any, cast
from urllib.parse import quote, unquote

from mcp.types import Resource

from ..utils.db import DorisConnection, DorisConnectionManager
from ..utils.logger import get_logger
from ..utils.redaction import redact_uri
from ..utils.sql_security_utils import get_auth_context, quote_identifier

logger = get_logger(__name__)


class TableMetadata:
    """Data table metadata"""

    def __init__(
        self,
        name: str,
        comment: str | None = None,
        row_count: int = 0,
        columns: list[dict[str, Any]] | None = None,
        create_time: datetime | None = None,
        database: str | None = None,
    ) -> None:
        self.name = name
        self.comment = comment
        self.row_count = row_count
        self.columns = columns or []
        self.create_time = create_time
        self.database = database


class ViewMetadata:
    """Data view metadata"""

    def __init__(
        self,
        name: str,
        comment: str | None = None,
        definition: str | None = None,
        database: str | None = None,
    ) -> None:
        self.name = name
        self.comment = comment
        self.definition = definition
        self.database = database


class MetadataCache:
    """Metadata cache manager"""

    def __init__(
        self,
        ttl_seconds: int = 300,
        enabled: bool = False,
        max_entries: int = 128,
    ):
        self.cache: dict[str, tuple[Any, float]] = {}
        self.ttl = ttl_seconds
        self.enabled = enabled
        self.max_entries = max_entries

    async def get(self, key: str) -> Any | None:
        if not self.enabled:
            return None
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.now().timestamp() - timestamp < self.ttl:
                return data
            else:
                del self.cache[key]
        return None

    async def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        if key not in self.cache and len(self.cache) >= self.max_entries:
            oldest_key = min(self.cache, key=lambda item: self.cache[item][1])
            del self.cache[oldest_key]
        self.cache[key] = (value, datetime.now().timestamp())


class ResourceMetadataError(RuntimeError):
    """Structured resource-list failure that is safe to classify at the protocol boundary."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        status_code: int,
        list_error_category: str,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code
        self.list_error_category = list_error_category


class DorisOAuthResourceError(ResourceMetadataError):
    """Structured resource metadata failure for Doris OAuth requests."""


class InvalidResourceURIError(ValueError):
    """A resource URI that cannot identify a supported Doris resource."""

    error_code = "INVALID_RESOURCE_URI"


class ResourceNotFoundError(ValueError):
    """A syntactically valid Doris resource URI with no visible target."""

    error_code = "RESOURCE_NOT_FOUND"


EXCLUDED_RESOURCE_DATABASES = {
    "information_schema",
    "mysql",
    "performance_schema",
    "sys",
    "doris_metadata",
}


class DorisResourcesManager:
    """Apache Doris Resources Manager"""

    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        self.metadata_cache = MetadataCache(enabled=True)

    def _metadata_cache_scope(self) -> str:
        auth_context = get_auth_context()
        original_config = getattr(
            self.connection_manager,
            "original_db_config",
            {},
        )
        endpoint = {
            field: original_config.get(field)
            for field in ("host", "port", "user", "database")
        }

        token_manager = getattr(self.connection_manager, "token_manager", None)
        token = getattr(auth_context, "token", "") if auth_context else ""
        if token_manager and token:
            token_config = token_manager.get_database_config_by_token(token)
            if token_config:
                endpoint = {
                    field: getattr(token_config, field, None)
                    for field in ("host", "port", "user", "database")
                }

        identity = {
            "authMethod": getattr(auth_context, "auth_method", ""),
            "tokenId": getattr(auth_context, "token_id", ""),
            "userId": getattr(auth_context, "user_id", ""),
            "roles": sorted(getattr(auth_context, "roles", [])),
            "permissions": sorted(getattr(auth_context, "permissions", [])),
            "dorisUser": getattr(auth_context, "doris_user", ""),
            "oauthClientId": getattr(auth_context, "oauth_client_id", ""),
            "oauthScopes": sorted(getattr(auth_context, "oauth_scopes", [])),
            "oauthResource": getattr(auth_context, "oauth_resource", ""),
            "oauthAudiences": sorted(
                getattr(auth_context, "oauth_audiences", [])
            ),
            "poolKey": getattr(auth_context, "pool_key", ""),
        }
        payload = json.dumps(
            {"endpoint": endpoint, "identity": identity},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return sha256(payload.encode("utf-8")).hexdigest()

    def _is_doris_oauth_context(self) -> bool:
        return getattr(get_auth_context(), "auth_method", "") == "doris_oauth"

    def _schema_filter(
        self,
        column_name: str,
        db_name: str | None,
    ) -> tuple[str, tuple[str, ...]]:
        safe_column = quote_identifier(column_name, "information schema column")
        if db_name:
            return f"{safe_column} = %s", (db_name,)
        return f"{safe_column} = DATABASE()", ()

    def _first_row_value(self, row: Any) -> Any:
        if isinstance(row, dict):
            return next(iter(row.values()), None)
        if isinstance(row, list | tuple):
            return row[0] if row else None
        return row

    def _visible_resource_database(self, db_name: str | None) -> bool:
        return bool(db_name) and str(db_name).lower() not in EXCLUDED_RESOURCE_DATABASES

    def _resource_uri_segment(self, value: Any) -> str:
        return quote(str(value), safe="")

    def _decode_resource_uri_segment(self, value: str) -> str:
        return unquote(value)

    def _stats_resource_uri(self, db_name: str) -> str:
        segment = self._resource_uri_segment(db_name)
        if segment == "database":
            return f"doris://stats/database/{segment}"
        return f"doris://stats/{segment}"

    def _resource_error_from_exception(self, exc: Exception) -> ResourceMetadataError:
        if isinstance(exc, ResourceMetadataError):
            return exc

        is_doris_oauth = self._is_doris_oauth_context()
        error_type = (
            DorisOAuthResourceError if is_doris_oauth else ResourceMetadataError
        )
        error_prefix = (
            "DORIS_OAUTH_METADATA" if is_doris_oauth else "DORIS_METADATA"
        )
        error_code = getattr(exc, "error_code", None)
        status_code = getattr(exc, "status_code", None)
        message = str(exc) or exc.__class__.__name__
        if error_code:
            normalized_status = int(status_code or 500)
            category = (
                "permission_denied"
                if normalized_status in {401, 403}
                else "backend_unavailable"
            )
            return error_type(
                message,
                error_code=str(error_code),
                status_code=normalized_status,
                list_error_category=category,
            )

        mysql_error_code = None
        if getattr(exc, "args", None):
            try:
                mysql_error_code = int(exc.args[0])
            except (TypeError, ValueError):
                mysql_error_code = None
        if mysql_error_code in {1044, 1045, 1049, 1142, 1227}:
            return error_type(
                message,
                error_code=f"{error_prefix}_PERMISSION_DENIED",
                status_code=403,
                list_error_category="permission_denied",
            )

        lowered = message.lower()
        permission_markers = (
            "permission denied",
            "access denied",
            "not authorized",
            "privilege",
        )
        if any(marker in lowered for marker in permission_markers):
            return error_type(
                message,
                error_code=f"{error_prefix}_PERMISSION_DENIED",
                status_code=403,
                list_error_category="permission_denied",
            )

        exception_family = exc.__class__.__module__.partition(".")[0]
        if (
            is_doris_oauth
            or isinstance(exc, OSError | TimeoutError)
            or exception_family in {"aiomysql", "pymysql"}
        ):
            return error_type(
                message,
                error_code=f"{error_prefix}_BACKEND_ERROR",
                status_code=502,
                list_error_category="backend_unavailable",
            )

        return error_type(
            message,
            error_code=f"{error_prefix}_INTERNAL_ERROR",
            status_code=500,
            list_error_category="internal_error",
        )

    def _reraise_if_doris_oauth_resource_error(self, exc: Exception) -> None:
        if isinstance(exc, InvalidResourceURIError | ResourceNotFoundError):
            return
        if isinstance(exc, DorisOAuthResourceError):
            raise exc
        if self._is_doris_oauth_context():
            raise self._resource_error_from_exception(exc) from exc

    @asynccontextmanager
    async def _connection_context(
        self,
        session_id: str = "system",
    ) -> AsyncIterator[DorisConnection]:
        manager_context = getattr(self.connection_manager, "get_connection_context", None)
        if manager_context:
            async with manager_context(session_id) as connection:
                yield connection
            return

        connection = await self.connection_manager.get_connection(session_id)
        try:
            yield connection
        finally:
            release = getattr(self.connection_manager, "release_connection", None)
            if release:
                await release(session_id, connection)

    async def list_resources(self) -> list[Resource]:
        """List all available database resources"""
        resources: list[Resource] = []

        try:
            if self._is_doris_oauth_context():
                return await self._list_doris_oauth_resources()

            # Get metadata for all tables
            tables = await self._get_table_metadata()
            for table in tables:
                resources.append(
                    Resource(
                        uri=f"doris://table/{self._resource_uri_segment(table.name)}",
                        name=f"Data Table: {table.name}",
                        description=f"{table.comment or 'Data table'} (rows: {table.row_count:,})",
                        mime_type="application/json",
                    )
                )

            # Get metadata for all views
            views = await self._get_view_metadata()
            for view in views:
                resources.append(
                    Resource(
                        uri=f"doris://view/{self._resource_uri_segment(view.name)}",
                        name=f"Data View: {view.name}",
                        description=f"{view.comment or 'Data view'}",
                        mime_type="application/json",
                    )
                )

            # Add database statistics resource
            resources.append(
                Resource(
                    uri="doris://stats/database",
                    name="Database Statistics",
                    description="Overall database statistics and performance metrics",
                    mime_type="application/json",
                )
            )

        except Exception as e:
            logger.exception("Failed to get resource list")
            raise self._resource_error_from_exception(e) from e

        return resources

    async def _list_doris_oauth_resources(self) -> list[Resource]:
        """List database-qualified resources visible to the routed Doris user."""
        resources: list[Resource] = []
        async with self._connection_context("system") as connection:
            databases = await self._get_visible_databases(connection)
            for db_name in databases:
                tables = await self._get_table_metadata_for_database(connection, db_name)
                for table in tables:
                    resources.append(
                        Resource(
                            uri=(
                                f"doris://table/{self._resource_uri_segment(db_name)}/"
                                f"{self._resource_uri_segment(table.name)}"
                            ),
                            name=f"Data Table: {db_name}.{table.name}",
                            description=f"{table.comment or 'Data table'} (rows: {table.row_count:,})",
                            mime_type="application/json",
                        )
                    )

                views = await self._get_view_metadata_for_database(connection, db_name)
                for view in views:
                    resources.append(
                        Resource(
                            uri=(
                                f"doris://view/{self._resource_uri_segment(db_name)}/"
                                f"{self._resource_uri_segment(view.name)}"
                            ),
                            name=f"Data View: {db_name}.{view.name}",
                            description=f"{view.comment or 'Data view'}",
                            mime_type="application/json",
                        )
                    )

                resources.append(
                    Resource(
                        uri=self._stats_resource_uri(db_name),
                        name=f"Database Statistics: {db_name}",
                        description=f"Overall database statistics for {db_name}",
                        mime_type="application/json",
                    )
                )
        return resources

    async def read_resource(self, uri: str) -> str:
        """Read detailed information of specific resource"""
        try:
            resource_type, resource_name, db_name = self._parse_resource_uri(uri)

            if resource_type == "table":
                return await self._get_table_schema(resource_name, db_name)
            elif resource_type == "view":
                return await self._get_view_definition(resource_name, db_name)
            elif resource_type == "stats" and resource_name == "database":
                return await self._get_database_stats(db_name)
            else:
                raise InvalidResourceURIError(
                    f"Unsupported resource type: {resource_type}"
                )

        except Exception as e:
            self._reraise_if_doris_oauth_resource_error(e)
            if isinstance(e, InvalidResourceURIError):
                message = "Invalid resource URI"
            elif isinstance(e, ResourceNotFoundError):
                message = "Resource not found"
            else:
                logger.exception("Failed to read resource")
                message = "Resource read failed"
            payload = {
                "error": message,
                "uri": redact_uri(uri),
            }
            if isinstance(e, InvalidResourceURIError | ResourceNotFoundError):
                payload["error_code"] = e.error_code
            return json.dumps(payload, ensure_ascii=False, indent=2)

    async def _get_table_metadata(self) -> list[TableMetadata]:
        """Get metadata for all tables"""
        cache_key = f"{self._metadata_cache_scope()}:table_metadata"
        cached = await self.metadata_cache.get(cache_key)
        if cached:
            return cast(list[TableMetadata], cached)

        async with self._connection_context("system") as connection:
            tables = await self._get_table_metadata_for_database(connection)

        await self.metadata_cache.set(cache_key, tables)
        return tables

    async def _get_visible_databases(
        self,
        connection: DorisConnection,
    ) -> list[str]:
        """Get databases visible to the current routed Doris user."""
        auth_context = get_auth_context()
        result = await connection.execute("SHOW DATABASES", auth_context=auth_context)
        databases: list[str] = []
        for row in result.data:
            db_name = self._first_row_value(row)
            if self._visible_resource_database(db_name):
                databases.append(str(db_name))
        return databases

    async def _get_table_metadata_for_database(
        self,
        connection: DorisConnection,
        db_name: str | None = None,
    ) -> list[TableMetadata]:
        """Get table metadata for a specific database or the current database."""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # SQL sink audit: schema column -> quote_identifier and database value
        # -> bound param; fixed template -> DorisConnection.execute.
        tables_query = f"""
        SELECT
            table_name,
            table_comment,
            table_rows as row_count,
            create_time
        FROM information_schema.tables
        WHERE {schema_filter}
        AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """  # nosec B608

        auth_context = get_auth_context()
        result = await connection.execute(
            tables_query,
            params=schema_params or None,
            auth_context=auth_context,
        )
        tables: list[TableMetadata] = []

        for row in result.data:
            table = TableMetadata(
                name=row["table_name"],
                comment=row.get("table_comment"),
                row_count=row.get("row_count", 0),
                create_time=row.get("create_time"),
                database=db_name,
            )
            tables.append(table)

        return tables

    async def _get_table_columns(
        self,
        connection: DorisConnection,
        table_name: str,
        db_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get column information for table"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # SQL sink audit: schema column -> quote_identifier; database/table
        # values -> bound params; fixed template -> DorisConnection.execute.
        columns_query = f"""
        SELECT
            column_name,
            data_type,
            is_nullable,
            column_default,
            column_comment,
            column_key
        FROM information_schema.columns
        WHERE {schema_filter}
        AND table_name = %s
        ORDER BY ordinal_position
        """  # nosec B608

        auth_context = get_auth_context()
        result = await connection.execute(
            columns_query,
            params=(*schema_params, table_name),
            auth_context=auth_context,
        )
        return [dict(row) for row in result.data]

    async def _get_view_metadata(self) -> list[ViewMetadata]:
        """Get metadata for all views"""
        cache_key = f"{self._metadata_cache_scope()}:view_metadata"
        cached = await self.metadata_cache.get(cache_key)
        if cached:
            return cast(list[ViewMetadata], cached)

        async with self._connection_context("system") as connection:
            views = await self._get_view_metadata_for_database(connection)

        await self.metadata_cache.set(cache_key, views)
        return views

    async def _get_view_metadata_for_database(
        self,
        connection: DorisConnection,
        db_name: str | None = None,
    ) -> list[ViewMetadata]:
        """Get view metadata for a specific database or the current database."""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # SQL sink audit: schema column -> quote_identifier and database value
        # -> bound param; fixed template -> DorisConnection.execute.
        views_query = f"""
        SELECT
            table_name,
            view_definition
        FROM information_schema.views
        WHERE {schema_filter}
        ORDER BY table_name
        """  # nosec B608

        auth_context = get_auth_context()
        result = await connection.execute(
            views_query,
            params=schema_params or None,
            auth_context=auth_context,
        )
        views: list[ViewMetadata] = []

        for row in result.data:
            view = ViewMetadata(
                name=row["table_name"],
                comment=row.get("table_comment"),
                definition=row.get("view_definition"),
                database=db_name,
            )
            views.append(view)

        return views

    async def _get_table_schema(self, table_name: str, db_name: str | None = None) -> str:
        """Get detailed structure information of table"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # Get basic table information
        # SQL sink audit: schema column -> quote_identifier; database/table
        # values -> bound params; fixed template -> DorisConnection.execute.
        table_info_query = f"""
        SELECT
            table_name,
            table_comment,
            table_rows,
            create_time,
            engine
        FROM information_schema.tables
        WHERE {schema_filter}
        AND table_name = %s
        """  # nosec B608

        async with self._connection_context("system") as connection:
            auth_context = get_auth_context()
            table_result = await connection.execute(
                table_info_query,
                params=(*schema_params, table_name),
                auth_context=auth_context,
            )
            if not table_result.data:
                qualified_name = f"{db_name}.{table_name}" if db_name else table_name
                raise ResourceNotFoundError(f"Table {qualified_name} does not exist")

            table_info = table_result.data[0]

            # Get column information
            columns = await self._get_table_columns(connection, table_name, db_name)

            # Get index information
            indexes = await self._get_table_indexes(connection, table_name, db_name)

        schema_info = {
            "database_name": db_name,
            "table_name": table_info["table_name"],
            "comment": table_info.get("table_comment"),
            "row_count": table_info.get("table_rows", 0),
            "create_time": str(table_info.get("create_time")),
            "engine": table_info.get("engine"),
            "columns": columns,
            "indexes": indexes,
        }

        return json.dumps(schema_info, ensure_ascii=False, indent=2)

    async def _get_table_indexes(
        self,
        connection: DorisConnection,
        table_name: str,
        db_name: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get index information for table"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # SQL sink audit: schema column -> quote_identifier; database/table
        # values -> bound params; fixed template -> DorisConnection.execute.
        indexes_query = f"""
        SELECT
            index_name,
            column_name,
            index_type,
            non_unique
        FROM information_schema.statistics
        WHERE {schema_filter}
        AND table_name = %s
        ORDER BY index_name, seq_in_index
        """  # nosec B608

        auth_context = get_auth_context()
        result = await connection.execute(
            indexes_query,
            params=(*schema_params, table_name),
            auth_context=auth_context,
        )
        return [dict(row) for row in result.data]

    async def _get_view_definition(self, view_name: str, db_name: str | None = None) -> str:
        """Get definition information of view"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # SQL sink audit: schema column -> quote_identifier; database/view
        # values -> bound params; fixed template -> DorisConnection.execute.
        view_query = f"""
        SELECT
            table_name,
            view_definition
        FROM information_schema.views
        WHERE {schema_filter}
        AND table_name = %s
        """  # nosec B608

        async with self._connection_context("system") as connection:
            auth_context = get_auth_context()
            result = await connection.execute(
                view_query,
                params=(*schema_params, view_name),
                auth_context=auth_context,
            )
            if not result.data:
                qualified_name = f"{db_name}.{view_name}" if db_name else view_name
                raise ResourceNotFoundError(f"View {qualified_name} does not exist")

            view_info = result.data[0]

        schema_info = {
            "database_name": db_name,
            "view_name": view_info["table_name"],
            "comment": view_info.get("table_comment"),
            "definition": view_info.get("view_definition"),
        }

        return json.dumps(schema_info, ensure_ascii=False, indent=2)

    async def _get_database_stats(self, db_name: str | None = None) -> str:
        """Get database statistics"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        # Get table statistics
        # SQL sink audit: schema column -> quote_identifier and database value
        # -> bound param; fixed template -> DorisConnection.execute.
        table_stats_query = f"""
        SELECT
            COUNT(*) as table_count,
            SUM(table_rows) as total_rows
        FROM information_schema.tables
        WHERE {schema_filter}
        AND table_type = 'BASE TABLE'
        """  # nosec B608

        async with self._connection_context("system") as connection:
            auth_context = get_auth_context()
            table_result = await connection.execute(
                table_stats_query,
                params=schema_params or None,
                auth_context=auth_context,
            )
            table_stats = table_result.data[0] if table_result.data else {}

            # Get view statistics
            # SQL sink audit: same quote_identifier result and bound database
            # value flow into DorisConnection.execute.
            view_stats_query = f"""
            SELECT COUNT(*) as view_count
            FROM information_schema.views
            WHERE {schema_filter}
            """  # nosec B608

            view_result = await connection.execute(
                view_stats_query,
                params=schema_params or None,
                auth_context=auth_context,
            )
            view_stats = view_result.data[0] if view_result.data else {}

        stats_info = {
            "database_name": db_name or "current_database",
            "table_count": table_stats.get("table_count", 0),
            "view_count": view_stats.get("view_count", 0),
            "total_rows": table_stats.get("total_rows", 0),
            "last_updated": datetime.now().isoformat(),
        }

        return json.dumps(stats_info, ensure_ascii=False, indent=2)

    def _parse_resource_uri(self, uri: str) -> tuple[str, str, str | None]:
        """Parse resource URI"""
        if not uri.startswith("doris://"):
            raise InvalidResourceURIError("Invalid resource URI format")

        path = uri[8:]  # Remove "doris://" prefix
        parts = path.split("/")

        if len(parts) < 2:
            raise InvalidResourceURIError("Incomplete resource URI format")

        resource_type = parts[0]
        if resource_type in {"table", "view"}:
            if len(parts) >= 3:
                return (
                    resource_type,
                    self._decode_resource_uri_segment(parts[2]),
                    self._decode_resource_uri_segment(parts[1]),
                )
            return resource_type, self._decode_resource_uri_segment(parts[1]), None

        if resource_type == "stats":
            if len(parts) >= 3 and parts[1] == "database":
                return resource_type, "database", self._decode_resource_uri_segment(parts[2])
            if len(parts) == 2 and parts[1] == "database":
                return resource_type, "database", None
            if len(parts) == 2:
                return resource_type, "database", self._decode_resource_uri_segment(parts[1])

        return resource_type, self._decode_resource_uri_segment(parts[1]), None

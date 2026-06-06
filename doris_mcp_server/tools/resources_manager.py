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
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any
from urllib.parse import quote, unquote

from mcp.types import Resource

from ..utils.db import DorisConnectionManager
from ..utils.sql_security_utils import get_auth_context


class TableMetadata:
    """Data table metadata"""

    def __init__(
        self,
        name: str,
        comment: str = None,
        row_count: int = 0,
        columns: list[dict] = None,
        create_time: datetime = None,
        database: str | None = None,
    ):
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
        comment: str = None,
        definition: str = None,
        database: str | None = None,
    ):
        self.name = name
        self.comment = comment
        self.definition = definition
        self.database = database


class MetadataCache:
    """Metadata cache manager"""

    def __init__(self, ttl_seconds: int = 300, enabled: bool = False):
        self.cache = {}
        self.ttl = ttl_seconds
        self.enabled = enabled

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

    async def set(self, key: str, value: Any):
        if not self.enabled:
            return
        self.cache[key] = (value, datetime.now().timestamp())


class DorisOAuthResourceError(RuntimeError):
    """Structured resources metadata failure for Doris OAuth requests."""

    def __init__(self, message: str, *, error_code: str, status_code: int):
        super().__init__(message)
        self.error_code = error_code
        self.status_code = status_code


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
        # Resource metadata cache is disabled until it is identity-aware.
        # Static token-bound DB and Doris OAuth can route to different Doris
        # users; global cache keys would leak metadata across identities.
        self.metadata_cache = MetadataCache(enabled=False)

    def _is_doris_oauth_context(self) -> bool:
        return getattr(get_auth_context(), "auth_method", "") == "doris_oauth"

    def _schema_filter(self, column_name: str, db_name: str | None) -> tuple[str, tuple]:
        if db_name:
            return f"{column_name} = %s", (db_name,)
        return f"{column_name} = DATABASE()", ()

    def _first_row_value(self, row: Any) -> Any:
        if isinstance(row, dict):
            return next(iter(row.values()), None)
        if isinstance(row, (list, tuple)):
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

    def _resource_error_from_exception(self, exc: Exception) -> DorisOAuthResourceError:
        error_code = getattr(exc, "error_code", None)
        status_code = getattr(exc, "status_code", None)
        message = str(exc) or exc.__class__.__name__
        if error_code:
            return DorisOAuthResourceError(
                message,
                error_code=str(error_code),
                status_code=int(status_code or 500),
            )

        mysql_error_code = None
        if getattr(exc, "args", None):
            try:
                mysql_error_code = int(exc.args[0])
            except (TypeError, ValueError):
                mysql_error_code = None
        if mysql_error_code in {1044, 1045, 1049, 1142, 1227}:
            return DorisOAuthResourceError(
                message,
                error_code="DORIS_OAUTH_METADATA_PERMISSION_DENIED",
                status_code=403,
            )

        lowered = message.lower()
        permission_markers = ("permission denied", "access denied", "not authorized", "privilege")
        if any(marker in lowered for marker in permission_markers):
            return DorisOAuthResourceError(
                message,
                error_code="DORIS_OAUTH_METADATA_PERMISSION_DENIED",
                status_code=403,
            )
        return DorisOAuthResourceError(
            message,
            error_code="DORIS_OAUTH_METADATA_BACKEND_ERROR",
            status_code=502,
        )

    def _reraise_if_doris_oauth_resource_error(self, exc: Exception) -> None:
        if isinstance(exc, DorisOAuthResourceError):
            raise exc
        if self._is_doris_oauth_context():
            raise self._resource_error_from_exception(exc) from exc

    @asynccontextmanager
    async def _connection_context(self, session_id: str = "system"):
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
        resources = []

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
                        mimeType="application/json",
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
                        mimeType="application/json",
                    )
                )

            # Add database statistics resource
            resources.append(
                Resource(
                    uri="doris://stats/database",
                    name="Database Statistics",
                    description="Overall database statistics and performance metrics",
                    mimeType="application/json",
                )
            )

        except Exception as e:
            self._reraise_if_doris_oauth_resource_error(e)
            print(f"Failed to get resource list: {e}")

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
                            mimeType="application/json",
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
                            mimeType="application/json",
                        )
                    )

                resources.append(
                    Resource(
                        uri=self._stats_resource_uri(db_name),
                        name=f"Database Statistics: {db_name}",
                        description=f"Overall database statistics for {db_name}",
                        mimeType="application/json",
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
                raise ValueError(f"Unsupported resource type: {resource_type}")

        except Exception as e:
            self._reraise_if_doris_oauth_resource_error(e)
            return json.dumps(
                {"error": f"Failed to read resource: {str(e)}", "uri": uri},
                ensure_ascii=False,
                indent=2,
            )

    async def _get_table_metadata(self) -> list[TableMetadata]:
        """Get metadata for all tables"""
        cache_key = "table_metadata"
        cached = await self.metadata_cache.get(cache_key)
        if cached:
            return cached

        async with self._connection_context("system") as connection:
            tables = await self._get_table_metadata_for_database(connection)

        await self.metadata_cache.set(cache_key, tables)
        return tables

    async def _get_visible_databases(self, connection) -> list[str]:
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
        self, connection, db_name: str | None = None
    ) -> list[TableMetadata]:
        """Get table metadata for a specific database or the current database."""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        tables_query = """
        SELECT
            table_name,
            table_comment,
            table_rows as row_count,
            create_time
        FROM information_schema.tables
        WHERE {schema_filter}
        AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """.format(schema_filter=schema_filter)

        auth_context = get_auth_context()
        result = await connection.execute(
            tables_query,
            params=schema_params or None,
            auth_context=auth_context,
        )
        tables = []

        for row in result.data:
            columns = await self._get_table_columns(connection, row["table_name"], db_name)

            table = TableMetadata(
                name=row["table_name"],
                comment=row.get("table_comment"),
                row_count=row.get("row_count", 0),
                columns=columns,
                create_time=row.get("create_time"),
                database=db_name,
            )
            tables.append(table)

        return tables

    async def _get_table_columns(
        self, connection, table_name: str, db_name: str | None = None
    ) -> list[dict]:
        """Get column information for table"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        columns_query = """
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
        """.format(schema_filter=schema_filter)

        auth_context = get_auth_context()
        result = await connection.execute(
            columns_query,
            params=(*schema_params, table_name),
            auth_context=auth_context,
        )
        return [dict(row) for row in result.data]

    async def _get_view_metadata(self) -> list[ViewMetadata]:
        """Get metadata for all views"""
        cache_key = "view_metadata"
        cached = await self.metadata_cache.get(cache_key)
        if cached:
            return cached

        async with self._connection_context("system") as connection:
            views = await self._get_view_metadata_for_database(connection)

        await self.metadata_cache.set(cache_key, views)
        return views

    async def _get_view_metadata_for_database(
        self, connection, db_name: str | None = None
    ) -> list[ViewMetadata]:
        """Get view metadata for a specific database or the current database."""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        views_query = """
        SELECT
            table_name,
            table_comment,
            view_definition
        FROM information_schema.views
        WHERE {schema_filter}
        ORDER BY table_name
        """.format(schema_filter=schema_filter)

        auth_context = get_auth_context()
        result = await connection.execute(
            views_query,
            params=schema_params or None,
            auth_context=auth_context,
        )
        views = []

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
        table_info_query = """
        SELECT
            table_name,
            table_comment,
            table_rows,
            create_time,
            engine
        FROM information_schema.tables
        WHERE {schema_filter}
        AND table_name = %s
        """.format(schema_filter=schema_filter)

        async with self._connection_context("system") as connection:
            auth_context = get_auth_context()
            table_result = await connection.execute(
                table_info_query,
                params=(*schema_params, table_name),
                auth_context=auth_context,
            )
            if not table_result.data:
                qualified_name = f"{db_name}.{table_name}" if db_name else table_name
                raise ValueError(f"Table {qualified_name} does not exist")

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
        self, connection, table_name: str, db_name: str | None = None
    ) -> list[dict]:
        """Get index information for table"""
        schema_filter, schema_params = self._schema_filter("table_schema", db_name)
        indexes_query = """
        SELECT
            index_name,
            column_name,
            index_type,
            non_unique
        FROM information_schema.statistics
        WHERE {schema_filter}
        AND table_name = %s
        ORDER BY index_name, seq_in_index
        """.format(schema_filter=schema_filter)

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
        view_query = """
        SELECT
            table_name,
            table_comment,
            view_definition
        FROM information_schema.views
        WHERE {schema_filter}
        AND table_name = %s
        """.format(schema_filter=schema_filter)

        async with self._connection_context("system") as connection:
            auth_context = get_auth_context()
            result = await connection.execute(
                view_query,
                params=(*schema_params, view_name),
                auth_context=auth_context,
            )
            if not result.data:
                qualified_name = f"{db_name}.{view_name}" if db_name else view_name
                raise ValueError(f"View {qualified_name} does not exist")

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
        table_stats_query = """
        SELECT
            COUNT(*) as table_count,
            SUM(table_rows) as total_rows
        FROM information_schema.tables
        WHERE {schema_filter}
        AND table_type = 'BASE TABLE'
        """.format(schema_filter=schema_filter)

        async with self._connection_context("system") as connection:
            auth_context = get_auth_context()
            table_result = await connection.execute(
                table_stats_query,
                params=schema_params or None,
                auth_context=auth_context,
            )
            table_stats = table_result.data[0] if table_result.data else {}

            # Get view statistics
            view_stats_query = """
            SELECT COUNT(*) as view_count
            FROM information_schema.views
            WHERE {schema_filter}
            """.format(schema_filter=schema_filter)

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
            raise ValueError("Invalid resource URI format")

        path = uri[8:]  # Remove "doris://" prefix
        parts = path.split("/")

        if len(parts) < 2:
            raise ValueError("Incomplete resource URI format")

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

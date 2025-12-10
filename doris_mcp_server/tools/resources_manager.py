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
from datetime import datetime
from typing import Any

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
    ):
        self.name = name
        self.comment = comment
        self.row_count = row_count
        self.columns = columns or []
        self.create_time = create_time


class ViewMetadata:
    """Data view metadata"""

    def __init__(self, name: str, comment: str = None, definition: str = None):
        self.name = name
        self.comment = comment
        self.definition = definition


class MetadataCache:
    """Metadata cache manager"""

    def __init__(self, ttl_seconds: int = 300):
        self.cache = {}
        self.ttl = ttl_seconds

    async def get(self, key: str) -> Any | None:
        if key in self.cache:
            data, timestamp = self.cache[key]
            if datetime.now().timestamp() - timestamp < self.ttl:
                return data
            else:
                del self.cache[key]
        return None

    async def set(self, key: str, value: Any):
        self.cache[key] = (value, datetime.now().timestamp())


class DorisResourcesManager:
    """Apache Doris Resources Manager"""

    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        self.metadata_cache = MetadataCache()

    async def list_resources(self) -> list[Resource]:
        """List all available database resources"""
        resources = []

        try:
            # Get metadata for all tables
            tables = await self._get_table_metadata()
            for table in tables:
                resources.append(
                    Resource(
                        uri=f"doris://table/{table.name}",
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
                        uri=f"doris://view/{view.name}",
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
            print(f"Failed to get resource list: {e}")

        return resources

    async def read_resource(self, uri: str) -> str:
        """Read detailed information of specific resource"""
        try:
            resource_type, resource_name = self._parse_resource_uri(uri)

            if resource_type == "table":
                return await self._get_table_schema(resource_name)
            elif resource_type == "view":
                return await self._get_view_definition(resource_name)
            elif resource_type == "stats" and resource_name == "database":
                return await self._get_database_stats()
            else:
                raise ValueError(f"Unsupported resource type: {resource_type}")

        except Exception as e:
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

        connection = await self.connection_manager.get_connection("system")

        # Query basic table information
        tables_query = """
        SELECT
            table_name,
            table_comment,
            table_rows as row_count,
            create_time
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_type = 'BASE TABLE'
        ORDER BY table_name
        """

        auth_context = get_auth_context()
        result = await connection.execute(tables_query, auth_context=auth_context)
        tables = []

        for row in result.data:
            # Get column information for the table
            columns = await self._get_table_columns(connection, row["table_name"])

            table = TableMetadata(
                name=row["table_name"],
                comment=row.get("table_comment"),
                row_count=row.get("row_count", 0),
                columns=columns,
                create_time=row.get("create_time"),
            )
            tables.append(table)

        await self.metadata_cache.set(cache_key, tables)
        return tables

    async def _get_table_columns(self, connection, table_name: str) -> list[dict]:
        """Get column information for table"""
        columns_query = """
        SELECT
            column_name,
            data_type,
            is_nullable,
            column_default,
            column_comment,
            column_key
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
        AND table_name = %s
        ORDER BY ordinal_position
        """

        auth_context = get_auth_context()
        result = await connection.execute(columns_query, params=(table_name,), auth_context=auth_context)
        return [dict(row) for row in result.data]

    async def _get_view_metadata(self) -> list[ViewMetadata]:
        """Get metadata for all views"""
        cache_key = "view_metadata"
        cached = await self.metadata_cache.get(cache_key)
        if cached:
            return cached

        connection = await self.connection_manager.get_connection("system")

        views_query = """
        SELECT
            table_name,
            table_comment,
            view_definition
        FROM information_schema.views
        WHERE table_schema = DATABASE()
        ORDER BY table_name
        """

        auth_context = get_auth_context()
        result = await connection.execute(views_query, auth_context=auth_context)
        views = []

        for row in result.data:
            view = ViewMetadata(
                name=row["table_name"],
                comment=row.get("table_comment"),
                definition=row.get("view_definition"),
            )
            views.append(view)

        await self.metadata_cache.set(cache_key, views)
        return views

    async def _get_table_schema(self, table_name: str) -> str:
        """Get detailed structure information of table"""
        connection = await self.connection_manager.get_connection("system")

        # Get basic table information
        table_info_query = """
        SELECT
            table_name,
            table_comment,
            table_rows,
            create_time,
            engine
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_name = %s
        """

        auth_context = get_auth_context()
        table_result = await connection.execute(table_info_query, params=(table_name,), auth_context=auth_context)
        if not table_result.data:
            raise ValueError(f"Table {table_name} does not exist")

        table_info = table_result.data[0]

        # Get column information
        columns = await self._get_table_columns(connection, table_name)

        # Get index information
        indexes = await self._get_table_indexes(connection, table_name)

        schema_info = {
            "table_name": table_info["table_name"],
            "comment": table_info.get("table_comment"),
            "row_count": table_info.get("table_rows", 0),
            "create_time": str(table_info.get("create_time")),
            "engine": table_info.get("engine"),
            "columns": columns,
            "indexes": indexes,
        }

        return json.dumps(schema_info, ensure_ascii=False, indent=2)

    async def _get_table_indexes(self, connection, table_name: str) -> list[dict]:
        """Get index information for table"""
        indexes_query = """
        SELECT
            index_name,
            column_name,
            index_type,
            non_unique
        FROM information_schema.statistics
        WHERE table_schema = DATABASE()
        AND table_name = %s
        ORDER BY index_name, seq_in_index
        """

        auth_context = get_auth_context()
        result = await connection.execute(indexes_query, params=(table_name,), auth_context=auth_context)
        return [dict(row) for row in result.data]

    async def _get_view_definition(self, view_name: str) -> str:
        """Get definition information of view"""
        connection = await self.connection_manager.get_connection("system")

        view_query = """
        SELECT
            table_name,
            table_comment,
            view_definition
        FROM information_schema.views
        WHERE table_schema = DATABASE()
        AND table_name = %s
        """

        auth_context = get_auth_context()
        result = await connection.execute(view_query, params=(view_name,), auth_context=auth_context)
        if not result.data:
            raise ValueError(f"View {view_name} does not exist")

        view_info = result.data[0]

        schema_info = {
            "view_name": view_info["table_name"],
            "comment": view_info.get("table_comment"),
            "definition": view_info.get("view_definition"),
        }

        return json.dumps(schema_info, ensure_ascii=False, indent=2)

    async def _get_database_stats(self) -> str:
        """Get database statistics"""
        connection = await self.connection_manager.get_connection("system")

        # Get table statistics
        table_stats_query = """
        SELECT
            COUNT(*) as table_count,
            SUM(table_rows) as total_rows
        FROM information_schema.tables
        WHERE table_schema = DATABASE()
        AND table_type = 'BASE TABLE'
        """

        auth_context = get_auth_context()
        table_result = await connection.execute(table_stats_query, auth_context=auth_context)
        table_stats = table_result.data[0] if table_result.data else {}

        # Get view statistics
        view_stats_query = """
        SELECT COUNT(*) as view_count
        FROM information_schema.views
        WHERE table_schema = DATABASE()
        """

        view_result = await connection.execute(view_stats_query, auth_context=auth_context)
        view_stats = view_result.data[0] if view_result.data else {}

        stats_info = {
            "database_name": "current_database",
            "table_count": table_stats.get("table_count", 0),
            "view_count": view_stats.get("view_count", 0),
            "total_rows": table_stats.get("total_rows", 0),
            "last_updated": datetime.now().isoformat(),
        }

        return json.dumps(stats_info, ensure_ascii=False, indent=2)

    def _parse_resource_uri(self, uri: str) -> tuple:
        """Parse resource URI"""
        if not uri.startswith("doris://"):
            raise ValueError("Invalid resource URI format")

        path = uri[8:]  # Remove "doris://" prefix
        parts = path.split("/")

        if len(parts) < 2:
            raise ValueError("Incomplete resource URI format")

        return parts[0], parts[1]

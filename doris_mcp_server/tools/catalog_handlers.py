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
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Catalog handler routes shared by formal and hidden legacy bindings."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..utils.analysis_tools import SQLAnalyzer
from ..utils.catalog_metadata import (
    CatalogMetadataFailure,
    DorisCatalogMetadataReader,
)
from ..utils.data_quality_tools import DataQualityTools
from ..utils.db import DorisConnectionManager
from ..utils.schema_extractor import MetadataExtractor


class CatalogToolHandlersMixin:
    """Keep Catalog-domain routing outside the manager control plane."""

    metadata_extractor: MetadataExtractor
    catalog_metadata: DorisCatalogMetadataReader
    sql_analyzer: SQLAnalyzer
    data_quality_tools: DataQualityTools

    def _initialize_catalog_handlers(
        self,
        connection_manager: DorisConnectionManager,
    ) -> None:
        self.catalog_metadata = DorisCatalogMetadataReader(connection_manager)

    @staticmethod
    def _required_string(arguments: dict[str, Any], name: str) -> str:
        raise NotImplementedError

    async def _get_table_schema_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.get_table_schema(
                table_name=table_name,
                database_name=self._required_string(arguments, "db_name"),
                catalog_name=catalog_name,
            )
        return await self.metadata_extractor.get_table_schema_for_mcp(
            table_name,
            db_name,
            catalog_name,
        )

    async def _get_db_table_list_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.list_tables(
                database_name=self._required_string(arguments, "db_name"),
                catalog_name=catalog_name,
            )
        return await self.metadata_extractor.get_db_table_list_for_mcp(
            db_name,
            catalog_name,
        )

    async def _get_db_list_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        catalog_name = arguments.get("catalog_name")
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.list_databases(
                catalog_name=catalog_name,
            )
        return await self.metadata_extractor.get_db_list_for_mcp(catalog_name)

    async def _get_table_comment_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.get_table_comment(
                table_name=table_name,
                database_name=self._required_string(arguments, "db_name"),
                catalog_name=catalog_name,
            )
        return await self.metadata_extractor.get_table_comment_for_mcp(
            table_name,
            db_name,
            catalog_name,
        )

    async def _get_table_column_comments_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.get_column_comments(
                table_name=table_name,
                database_name=self._required_string(arguments, "db_name"),
                catalog_name=catalog_name,
            )
        return await self.metadata_extractor.get_table_column_comments_for_mcp(
            table_name,
            db_name,
            catalog_name,
        )

    async def _get_table_indexes_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        table_name = self._required_string(arguments, "table_name")
        db_name = arguments.get("db_name")
        catalog_name = arguments.get("catalog_name")
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.get_table_indexes(
                table_name=table_name,
                database_name=self._required_string(arguments, "db_name"),
                catalog_name=catalog_name,
            )
        return await self.metadata_extractor.get_table_indexes_for_mcp(
            table_name,
            db_name,
            catalog_name,
        )

    async def _get_catalog_list_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.list_catalogs()
        return await self.metadata_extractor.get_catalog_list_for_mcp()

    async def _get_table_data_size_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        db_name = arguments.get("db_name")
        table_name = arguments.get("table_name")
        single_replica = arguments.get("single_replica", False)
        if arguments.get("_formal_catalog"):
            return await self.catalog_metadata.get_table_size(
                table_name=self._required_string(arguments, "table_name"),
                database_name=self._required_string(arguments, "db_name"),
                catalog_name=arguments.get("catalog_name"),
                include_partitions=bool(
                    arguments.get("include_partitions", False)
                ),
            )
        return await self.sql_analyzer.get_table_data_size(
            db_name,
            table_name,
            single_replica,
        )

    async def _get_table_basic_info_tool(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            table_name = self._required_string(arguments, "table_name")
            catalog_name = arguments.get("catalog_name")
            db_name = arguments.get("db_name")
            if arguments.get("_formal_catalog"):
                return await self.catalog_metadata.get_table_basic(
                    table_name=table_name,
                    database_name=self._required_string(
                        arguments,
                        "db_name",
                    ),
                    catalog_name=catalog_name,
                )
            return await self.data_quality_tools.get_table_basic_info(
                table_name=table_name,
                catalog_name=catalog_name,
                db_name=db_name,
            )
        except CatalogMetadataFailure:
            raise
        except Exception as exc:
            return {
                "error": str(exc),
                "analysis_type": "table_basic_info",
                "timestamp": datetime.now().isoformat(),
            }


__all__ = ["CatalogToolHandlersMixin"]

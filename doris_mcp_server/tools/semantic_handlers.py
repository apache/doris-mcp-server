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

"""Formal Semantic-domain handlers backed by the Ossie adapter runtime."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

from ..semantic.runtime import DorisSemanticRuntime
from ..utils.db import DorisConnectionManager


class _SemanticHandlerOwner(Protocol):
    semantic_runtime: DorisSemanticRuntime


class SemanticToolHandlersMixin:
    """Route all semantic children through exact-reference operations."""

    def _initialize_semantic_handlers(
        self: _SemanticHandlerOwner,
        connection_manager: DorisConnectionManager,
    ) -> None:
        self.semantic_runtime = DorisSemanticRuntime(connection_manager)

    async def _formal_doris_semantic_list_semantic_models_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.list_semantic_models(
            namespace=cast(str | None, arguments.get("namespace")),
            tag=cast(str | None, arguments.get("tag")),
            pattern=cast(str | None, arguments.get("pattern")),
        )

    async def _formal_doris_semantic_get_semantic_model_summary_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.get_semantic_model_summary(
            model_ref=cast(str, arguments.get("model_ref")),
            include_bindings=bool(arguments.get("include_bindings", False)),
        )

    async def _formal_doris_semantic_get_semantic_context_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.get_semantic_context(
            model_ref=cast(str, arguments.get("model_ref")),
            request=cast(Mapping[str, Any], arguments.get("request")),
        )

    async def _formal_doris_semantic_get_semantic_mapping_status_tool(
        self: _SemanticHandlerOwner,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        return await self.semantic_runtime.get_semantic_mapping_status(
            model_ref=cast(str, arguments.get("model_ref")),
            datasource=cast(str | None, arguments.get("datasource")),
        )


__all__ = ["SemanticToolHandlersMixin"]

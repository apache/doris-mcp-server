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

"""Exact routing tests for the formal Semantic-domain handlers."""

from __future__ import annotations

from typing import Any

import pytest

from doris_mcp_server.tools.semantic_handlers import SemanticToolHandlersMixin


class _Runtime:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def list_semantic_models(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("list", kwargs))
        return {"operation": "list"}

    async def get_semantic_model_summary(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls.append(("summary", kwargs))
        return {"operation": "summary"}

    async def get_semantic_context(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(("context", kwargs))
        return {"operation": "context"}

    async def get_semantic_mapping_status(
        self,
        **kwargs: Any,
    ) -> dict[str, Any]:
        self.calls.append(("mapping", kwargs))
        return {"operation": "mapping"}


class _Owner(SemanticToolHandlersMixin):
    def __init__(self) -> None:
        self.semantic_runtime = _Runtime()  # type: ignore[assignment]


@pytest.mark.asyncio
async def test_semantic_handlers_route_exact_arguments() -> None:
    owner = _Owner()

    assert await owner._formal_doris_semantic_list_semantic_models_tool(
        {
            "namespace": "commerce",
            "tag": "certified",
            "pattern": "ret*",
        }
    ) == {"operation": "list"}
    assert (
        await owner._formal_doris_semantic_get_semantic_model_summary_tool(
            {
                "model_ref": "retail/main",
                "include_bindings": True,
            }
        )
        == {"operation": "summary"}
    )
    request = {"question": "revenue"}
    assert await owner._formal_doris_semantic_get_semantic_context_tool(
        {
            "model_ref": "retail/main",
            "request": request,
        }
    ) == {"operation": "context"}
    assert (
        await owner._formal_doris_semantic_get_semantic_mapping_status_tool(
            {
                "model_ref": "retail/main",
                "datasource": "orders",
            }
        )
        == {"operation": "mapping"}
    )

    assert owner.semantic_runtime.calls == [
        (
            "list",
            {
                "namespace": "commerce",
                "tag": "certified",
                "pattern": "ret*",
            },
        ),
        (
            "summary",
            {
                "model_ref": "retail/main",
                "include_bindings": True,
            },
        ),
        (
            "context",
            {
                "model_ref": "retail/main",
                "request": request,
            },
        ),
        (
            "mapping",
            {
                "model_ref": "retail/main",
                "datasource": "orders",
            },
        ),
    ]


@pytest.mark.asyncio
async def test_semantic_handler_defaults_do_not_guess_model() -> None:
    owner = _Owner()

    await owner._formal_doris_semantic_list_semantic_models_tool({})
    await owner._formal_doris_semantic_get_semantic_model_summary_tool(
        {"model_ref": "retail/main"}
    )
    await owner._formal_doris_semantic_get_semantic_mapping_status_tool(
        {"model_ref": "retail/main"}
    )

    assert owner.semantic_runtime.calls == [
        (
            "list",
            {"namespace": None, "tag": None, "pattern": None},
        ),
        (
            "summary",
            {
                "model_ref": "retail/main",
                "include_bindings": False,
            },
        ),
        (
            "mapping",
            {
                "model_ref": "retail/main",
                "datasource": None,
            },
        ),
    ]

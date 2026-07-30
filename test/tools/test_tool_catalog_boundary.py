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
"""Architectural boundary tests for tool metadata and manager routing."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from doris_mcp_server.tools.tool_catalog import build_tool_registry
from doris_mcp_server.tools.tools_manager import DorisToolsManager


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        security=SimpleNamespace(max_result_rows=50),
        performance=SimpleNamespace(
            max_result_bytes=4096,
            query_timeout=20,
        ),
        adbc=SimpleNamespace(
            default_max_rows=25,
            default_timeout=10,
            default_return_format="dict",
        ),
    )


def test_manager_delegates_catalog_construction() -> None:
    source = inspect.getsource(DorisToolsManager._build_tool_registry)

    assert "build_tool_registry(" in source
    assert "Tool(" not in source
    assert len(Path(inspect.getfile(DorisToolsManager)).read_text().splitlines()) < 800


def test_catalog_does_not_depend_on_tools_manager_module() -> None:
    catalog_path = Path(inspect.getfile(build_tool_registry))
    tree = ast.parse(catalog_path.read_text())
    imports = {
        node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }

    assert "tools_manager" not in imports
    assert ".tools_manager" not in imports


def test_catalog_preserves_names_schemas_and_handler_binding() -> None:
    connection_manager = Mock()
    connection_manager.config = _config()
    manager = DorisToolsManager(connection_manager)

    standalone = build_tool_registry(manager, connection_manager.config)
    delegated = manager.tool_registry

    standalone_names = tuple(definition.name for definition in standalone.definitions)
    delegated_names = tuple(definition.name for definition in delegated.definitions)
    assert standalone_names == delegated_names
    for name in delegated_names:
        standalone_definition = standalone.resolve(name)
        delegated_definition = delegated.resolve(name)
        assert standalone_definition.tool == delegated_definition.tool
        assert standalone_definition.handler_name == (delegated_definition.handler_name)
        assert standalone_definition.bind_handler(manager).__self__ is manager

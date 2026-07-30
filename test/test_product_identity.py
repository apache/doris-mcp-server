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
"""Product identity must come from one build-time version source."""

import tomllib
from importlib.metadata import version as distribution_version
from pathlib import Path

import pytest

from doris_mcp_client.client import create_arg_parser as create_client_arg_parser
from doris_mcp_server import __version__
from doris_mcp_server.main import create_arg_parser as create_server_arg_parser
from doris_mcp_server.utils.config import DorisConfig

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_package_metadata_matches_runtime_version():
    assert distribution_version("doris-mcp-server") == __version__


@pytest.mark.parametrize(
    "parser_factory",
    [create_server_arg_parser, create_client_arg_parser],
)
def test_cli_reports_product_version(capsys, parser_factory):
    with pytest.raises(SystemExit) as exit_info:
        parser_factory().parse_args(["--version"])

    assert exit_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"pytest {__version__}"


def test_configuration_cannot_override_product_version(monkeypatch):
    monkeypatch.setenv("SERVER_VERSION", "9.9.9")

    assert DorisConfig.from_env().server_version == __version__
    assert DorisConfig._from_dict({"server_version": "9.9.9"}).server_version == (
        __version__
    )


def test_release_docs_and_commands_match_product_version():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    normalized_readme = " ".join(readme.split())
    changelog = (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    makefile = (PROJECT_ROOT / "Makefile").read_text(encoding="utf-8")
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert f"pip install doris-mcp-server=={__version__}" in readme
    assert f"## [{__version__}]" in changelog
    assert (
        "MCP `2026-07-28` protocol compatibility on `master` is **Generally "
        "Available (GA)**"
    ) in normalized_readme
    assert "This GA statement is scoped to protocol compatibility" in readme
    assert (
        "Development Status :: 4 - Beta"
        in pyproject["project"]["classifiers"]
    )
    assert "the two commands are not interchangeable" in readme
    assert pyproject["project"]["scripts"] == {
        "doris-mcp-server": "doris_mcp_server.main:main_sync",
        "doris-mcp-client": "doris_mcp_client.client:main",
    }
    assert "start-http:" in makefile
    assert "--transport http" in makefile
    assert "start-sse" not in makefile
    assert "--transport sse" not in makefile


def test_readme_language_switcher_is_bidirectional():
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    chinese_readme = (PROJECT_ROOT / "README.zh-CN.md").read_text(encoding="utf-8")

    assert "[English](README.md) | [简体中文](README.zh-CN.md)" in readme
    assert "[English](README.md) | 简体中文" in chinese_readme

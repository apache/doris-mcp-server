# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Release artifacts must remain generated, English, and identity-aligned."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from doris_mcp_server import __version__
from doris_mcp_server.tools.domain_catalog import (
    DORIS_DOMAIN_CATALOG,
    FORMAL_CHILD_FEATURE_IDS,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOL_CATALOG = REPOSITORY_ROOT / "docs" / "tool-registry.md"
MIGRATION_GUIDE = REPOSITORY_ROOT / "docs" / "migration-1.0.0.md"
RELEASE_NOTES = REPOSITORY_ROOT / "docs" / "release-notes-1.0.0.md"
HAN_TEXT = re.compile(r"[\u3400-\u9fff]")


def test_release_identity_and_documents_are_1_0_0() -> None:
    readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
    chinese_readme = (REPOSITORY_ROOT / "README.zh-CN.md").read_text(
        encoding="utf-8"
    )
    changelog = (REPOSITORY_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    assert __version__ == "1.0.0"
    assert "pip install doris-mcp-server==1.0.0" in readme
    assert "pip install doris-mcp-server==1.0.0" in chinese_readme
    assert "[1.0.0] - 2026-07-31" in changelog
    assert "[Unreleased]: " in changelog
    assert "compare/1.0.0...HEAD" in changelog
    assert "docs/migration-1.0.0.md" in readme
    assert "docs/release-notes-1.0.0.md" in readme
    assert "docs/tool-registry.md" in readme


def test_source_distribution_includes_release_documents() -> None:
    pyproject = tomllib.loads(
        (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    included = set(pyproject["tool"]["hatch"]["build"]["targets"]["sdist"]["include"])

    assert {
        "/docs/migration-1.0.0.md",
        "/docs/release-notes-1.0.0.md",
        "/docs/tool-registry.md",
    }.issubset(included)


def test_generated_tool_catalog_matches_the_runtime_source() -> None:
    catalog = TOOL_CATALOG.read_text(encoding="utf-8")
    summary = DORIS_DOMAIN_CATALOG.summary()

    assert catalog == DORIS_DOMAIN_CATALOG.render_markdown()
    assert summary.domain_count == 8
    assert summary.child_count == 47
    assert summary.migrated_flat_tool_count == 25
    assert len(FORMAL_CHILD_FEATURE_IDS) == 47
    assert all(f"`{feature_id}`" in catalog for feature_id in FORMAL_CHILD_FEATURE_IDS)


def test_new_release_documents_are_english_only() -> None:
    for path in (TOOL_CATALOG, MIGRATION_GUIDE, RELEASE_NOTES):
        content = path.read_text(encoding="utf-8")
        assert not HAN_TEXT.search(content), path


def test_migration_guide_does_not_promise_legacy_aliases() -> None:
    guide = MIGRATION_GUIDE.read_text(encoding="utf-8")
    normalized = " ".join(guide.split())

    assert "not registered as aliases" in guide
    assert "Flat mode does not restore pre-1.0 names." in guide
    assert "do not make the old call names discoverable or callable" in normalized
    assert "MCP_TOOL_EXPOSURE_MODE=flat" in guide
    assert "ENABLE_LEGACY_HTTP_ADAPTER=true" in guide

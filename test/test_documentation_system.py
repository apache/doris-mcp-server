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

"""Contracts for the categorized bilingual documentation system."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOCS_ROOT = PROJECT_ROOT / "docs"
LICENSE_MARKER = "Licensed to the Apache Software Foundation (ASF)"
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)\n]+)\)")

TOPIC_PAIRS = (
    ("docs/README.md", "docs/README.zh-CN.md"),
    (
        "docs/getting-started/quickstart.md",
        "docs/getting-started/quickstart.zh-CN.md",
    ),
    ("docs/architecture/overview.md", "docs/architecture/overview.zh-CN.md"),
    (
        "docs/architecture/request-lifecycle.md",
        "docs/architecture/request-lifecycle.zh-CN.md",
    ),
    (
        "docs/capabilities/tool-domains.md",
        "docs/capabilities/tool-domains.zh-CN.md",
    ),
    (
        "docs/capabilities/availability.md",
        "docs/capabilities/availability.zh-CN.md",
    ),
    (
        "docs/protocol/mcp-2026-07-28.md",
        "docs/protocol/mcp-2026-07-28.zh-CN.md",
    ),
    (
        "docs/security/security-model.md",
        "docs/security/security-model.zh-CN.md",
    ),
    (
        "docs/operations/deployment.md",
        "docs/operations/deployment.zh-CN.md",
    ),
    (
        "docs/operations/reliability.md",
        "docs/operations/reliability.zh-CN.md",
    ),
    (
        "docs/operations/troubleshooting.md",
        "docs/operations/troubleshooting.zh-CN.md",
    ),
    (
        "docs/reference/configuration.md",
        "docs/reference/configuration.zh-CN.md",
    ),
    ("docs/integrations/hosts.md", "docs/integrations/hosts.zh-CN.md"),
    (
        "docs/development/contributing.md",
        "docs/development/contributing.zh-CN.md",
    ),
    ("docs/migration/1.0.0.md", "docs/migration/1.0.0.zh-CN.md"),
    ("docs/releases/1.0.0.md", "docs/releases/1.0.0.zh-CN.md"),
    (
        "docs/custom-tool-providers.md",
        "docs/custom-tool-providers.zh-CN.md",
    ),
    (
        "docs/doris-fine-grained-access-control.md",
        "docs/doris-fine-grained-access-control.zh-CN.md",
    ),
)


def _markdown_files() -> tuple[Path, ...]:
    files = [PROJECT_ROOT / "README.md", PROJECT_ROOT / "README.zh-CN.md"]
    files.extend(sorted(DOCS_ROOT.rglob("*.md")))
    files.append(PROJECT_ROOT / "test" / "README.md")
    return tuple(files)


def _relative_link_target(source: Path, raw_target: str) -> Path | None:
    target = raw_target.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")]
    else:
        target = target.split(maxsplit=1)[0]

    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None
    if parsed.path.startswith("/"):
        return None

    return (source.parent / unquote(parsed.path)).resolve()


def test_root_readmes_are_bounded_entry_points() -> None:
    assert len((PROJECT_ROOT / "README.md").read_text().splitlines()) <= 300
    assert len((PROJECT_ROOT / "README.zh-CN.md").read_text().splitlines()) <= 300


def test_bilingual_topics_exist_and_cross_link() -> None:
    for english_name, chinese_name in TOPIC_PAIRS:
        english = PROJECT_ROOT / english_name
        chinese = PROJECT_ROOT / chinese_name

        assert english.is_file(), english_name
        assert chinese.is_file(), chinese_name
        english_content = english.read_text(encoding="utf-8")
        chinese_content = chinese.read_text(encoding="utf-8")
        assert chinese.name in english_content, english_name
        assert english.name in chinese_content, chinese_name
        assert english_content.count("\n## ") == chinese_content.count("\n## "), (
            english_name,
            chinese_name,
        )


def test_new_topic_guides_have_apache_license_headers() -> None:
    checked = {PROJECT_ROOT / name for pair in TOPIC_PAIRS for name in pair}
    for path in checked:
        content = path.read_text(encoding="utf-8")
        assert content.count(LICENSE_MARKER) == 1, path
        assert len(re.findall(r"^# [^#]", content, flags=re.MULTILINE)) == 1, path


def test_documentation_relative_links_resolve() -> None:
    broken: list[str] = []

    for source in _markdown_files():
        content = source.read_text(encoding="utf-8")
        for match in MARKDOWN_LINK.finditer(content):
            target = _relative_link_target(source, match.group(1))
            if target is not None and not target.exists():
                broken.append(f"{source.relative_to(PROJECT_ROOT)} -> {match.group(1)}")

    assert not broken, "Broken documentation links:\n" + "\n".join(broken)


def test_documentation_indexes_cover_the_public_contract() -> None:
    english = (DOCS_ROOT / "README.md").read_text(encoding="utf-8")
    chinese = (DOCS_ROOT / "README.zh-CN.md").read_text(encoding="utf-8")

    for marker in (
        "architecture/overview.md",
        "capabilities/tool-domains.md",
        "protocol/mcp-2026-07-28.md",
        "security/security-model.md",
        "operations/reliability.md",
        "releases/1.0.0.md",
        "issues/189",
    ):
        assert marker in english

    for marker in (
        "architecture/overview.zh-CN.md",
        "capabilities/tool-domains.zh-CN.md",
        "protocol/mcp-2026-07-28.zh-CN.md",
        "security/security-model.zh-CN.md",
        "operations/reliability.zh-CN.md",
        "releases/1.0.0.zh-CN.md",
        "issues/189",
    ):
        assert marker in chinese

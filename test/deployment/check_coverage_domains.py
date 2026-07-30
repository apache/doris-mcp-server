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
"""Enforce coverage floors for the highest-risk runtime domains."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CoverageDomain:
    minimum: float
    exact_files: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()


DOMAINS = {
    "protocol": CoverageDomain(
        minimum=80.0,
        exact_files=frozenset(
            {
                "doris_mcp_server/health.py",
                "doris_mcp_server/http_transport.py",
                "doris_mcp_server/pagination.py",
                "doris_mcp_server/protocol.py",
                "doris_mcp_server/schema_validation.py",
                "doris_mcp_server/state_handles.py",
                "doris_mcp_server/trace_context.py",
            }
        ),
    ),
    "authentication": CoverageDomain(
        minimum=80.0,
        prefixes=("doris_mcp_server/auth/",),
    ),
    "core_managers": CoverageDomain(
        minimum=80.0,
        exact_files=frozenset(
            {
                "doris_mcp_server/tools/prompts_manager.py",
                "doris_mcp_server/tools/resources_manager.py",
                "doris_mcp_server/tools/tool_catalog.py",
                "doris_mcp_server/tools/tool_registry.py",
                "doris_mcp_server/tools/tools_manager.py",
            }
        ),
    ),
}


def _normalized_files(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        name.replace("\\", "/"): details
        for name, details in report.get("files", {}).items()
    }


def evaluate_domains(report: dict[str, Any]) -> dict[str, float]:
    """Return domain percentages or raise when the report is incomplete."""
    files = _normalized_files(report)
    percentages: dict[str, float] = {}

    for name, domain in DOMAINS.items():
        missing = domain.exact_files.difference(files)
        if missing:
            raise ValueError(
                f"{name} coverage is missing required files: {', '.join(sorted(missing))}"
            )

        selected = {
            path: details
            for path, details in files.items()
            if path in domain.exact_files
            or any(path.startswith(prefix) for prefix in domain.prefixes)
        }
        if not selected:
            raise ValueError(f"{name} coverage selected no measured files")

        statements = sum(
            int(details["summary"]["num_statements"]) for details in selected.values()
        )
        covered = sum(
            int(details["summary"]["covered_lines"]) for details in selected.values()
        )
        if statements == 0:
            raise ValueError(f"{name} coverage has no executable statements")
        percentages[name] = covered * 100.0 / statements

    return percentages


def enforce_domains(report: dict[str, Any]) -> dict[str, float]:
    """Raise when any domain is below its declared minimum."""
    percentages = evaluate_domains(report)
    failures = [
        f"{name}={percentages[name]:.2f}% < {domain.minimum:.2f}%"
        for name, domain in DOMAINS.items()
        if percentages[name] < domain.minimum
    ]
    if failures:
        raise ValueError("coverage domain gate failed: " + "; ".join(failures))
    return percentages


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: check_coverage_domains.py COVERAGE_JSON", file=sys.stderr)
        return 2

    try:
        report = json.loads(Path(args[0]).read_text(encoding="utf-8"))
        percentages = enforce_domains(report)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for name, percentage in percentages.items():
        print(f"{name}: {percentage:.2f}% (minimum {DOMAINS[name].minimum:.2f}%)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

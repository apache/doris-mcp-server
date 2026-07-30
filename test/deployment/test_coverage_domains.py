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

from __future__ import annotations

import json
from pathlib import Path

import pytest

from test.deployment.check_coverage_domains import (
    DOMAINS,
    enforce_domains,
    evaluate_domains,
    main,
)


def _report(*, covered: int = 8, statements: int = 10) -> dict:
    files: dict[str, dict] = {}
    for domain in DOMAINS.values():
        paths = set(domain.exact_files)
        if domain.prefixes:
            paths.add(f"{domain.prefixes[0]}representative.py")
        for path in paths:
            files[path] = {
                "summary": {
                    "covered_lines": covered,
                    "num_statements": statements,
                }
            }
    return {"files": files}


def test_domain_gate_accepts_each_domain_at_eighty_percent() -> None:
    assert enforce_domains(_report()) == {
        "protocol": 80.0,
        "authentication": 80.0,
        "core_managers": 80.0,
    }


def test_domain_gate_includes_every_authentication_module() -> None:
    report = _report()
    report["files"]["doris_mcp_server/auth/uncovered.py"] = {
        "summary": {"covered_lines": 0, "num_statements": 10}
    }

    percentages = evaluate_domains(report)

    assert percentages["authentication"] < 80.0
    with pytest.raises(ValueError, match="authentication="):
        enforce_domains(report)


def test_domain_gate_fails_closed_when_required_file_is_absent() -> None:
    report = _report()
    report["files"].pop("doris_mcp_server/protocol.py")

    with pytest.raises(ValueError, match="missing required files"):
        evaluate_domains(report)


def test_cli_reports_failures_and_success(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    report_path = tmp_path / "coverage.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    assert main([str(report_path)]) == 0
    assert "authentication: 80.00%" in capsys.readouterr().out

    report_path.write_text("{}", encoding="utf-8")
    assert main([str(report_path)]) == 1
    assert "missing required files" in capsys.readouterr().err

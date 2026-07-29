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

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.tools.resources_manager import DorisResourcesManager
from doris_mcp_server.utils.analysis_tools import TableAnalyzer
from doris_mcp_server.utils.data_governance_tools import DataGovernanceTools
from doris_mcp_server.utils.data_quality_tools import DataQualityTools
from doris_mcp_server.utils.performance_analytics_tools import (
    PerformanceAnalyticsTools,
)
from doris_mcp_server.utils.schema_extractor import MetadataExtractor
from doris_mcp_server.utils.security_analytics_tools import SecurityAnalyticsTools
from doris_mcp_server.utils.sql_security_utils import (
    SQLSecurityError,
    build_rule_predicate,
    validate_integer,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = REPOSITORY_ROOT / "doris_mcp_server"
FULL_BANDIT_TARGETS = (
    SOURCE_ROOT,
    REPOSITORY_ROOT / "doris_mcp_client",
    REPOSITORY_ROOT / "generate_requirements.py",
)


def test_configured_bandit_source_gate_has_no_findings():
    bandit = shutil.which("bandit")
    assert bandit is not None, "Bandit must be installed from the dev dependency group"
    completed = subprocess.run(
        [
            bandit,
            "-q",
            "-c",
            str(REPOSITORY_ROOT / "pyproject.toml"),
            "-r",
            *(str(path) for path in FULL_BANDIT_TARGETS),
            "-f",
            "json",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    report = json.loads(completed.stdout)
    assert report["results"] == [], completed.stdout
    assert completed.returncode == 0


def test_non_sql_bandit_exceptions_are_rule_specific_and_documented():
    exceptions = 0
    for root in FULL_BANDIT_TARGETS:
        paths = root.rglob("*.py") if root.is_dir() else (root,)
        for path in paths:
            lines = path.read_text(encoding="utf-8").splitlines()
            for index, line in enumerate(lines):
                if "# nosec" not in line or "# nosec B608" in line:
                    continue
                exceptions += 1
                rule_text = line.split("# nosec", 1)[1].strip()
                rules = [rule.strip() for rule in rule_text.split(",")]
                assert rules and all(
                    len(rule) == 4
                    and rule.startswith("B")
                    and rule[1:].isdigit()
                    for rule in rules
                ), f"non-specific Bandit exception: {path}:{index + 1}"
                rationale = " ".join(lines[max(0, index - 3) : index + 1])
                assert "Bandit audit:" in rationale, (
                    f"missing Bandit rationale: {path}:{index + 1}"
                )

    assert exceptions == 2


def test_b608_has_no_untriaged_dynamic_sql_findings():
    bandit = shutil.which("bandit")
    if bandit is None:
        pytest.skip("install the project dev extra to run the Bandit SQL sink gate")
    completed = subprocess.run(
        [
            bandit,
            "-q",
            "-r",
            str(SOURCE_ROOT),
            "-t",
            "B608",
            "-f",
            "json",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )

    report = json.loads(completed.stdout)
    assert report["results"] == [], completed.stdout
    assert completed.returncode == 0


def test_every_b608_exception_carries_local_source_validation_sink_rationale():
    exceptions = 0
    for path in SOURCE_ROOT.rglob("*.py"):
        lines = path.read_text(encoding="utf-8").splitlines()
        previous_exception = -1
        for index, line in enumerate(lines):
            if "# nosec B608" not in line:
                continue
            exceptions += 1
            rationale = " ".join(
                lines[max(previous_exception + 1, index - 50) : index + 1]
            )
            assert "SQL sink audit:" in rationale, f"missing rationale: {path}:{index + 1}"
            assert (
                "execute" in rationale or "executor" in rationale
            ), f"missing sink: {path}:{index + 1}"
            previous_exception = index

    assert exceptions > 0


@pytest.mark.parametrize("value", [True, "10", 1.5, None])
def test_sql_integer_validation_rejects_non_integers(value):
    with pytest.raises(SQLSecurityError):
        validate_integer(value, "limit", minimum=0, maximum=100)


def test_structured_business_rule_uses_bound_values():
    attack_value = "active' OR 1=1 --"

    predicate, params = build_rule_predicate(
        {
            "column": "status",
            "operator": "=",
            "value": attack_value,
        }
    )

    assert predicate == "`status` = %s"
    assert params == (attack_value,)
    assert attack_value not in predicate


@pytest.mark.parametrize(
    "rule",
    [
        {"sql_condition": "1=1); DROP TABLE users; --"},
        {"sql_condition": ""},
        {"operator": "=", "value": 1},
        {"column": "status`; DROP TABLE users; --", "operator": "=", "value": 1},
        {"column": "status", "operator": "= 1 OR 1=1", "value": 1},
        {"column": "status", "operator": "IN", "values": []},
    ],
)
def test_structured_business_rule_rejects_raw_or_invalid_fragments(rule):
    with pytest.raises(SQLSecurityError):
        build_rule_predicate(rule)


@pytest.mark.asyncio
async def test_business_rule_sink_binds_untrusted_value():
    attack_value = "active' OR 1=1 --"
    connection = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                data=[{"total_count": 2, "pass_count": 1}]
            )
        )
    )
    tools = DataGovernanceTools(SimpleNamespace())

    result = await tools._check_business_rule_compliance(
        connection,
        "`internal`.`analytics`.`orders`",
        [
            {
                "rule_name": "active-only",
                "column": "status",
                "operator": "=",
                "value": attack_value,
            }
        ],
        2,
    )

    assert result["active-only"]["pass_count"] == 1
    sql = connection.execute.await_args.args[0]
    assert attack_value not in sql
    assert connection.execute.await_args.kwargs["params"] == (attack_value,)


@pytest.mark.asyncio
async def test_table_analyzer_rejects_identifier_injection_before_db_sink():
    manager = SimpleNamespace(get_connection=AsyncMock())
    analyzer = TableAnalyzer(manager)

    result = await analyzer.analyze_column(
        "orders`; DROP TABLE orders; --",
        "amount",
    )

    assert result["success"] is False
    manager.get_connection.assert_not_awaited()


@pytest.mark.asyncio
async def test_batch_column_analysis_quotes_metadata_identifiers_and_stable_aliases():
    connection = SimpleNamespace(
        execute=AsyncMock(
            return_value=SimpleNamespace(
                data=[
                    {
                        "total_rows": 2,
                        "column_0_non_null": 1,
                        "column_0_distinct": 1,
                    }
                ]
            )
        )
    )
    tools = object.__new__(DataQualityTools)

    result = await tools._analyze_completeness_batch(
        connection,
        "`internal`.`analytics`.`orders`",
        [{"column_name": "status"}],
    )

    sql = connection.execute.await_args.args[0]
    assert "COUNT(`status`) as column_0_non_null" in sql
    assert result["status"]["null_count"] == 1


def test_resource_schema_filter_quotes_the_only_dynamic_identifier():
    manager = DorisResourcesManager(SimpleNamespace())

    condition, params = manager._schema_filter("table_schema", "analytics")

    assert condition == "`table_schema` = %s"
    assert params == ("analytics",)
    with pytest.raises(SQLSecurityError):
        manager._schema_filter("table_schema OR 1=1", "analytics")


@pytest.mark.asyncio
async def test_schema_metadata_values_are_bound_before_connection_manager_sink():
    manager = SimpleNamespace(
        execute_query=AsyncMock(
            return_value=SimpleNamespace(data=[{"TABLE_VISIBLE": 1}])
        )
    )
    extractor = MetadataExtractor(
        db_name="analytics",
        catalog_name="internal",
        connection_manager=manager,
    )
    extractor._is_doris_oauth_context = lambda auth_context=None: True
    attack_table = "orders' OR 1=1 --"
    attack_database = "analytics' OR 1=1 --"

    await extractor._ensure_table_visible_for_doris_oauth_metadata(
        attack_table,
        attack_database,
        "internal",
    )

    sql = manager.execute_query.await_args.args[1]
    params = manager.execute_query.await_args.args[2]
    assert attack_table not in sql
    assert attack_database not in sql
    assert params == (attack_database, attack_table)


@pytest.mark.asyncio
async def test_audit_analytics_bind_dates_thresholds_and_system_users():
    connection = SimpleNamespace(
        execute=AsyncMock(return_value=SimpleNamespace(data=[]))
    )
    performance = PerformanceAnalyticsTools(SimpleNamespace())
    security = SecurityAnalyticsTools(SimpleNamespace())

    await performance._get_slow_query_data(connection, 7, 1000)
    performance_sql = connection.execute.await_args.args[0]
    performance_params = connection.execute.await_args.kwargs["params"]
    assert "WHERE `time` >= %s" in performance_sql
    assert "`query_time` >= %s" in performance_sql
    assert performance_params[1] == 1000

    connection.execute.reset_mock()
    await security._get_audit_log_data(
        connection,
        SimpleNamespace(),
        SimpleNamespace(),
        include_system_users=False,
    )
    security_sql = connection.execute.await_args.args[0]
    security_params = connection.execute.await_args.kwargs["params"]
    assert "NOT IN (%s, %s, %s, %s, %s)" in security_sql
    assert security_params[2:] == (
        "root",
        "admin",
        "system",
        "doris",
        "information_schema",
    )

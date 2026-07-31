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

"""Tests for route-aware, read-only Doris capability probes."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.tools.capability_detector import (
    CapabilityDetectionError,
    CapabilityProbeStatus,
    CapabilityRouteChangedError,
    DorisCapabilityDetector,
    _classify_profile_api_response,
)
from doris_mcp_server.tools.doris_feature_matrix import DORIS_FEATURE_MATRIX
from doris_mcp_server.utils.db import DorisRouteIdentity
from doris_mcp_server.utils.doris_http_client import DorisHTTPResponse
from doris_mcp_server.utils.security import AuthContext


class _ProbeConnection:
    def __init__(self) -> None:
        self.statements: list[str] = []
        self.failures: dict[str, Exception] = {}
        self.row_overrides: dict[str, list[dict[str, Any]]] = {}
        self.on_execute: Any | None = None

    async def execute(
        self,
        sql: str,
        *_args: Any,
        **_kwargs: Any,
    ) -> SimpleNamespace:
        self.statements.append(sql)
        if self.on_execute is not None:
            self.on_execute(sql)
        if sql in self.failures:
            raise self.failures[sql]
        rows: dict[str, list[dict[str, Any]]] = {
            "SELECT @@version_comment;": [
                {"@@version_comment": ("Doris version doris-4.0.5-rc01-59de8c4c524")}
            ],
            "SELECT 1 AS capability_probe": [{"capability_probe": 1}],
            "SHOW FRONTENDS": [
                {
                    "Name": "fe-1",
                    "Role": "FOLLOWER",
                    "IsMaster": "true",
                    "Version": "doris-4.0.5-rc01-59de8c4c524",
                },
                {
                    "Name": "fe-2",
                    "Role": "FOLLOWER",
                    "IsMaster": "false",
                    "Version": "doris-4.0.5-rc01-59de8c4c524",
                },
            ],
            "SHOW BACKENDS": [
                {
                    "BackendId": "1",
                    "Version": "doris-4.0.5-rc01-59de8c4c524",
                },
                {
                    "BackendId": "2",
                    "Version": "doris-4.0.5-rc01-59de8c4c524",
                },
            ],
            "EXPLAIN SELECT 1": [{"Explain String": "PLAN"}],
            "SHOW CATALOGS": [{"CatalogId": 0, "CatalogName": "internal"}],
            "SHOW DATABASES": [{"Database": "information_schema"}],
            (
                "SELECT 1 AS table_metadata_probe "
                "FROM information_schema.tables LIMIT 1"
            ): [{"table_metadata_probe": 1}],
            ("SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns LIMIT 1"): [
                {"COLUMN_NAME": "id", "DATA_TYPE": "bigint"}
            ],
            (
                "SELECT PARTITION_NAME, TABLE_ROWS, DATA_LENGTH "
                "FROM information_schema.partitions LIMIT 1"
            ): [
                {
                    "PARTITION_NAME": "p1",
                    "TABLE_ROWS": 1,
                    "DATA_LENGTH": 8,
                }
            ],
        }
        return SimpleNamespace(data=self.row_overrides.get(sql, rows.get(sql, [])))


class _ProbeConnectionManager:
    def __init__(self, connection: _ProbeConnection) -> None:
        self.connection = connection
        database_config = SimpleNamespace()
        self.config = SimpleNamespace(
            adbc=SimpleNamespace(enabled=False),
            database=database_config,
        )
        self.selected_database_config = database_config
        self.route = DorisRouteIdentity(
            route_key="global",
            generation=1,
            endpoint_fingerprint="endpoint-a",
            fingerprint="route-a",
        )
        self.context_error: Exception | None = None

    def get_route_identity(self, _auth_context: Any) -> DorisRouteIdentity:
        return self.route

    def get_database_config_for_auth_context(
        self,
        _auth_context: Any,
    ) -> Any:
        return self.selected_database_config

    @asynccontextmanager
    async def get_connection_context_for_auth_context(
        self,
        _session_id: str,
        _auth_context: Any,
    ):
        if self.context_error is not None:
            raise self.context_error
        yield self.connection


@pytest.mark.asyncio
async def test_detector_builds_version_vector_and_extends_domains_lazily() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]

    base = await detector.detect_base(
        None,
        capability_generation=3,
        provider_generation="provider.a",
    )
    query = await detector.detect_domain(base, "doris_query", None)
    catalog = await detector.detect_domain(base, "doris_catalog", None)

    assert base.route.fingerprint == "route-a"
    assert base.capability_generation == 3
    assert base.version_vector.master_fe.normalized == "4.0.5rc1"
    assert len(base.version_vector.follower_fes) == 1
    assert len(base.version_vector.backends) == 2
    assert base.mixed_versions is False
    assert (
        base.probe("version_probe_completed").status is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        base.probe("query_execution_readable").status is CapabilityProbeStatus.SUPPORTED
    )
    assert query.probed_domains == frozenset({"doris_query"})
    assert (
        query.probe("explain_output_readable").status is CapabilityProbeStatus.SUPPORTED
    )
    assert query.probe("audit_log_readable").status is CapabilityProbeStatus.SUPPORTED
    assert (
        query.probe("profile_or_audit_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        query.probe("query_profile_api_readable").status
        is CapabilityProbeStatus.UNKNOWN
    )
    assert (
        query.probe("adbc_driver_ready").status is CapabilityProbeStatus.MISCONFIGURED
    )
    assert catalog.probed_domains == frozenset({"doris_catalog"})
    assert (
        catalog.probe("database_metadata_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        catalog.probe("table_context_sections_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        catalog.probe("table_partition_statistics_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert connection.statements.count("SELECT @@version_comment;") == 1


@pytest.mark.asyncio
async def test_detector_marks_permission_failure_unknown_not_unsupported() -> None:
    connection = _ProbeConnection()
    connection.failures["SHOW BACKENDS"] = RuntimeError(
        1142,
        "permission denied",
    )
    detector = DorisCapabilityDetector(  # type: ignore[arg-type]
        _ProbeConnectionManager(connection)
    )

    snapshot = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    evidence = snapshot.probe("backends_metadata_readable")
    assert evidence is not None
    assert evidence.status is CapabilityProbeStatus.UNKNOWN
    assert evidence.reason_code == "PROBE_PERMISSION_DENIED"
    assert snapshot.version_vector.backends == ()


@pytest.mark.asyncio
async def test_detector_marks_adbc_callable_only_after_live_probes() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    manager.config.adbc.enabled = True
    adbc_tools = SimpleNamespace(
        _import_adbc_modules=AsyncMock(return_value={"success": True}),
        _check_arrow_flight_ports=AsyncMock(
            return_value={
                "success": True,
                "be_available_count": 1,
            }
        ),
    )
    detector = DorisCapabilityDetector(
        manager,  # type: ignore[arg-type]
        adbc_query_tools=adbc_tools,
    )
    base = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    query = await detector.detect_domain(base, "doris_query", None)

    assert query.probe("adbc_driver_ready").status is CapabilityProbeStatus.SUPPORTED
    assert query.probe("flight_sql_reachable").status is CapabilityProbeStatus.SUPPORTED
    assert query.probe("flight_sql").status is CapabilityProbeStatus.SUPPORTED
    adbc_tools._import_adbc_modules.assert_awaited_once_with()
    adbc_tools._check_arrow_flight_ports.assert_awaited_once_with(
        connectivity_timeout=1.0
    )


@pytest.mark.asyncio
async def test_detector_isolates_optional_adbc_probe_timeout() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    manager.config.adbc.enabled = True
    detector = DorisCapabilityDetector(
        manager,  # type: ignore[arg-type]
        adbc_query_tools=SimpleNamespace(),
    )
    detector._probe_adbc_services = AsyncMock(  # type: ignore[method-assign]
        side_effect=TimeoutError
    )
    base = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    query = await detector.detect_domain(base, "doris_query", None)

    assert (
        query.probe("query_execution_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        query.probe("explain_output_readable").status is CapabilityProbeStatus.SUPPORTED
    )
    assert query.probe("adbc_driver_ready").status is CapabilityProbeStatus.DEGRADED
    assert (
        query.probe("adbc_driver_ready").reason_code == "ADBC_RUNTIME_PROBE_TIMED_OUT"
    )


@pytest.mark.asyncio
async def test_detector_marks_oauth_http_and_adbc_routes_unavailable() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    manager.config.adbc.enabled = True
    adbc_tools = SimpleNamespace(
        _import_adbc_modules=AsyncMock(
            side_effect=AssertionError("ADBC import probe must not run")
        ),
        _check_arrow_flight_ports=AsyncMock(
            side_effect=AssertionError("ADBC endpoint probe must not run")
        ),
    )
    detector = DorisCapabilityDetector(
        manager,  # type: ignore[arg-type]
        adbc_query_tools=adbc_tools,
    )
    auth_context = AuthContext(
        auth_method="doris_oauth",
        doris_user="analyst",
    )
    base = await detector.detect_base(
        auth_context,
        capability_generation=1,
        provider_generation="provider.a",
    )

    query = await detector.detect_domain(
        base,
        "doris_query",
        auth_context,
    )

    assert (
        query.probe("query_execution_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        query.probe("query_profile_api_readable").reason_code
        == "PROFILE_API_CREDENTIAL_ROUTE_UNAVAILABLE"
    )
    assert (
        query.probe("adbc_driver_ready").reason_code
        == "ADBC_CREDENTIAL_ROUTE_UNAVAILABLE"
    )
    adbc_tools._import_adbc_modules.assert_not_awaited()
    adbc_tools._check_arrow_flight_ports.assert_not_awaited()


@pytest.mark.asyncio
async def test_detector_marks_static_token_adbc_route_unavailable() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    manager.config.adbc.enabled = True
    manager.selected_database_config = SimpleNamespace()
    adbc_tools = SimpleNamespace(
        _import_adbc_modules=AsyncMock(
            side_effect=AssertionError("ADBC import probe must not run")
        ),
        _check_arrow_flight_ports=AsyncMock(
            side_effect=AssertionError("ADBC endpoint probe must not run")
        ),
    )
    detector = DorisCapabilityDetector(
        manager,  # type: ignore[arg-type]
        adbc_query_tools=adbc_tools,
    )
    auth_context = AuthContext(
        auth_method="token",
        token="tenant-token",
    )
    base = await detector.detect_base(
        auth_context,
        capability_generation=1,
        provider_generation="provider.a",
    )

    query = await detector.detect_domain(
        base,
        "doris_query",
        auth_context,
    )

    assert (
        query.probe("query_execution_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        query.probe("adbc_driver_ready").reason_code
        == "ADBC_CREDENTIAL_ROUTE_UNAVAILABLE"
    )
    adbc_tools._import_adbc_modules.assert_not_awaited()
    adbc_tools._check_arrow_flight_ports.assert_not_awaited()


@pytest.mark.parametrize(
    ("http_status", "payload", "expected_status", "expected_reason"),
    [
        (
            200,
            {"code": 0},
            CapabilityProbeStatus.SUPPORTED,
            "PROFILE_API_READABLE",
        ),
        (
            200,
            {"code": "403"},
            CapabilityProbeStatus.UNKNOWN,
            "PROFILE_API_PERMISSION_DENIED",
        ),
        (
            200,
            None,
            CapabilityProbeStatus.UNKNOWN,
            "PROFILE_API_INVALID_RESPONSE",
        ),
        (
            503,
            None,
            CapabilityProbeStatus.DEGRADED,
            "PROFILE_API_UNREACHABLE",
        ),
        (
            404,
            None,
            CapabilityProbeStatus.UNSUPPORTED,
            "PROFILE_API_UNSUPPORTED",
        ),
    ],
)
def test_profile_api_probe_classification_is_fail_closed(
    http_status: int,
    payload: dict[str, Any] | None,
    expected_status: CapabilityProbeStatus,
    expected_reason: str,
) -> None:
    status, reason = _classify_profile_api_response(
        http_status,
        payload,
    )

    assert status is expected_status
    assert reason == expected_reason


@pytest.mark.asyncio
async def test_detector_retains_visible_backend_with_unknown_version() -> None:
    connection = _ProbeConnection()
    connection.row_overrides["SHOW BACKENDS"] = [
        {
            "BackendId": "1",
            "Version": "doris-4.0.5-rc01-59de8c4c524",
        },
        {
            "BackendId": "2",
            "Version": "",
        },
    ]
    detector = DorisCapabilityDetector(  # type: ignore[arg-type]
        _ProbeConnectionManager(connection)
    )

    snapshot = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )
    evaluation = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="get_cache_status",
        versions=snapshot.version_vector,
    )

    assert len(snapshot.version_vector.backends) == 2
    assert snapshot.version_vector.backends[0].is_parsed is True
    assert snapshot.version_vector.backends[1].is_parsed is False
    assert evaluation.compatible is False
    assert evaluation.reason_code == "DORIS_VERSION_UNKNOWN"


@pytest.mark.asyncio
async def test_detector_ignores_explicitly_dead_backend_for_version_gating() -> None:
    connection = _ProbeConnection()
    connection.row_overrides["SHOW BACKENDS"] = [
        {
            "BackendId": "1",
            "Alive": "true",
            "Version": "doris-4.0.5-rc01-59de8c4c524",
        },
        {
            "BackendId": "2",
            "Alive": "false",
            "Version": "",
        },
    ]
    detector = DorisCapabilityDetector(  # type: ignore[arg-type]
        _ProbeConnectionManager(connection)
    )

    snapshot = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )
    evaluation = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_cluster",
        child_name="list_cluster_nodes",
        versions=snapshot.version_vector,
    )

    assert tuple(
        version.normalized for version in snapshot.version_vector.backends
    ) == ("4.0.5rc1",)
    assert evaluation.compatible is True


@pytest.mark.asyncio
async def test_detector_uses_fallback_for_unknown_master_and_retains_follower() -> None:
    connection = _ProbeConnection()
    connection.row_overrides["SHOW FRONTENDS"] = [
        {
            "Name": "fe-1",
            "IsMaster": "true",
            "Version": "",
        },
        {
            "Name": "fe-2",
            "IsMaster": "false",
            "Version": "",
        },
    ]
    detector = DorisCapabilityDetector(  # type: ignore[arg-type]
        _ProbeConnectionManager(connection)
    )

    snapshot = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )
    evaluation = DORIS_FEATURE_MATRIX.evaluate(
        domain="doris_governance",
        child_name="get_lineage_capability_status",
        versions=snapshot.version_vector,
        variant_name="native_lineage_status",
    )

    assert snapshot.version_vector.master_fe.normalized == "4.0.5rc1"
    assert len(snapshot.version_vector.follower_fes) == 1
    assert snapshot.version_vector.follower_fes[0].is_parsed is False
    assert evaluation.compatible is False
    assert evaluation.reason_code == "DORIS_VERSION_UNKNOWN"


@pytest.mark.asyncio
async def test_detector_rejects_route_change_before_domain_probe() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]
    base = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )
    manager.route = DorisRouteIdentity(
        route_key="global",
        generation=2,
        endpoint_fingerprint="endpoint-a",
        fingerprint="route-b",
    )

    with pytest.raises(CapabilityRouteChangedError):
        await detector.detect_domain(base, "doris_query", None)


@pytest.mark.asyncio
async def test_detector_reprobes_after_route_changes_during_base_probe() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    switched = False

    def switch_route(sql: str) -> None:
        nonlocal switched
        if sql != "SELECT @@version_comment;" or switched:
            return
        switched = True
        manager.route = DorisRouteIdentity(
            route_key="global",
            generation=2,
            endpoint_fingerprint="endpoint-b",
            fingerprint="route-b",
        )

    connection.on_execute = switch_route
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]

    snapshot = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    assert snapshot.route.fingerprint == "route-b"
    assert connection.statements.count("SELECT @@version_comment;") == 2


@pytest.mark.asyncio
async def test_detector_reprobes_after_route_changes_at_end_of_base_probe() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    switched = False

    def switch_route(sql: str) -> None:
        nonlocal switched
        if sql != "SHOW BACKENDS" or switched:
            return
        switched = True
        manager.route = DorisRouteIdentity(
            route_key="global",
            generation=2,
            endpoint_fingerprint="endpoint-b",
            fingerprint="route-b",
        )

    connection.on_execute = switch_route
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]

    snapshot = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    assert snapshot.route.fingerprint == "route-b"
    assert connection.statements.count("SELECT @@version_comment;") == 2


@pytest.mark.asyncio
async def test_detector_rejects_route_change_at_end_of_domain_probe() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]
    base = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    def switch_route(sql: str) -> None:
        if sql != "EXPLAIN SELECT 1":
            return
        manager.route = DorisRouteIdentity(
            route_key="global",
            generation=2,
            endpoint_fingerprint="endpoint-b",
            fingerprint="route-b",
        )

    connection.on_execute = switch_route

    with pytest.raises(CapabilityRouteChangedError):
        await detector.detect_domain(base, "doris_query", None)


@pytest.mark.asyncio
async def test_detector_wraps_domain_connection_failures() -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]
    base = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )
    manager.context_error = ConnectionError("connection unavailable")

    with pytest.raises(
        CapabilityDetectionError,
        match="probe failed for doris_query",
    ):
        await detector.detect_domain(base, "doris_query", None)


@pytest.mark.asyncio
async def test_cluster_probe_keeps_405_compaction_on_real_legacy_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _ProbeConnection()
    manager = _ProbeConnectionManager(connection)
    database_config = SimpleNamespace(
        user="root",
        password="secret",
        host="fe-1",
        hosts=["fe-1"],
        fe_http_host="fe-1",
        fe_http_hosts=["fe-1"],
        fe_http_port=8030,
        be_hosts=["be-1"],
        be_webserver_port=8040,
    )
    manager.config.database = database_config
    manager.selected_database_config = database_config

    native_compaction = (
        "SELECT * "
        "FROM information_schema.doris_be_compaction_tasks LIMIT 1"
    )
    connection.failures[native_compaction] = RuntimeError(
        1146,
        "table does not exist",
    )
    connection.row_overrides.update(
        {
            'SHOW PROC "/current_queries"': [],
            (
                "SELECT BE_ID, METRIC_NAME "
                "FROM information_schema.file_cache_statistics LIMIT 1"
            ): [{"BE_ID": 1, "METRIC_NAME": "hits_ratio"}],
            "SHOW WORKLOAD GROUPS": [],
            "SHOW COMPUTE GROUPS": [],
            (
                "SELECT `time` "
                "FROM internal.__internal_schema.audit_log LIMIT 1"
            ): [],
        }
    )

    class _HTTPClient:
        async def get_first_available(
            self,
            *,
            role: str,
            **_kwargs: Any,
        ) -> DorisHTTPResponse:
            metrics = (
                "doris_fe_tablet_max_compaction_score 4\n"
                if role == "fe"
                else (
                    "doris_be_memory_allocated_bytes 1024\n"
                    "doris_be_file_cache_hits_ratio 0.8\n"
                    "doris_be_tablet_base_max_compaction_score 7\n"
                )
            )
            return DorisHTTPResponse(
                status=200,
                headers={},
                body=metrics.encode(),
                url=f"http://{role}/metrics",
            )

    monkeypatch.setattr(
        "doris_mcp_server.tools.capability_detector."
        "DorisHTTPClient.from_database_config",
        lambda _config: _HTTPClient(),
    )
    detector = DorisCapabilityDetector(manager)  # type: ignore[arg-type]
    base = await detector.detect_base(
        None,
        capability_generation=1,
        provider_generation="provider.a",
    )

    snapshot = await detector.detect_domain(base, "doris_cluster", None)

    assert snapshot.version_vector.master_fe.normalized == "4.0.5rc1"
    assert (
        snapshot.probe("information_schema.doris_be_compaction_tasks").status
        is CapabilityProbeStatus.UNSUPPORTED
    )
    assert (
        snapshot.probe("compaction_system_table_or_http_api").status
        is CapabilityProbeStatus.UNSUPPORTED
    )
    legacy = snapshot.probe("legacy_compaction_status_readable")
    assert legacy is not None
    assert legacy.status is CapabilityProbeStatus.DEGRADED
    assert legacy.reason_code == "LEGACY_COMPACTION_SUMMARY_READABLE"
    assert snapshot.probe("fe_metrics").status is CapabilityProbeStatus.SUPPORTED
    assert snapshot.probe("be_metrics").status is CapabilityProbeStatus.SUPPORTED
    assert (
        snapshot.probe("file_cache_metrics_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )

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

import pytest

from doris_mcp_server.tools.capability_detector import (
    CapabilityDetectionError,
    CapabilityProbeStatus,
    CapabilityRouteChangedError,
    DorisCapabilityDetector,
)
from doris_mcp_server.tools.doris_feature_matrix import DORIS_FEATURE_MATRIX
from doris_mcp_server.utils.db import DorisRouteIdentity


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
                {
                    "@@version_comment": (
                        "Doris version "
                        "doris-4.0.5-rc01-59de8c4c524"
                    )
                }
            ],
            "SELECT 1 AS capability_probe": [
                {"capability_probe": 1}
            ],
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
            ): [
                {"table_metadata_probe": 1}
            ],
            (
                "SELECT COLUMN_NAME, DATA_TYPE "
                "FROM information_schema.columns LIMIT 1"
            ): [
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
        return SimpleNamespace(
            data=self.row_overrides.get(sql, rows.get(sql, []))
        )


class _ProbeConnectionManager:
    def __init__(self, connection: _ProbeConnection) -> None:
        self.connection = connection
        self.route = DorisRouteIdentity(
            route_key="global",
            generation=1,
            endpoint_fingerprint="endpoint-a",
            fingerprint="route-a",
        )
        self.context_error: Exception | None = None

    def get_route_identity(self, _auth_context: Any) -> DorisRouteIdentity:
        return self.route

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
        base.probe("version_probe_completed").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert (
        base.probe("query_execution_readable").status
        is CapabilityProbeStatus.SUPPORTED
    )
    assert query.probed_domains == frozenset({"doris_query"})
    assert (
        query.probe("explain_output_readable").status
        is CapabilityProbeStatus.SUPPORTED
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

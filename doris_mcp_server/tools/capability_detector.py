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
"""Route-aware, read-only Doris capability probes."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from ..utils.db import DorisConnection, DorisConnectionManager, DorisRouteIdentity
from .doris_feature_matrix import DorisClusterVersionVector
from .doris_version import (
    DorisVersion,
    parse_doris_version_comment,
    probe_doris_version,
)


class CapabilityProbeStatus(StrEnum):
    """Normalized result of one private runtime capability probe."""

    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"
    MISCONFIGURED = "misconfigured"


@dataclass(frozen=True, slots=True)
class CapabilityProbeEvidence:
    """Bounded, secret-free evidence for one capability predicate."""

    probe_id: str
    status: CapabilityProbeStatus
    reason_code: str
    evidence_sources: tuple[str, ...] = ("runtime_probe",)


@dataclass(frozen=True, slots=True)
class DorisCapabilitySnapshot:
    """Private capability facts for one route and optional domain."""

    route: DorisRouteIdentity
    capability_generation: int
    provider_generation: str
    cluster_fingerprint: str
    version_vector: DorisClusterVersionVector
    deployment_mode: str
    mixed_versions: bool
    probes: Mapping[str, CapabilityProbeEvidence]
    probed_domains: frozenset[str]
    created_at: datetime
    expires_at: datetime
    stale_until: datetime
    stale: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "probes",
            MappingProxyType(dict(self.probes)),
        )

    def probe(self, probe_id: str) -> CapabilityProbeEvidence | None:
        return self.probes.get(probe_id)

    @property
    def generation_fingerprint(self) -> str:
        """Return a stable private generation for Manifest invalidation."""
        payload = {
            "route": self.route.fingerprint,
            "capability_generation": self.capability_generation,
            "provider_generation": self.provider_generation,
            "cluster": self.cluster_fingerprint,
            "deployment_mode": self.deployment_mode,
            "mixed_versions": self.mixed_versions,
            "probed_domains": sorted(self.probed_domains),
            "probes": {
                probe_id: {
                    "status": evidence.status.value,
                    "reason_code": evidence.reason_code,
                }
                for probe_id, evidence in sorted(self.probes.items())
            },
            "stale": self.stale,
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        return "cap." + hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()[:16]

    def as_stale(
        self,
        *,
        retry_at: datetime | None = None,
    ) -> DorisCapabilitySnapshot:
        expires_at = self.expires_at
        if retry_at is not None:
            expires_at = min(retry_at, self.stale_until)
        return replace(
            self,
            expires_at=expires_at,
            stale=True,
        )


class CapabilityDetectionError(RuntimeError):
    """Raised when no safe base capability snapshot can be established."""


class CapabilityRouteChangedError(CapabilityDetectionError):
    """Raised when a route changes while a domain snapshot is extended."""


_DOMAIN_PROBES: Mapping[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "doris_catalog": (
        ("SHOW CATALOGS", ("catalog_metadata_readable",)),
        ("SHOW DATABASES", ("database_metadata_readable",)),
        (
            (
                "SELECT 1 AS table_metadata_probe "
                "FROM information_schema.tables LIMIT 1"
            ),
            ("table_metadata_readable",),
        ),
        (
            (
                "SELECT COLUMN_NAME, DATA_TYPE "
                "FROM information_schema.columns LIMIT 1"
            ),
            (
                "information_schema.columns",
                "table_context_sections_readable",
            ),
        ),
        (
            (
                "SELECT PARTITION_NAME, TABLE_ROWS, DATA_LENGTH "
                "FROM information_schema.partitions LIMIT 1"
            ),
            ("table_partition_statistics_readable",),
        ),
    ),
    "doris_query": (
        (
            "EXPLAIN SELECT 1",
            ("explain_output_readable", "explain_readable"),
        ),
    ),
}


class DorisCapabilityDetector:
    """Build L1 snapshots and add low-cost domain probes lazily."""

    def __init__(
        self,
        connection_manager: DorisConnectionManager,
        *,
        probe_timeout_seconds: float = 5.0,
        snapshot_ttl_seconds: int = 300,
        stale_grace_seconds: int = 900,
        clock: Any | None = None,
    ) -> None:
        self._connection_manager = connection_manager
        self._probe_timeout_seconds = probe_timeout_seconds
        self._snapshot_ttl_seconds = snapshot_ttl_seconds
        self._stale_grace_seconds = stale_grace_seconds
        self._clock = clock or (lambda: datetime.now(UTC))

    def route_identity(self, auth_context: Any | None) -> DorisRouteIdentity:
        route = self._connection_manager.get_route_identity(auth_context)
        if not isinstance(route, DorisRouteIdentity):
            raise CapabilityDetectionError(
                "Doris route identity is unavailable"
            )
        return route

    async def detect_base(
        self,
        auth_context: Any | None,
        *,
        capability_generation: int,
        provider_generation: str,
    ) -> DorisCapabilitySnapshot:
        try:
            async with asyncio.timeout(self._probe_timeout_seconds):
                for _ in range(2):
                    requested_route = self.route_identity(auth_context)
                    session_id = (
                        "capability-base:"
                        f"{requested_route.fingerprint[:16]}"
                    )
                    async with (
                        self._connection_manager
                        .get_connection_context_for_auth_context(
                            session_id,
                            auth_context,
                        ) as connection
                    ):
                        snapshot = await self._detect_base_on_connection(
                            connection,
                            auth_context,
                            capability_generation=capability_generation,
                            provider_generation=provider_generation,
                        )
                    completed_route = self.route_identity(auth_context)
                    if (
                        snapshot.route.fingerprint
                        == requested_route.fingerprint
                        == completed_route.fingerprint
                    ):
                        return snapshot
                raise CapabilityRouteChangedError(
                    "Doris route changed during base capability probing"
                )
        except TimeoutError as exc:
            raise CapabilityDetectionError(
                "Doris capability base probe timed out"
            ) from exc
        except CapabilityDetectionError:
            raise
        except Exception as exc:
            raise CapabilityDetectionError(
                "Doris capability base probe failed"
            ) from exc

    async def detect_domain(
        self,
        base: DorisCapabilitySnapshot,
        domain_name: str,
        auth_context: Any | None,
    ) -> DorisCapabilitySnapshot:
        if domain_name in base.probed_domains:
            return base

        try:
            requested_route = self.route_identity(auth_context)
            if requested_route.fingerprint != base.route.fingerprint:
                raise CapabilityRouteChangedError(
                    "Doris route changed before domain capability probing"
                )

            session_id = (
                f"capability-domain:{domain_name}:"
                f"{requested_route.fingerprint[:12]}"
            )
            async with asyncio.timeout(self._probe_timeout_seconds):
                async with (
                    self._connection_manager
                    .get_connection_context_for_auth_context(
                        session_id,
                        auth_context,
                    ) as connection
                ):
                    current_route = self.route_identity(auth_context)
                    if current_route.fingerprint != base.route.fingerprint:
                        raise CapabilityRouteChangedError(
                            "Doris route changed during domain capability probing"
                        )
                    probes = dict(base.probes)
                    for sql, probe_ids in _DOMAIN_PROBES.get(
                        domain_name,
                        (),
                    ):
                        evidence = await self._probe_statement(
                            connection,
                            sql,
                            probe_ids,
                        )
                        probes.update(evidence)
                    completed_route = self.route_identity(auth_context)
                    if completed_route.fingerprint != base.route.fingerprint:
                        raise CapabilityRouteChangedError(
                            "Doris route changed during domain capability probing"
                        )
                    return replace(
                        base,
                        probes=probes,
                        probed_domains=(
                            base.probed_domains | frozenset({domain_name})
                        ),
                    )
        except TimeoutError as exc:
            raise CapabilityDetectionError(
                f"Doris capability probe timed out for {domain_name}"
            ) from exc
        except CapabilityDetectionError:
            raise
        except Exception as exc:
            raise CapabilityDetectionError(
                f"Doris capability probe failed for {domain_name}"
            ) from exc

    async def _detect_base_on_connection(
        self,
        connection: DorisConnection,
        auth_context: Any | None,
        *,
        capability_generation: int,
        provider_generation: str,
    ) -> DorisCapabilitySnapshot:
        version = await probe_doris_version(connection)
        route = self.route_identity(auth_context)
        now = self._clock()
        probes: dict[str, CapabilityProbeEvidence] = {}
        probes["version_probe_completed"] = CapabilityProbeEvidence(
            probe_id="version_probe_completed",
            status=(
                CapabilityProbeStatus.SUPPORTED
                if version.is_parsed
                else CapabilityProbeStatus.UNKNOWN
            ),
            reason_code=(
                "VERSION_PROBE_PARSED"
                if version.is_parsed
                else "DORIS_VERSION_UNKNOWN"
            ),
            evidence_sources=("version_probe",),
        )
        probes["read_only_sql_guard_ready"] = CapabilityProbeEvidence(
            probe_id="read_only_sql_guard_ready",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="READ_ONLY_GUARD_ENABLED",
            evidence_sources=("server_policy",),
        )
        probes.update(
            await self._probe_statement(
                connection,
                "SELECT 1 AS capability_probe",
                ("query_execution_readable",),
            )
        )

        frontend_rows, frontend_probe = await self._probe_rows(
            connection,
            "SHOW FRONTENDS",
            "frontends_metadata_readable",
        )
        backend_rows, backend_probe = await self._probe_rows(
            connection,
            "SHOW BACKENDS",
            "backends_metadata_readable",
        )
        probes[frontend_probe.probe_id] = frontend_probe
        probes[backend_probe.probe_id] = backend_probe

        master_fe, follower_fes = _frontend_versions(
            frontend_rows,
            fallback=version,
        )
        backends = _backend_versions(backend_rows)
        versions = DorisClusterVersionVector(
            master_fe=master_fe,
            follower_fes=follower_fes,
            backends=backends,
        )
        nodes_ready = bool(frontend_rows and backend_rows)
        node_status = (
            CapabilityProbeStatus.SUPPORTED
            if nodes_ready
            else CapabilityProbeStatus.UNKNOWN
        )
        node_reason = (
            "FE_BE_VERSIONS_OBSERVED"
            if nodes_ready
            else "FE_BE_VERSIONS_INCOMPLETE"
        )
        for probe_id in (
            "cluster_components_discoverable",
            "fe_be_node_metadata_readable",
        ):
            probes[probe_id] = CapabilityProbeEvidence(
                probe_id=probe_id,
                status=node_status,
                reason_code=node_reason,
                evidence_sources=(
                    "show_frontends",
                    "show_backends",
                ),
            )

        observed = (
            versions.master_fe,
            *versions.follower_fes,
            *versions.backends,
        )
        normalized = {
            candidate.normalized
            for candidate in observed
            if candidate.normalized is not None
        }
        mixed_versions = len(normalized) > 1
        cluster_fingerprint = _cluster_fingerprint(
            route,
            frontend_rows,
            backend_rows,
        )
        deployment_mode = version.deployment_hint or "unknown"
        return DorisCapabilitySnapshot(
            route=route,
            capability_generation=capability_generation,
            provider_generation=provider_generation,
            cluster_fingerprint=cluster_fingerprint,
            version_vector=versions,
            deployment_mode=deployment_mode,
            mixed_versions=mixed_versions,
            probes=probes,
            probed_domains=frozenset(),
            created_at=now,
            expires_at=now + timedelta(seconds=self._snapshot_ttl_seconds),
            stale_until=now
            + timedelta(
                seconds=(
                    self._snapshot_ttl_seconds
                    + self._stale_grace_seconds
                )
            ),
        )

    async def _probe_statement(
        self,
        connection: DorisConnection,
        sql: str,
        probe_ids: tuple[str, ...],
    ) -> dict[str, CapabilityProbeEvidence]:
        try:
            await connection.execute(
                sql,
                mask_result=False,
                max_rows=64,
                max_bytes=64 * 1024,
            )
        except Exception as exc:
            status, reason = _classify_probe_error(exc)
        else:
            status = CapabilityProbeStatus.SUPPORTED
            reason = "RUNTIME_PROBE_SUCCEEDED"
        return {
            probe_id: CapabilityProbeEvidence(
                probe_id=probe_id,
                status=status,
                reason_code=reason,
            )
            for probe_id in probe_ids
        }

    async def _probe_rows(
        self,
        connection: DorisConnection,
        sql: str,
        probe_id: str,
    ) -> tuple[tuple[Mapping[str, Any], ...], CapabilityProbeEvidence]:
        try:
            result = await connection.execute(
                sql,
                mask_result=False,
                max_rows=512,
                max_bytes=512 * 1024,
            )
            rows = tuple(
                row
                for row in (result.data or ())
                if isinstance(row, Mapping)
            )
        except Exception as exc:
            status, reason = _classify_probe_error(exc)
            rows = ()
        else:
            status = CapabilityProbeStatus.SUPPORTED
            reason = "RUNTIME_PROBE_SUCCEEDED"
        return rows, CapabilityProbeEvidence(
            probe_id=probe_id,
            status=status,
            reason_code=reason,
        )


def _classify_probe_error(
    error: Exception,
) -> tuple[CapabilityProbeStatus, str]:
    error_code = next(
        (
            value
            for value in getattr(error, "args", ())
            if isinstance(value, int)
        ),
        None,
    )
    if error_code in {1044, 1045, 1142, 1227}:
        return (
            CapabilityProbeStatus.UNKNOWN,
            "PROBE_PERMISSION_DENIED",
        )
    if error_code in {1064, 1109, 1146}:
        return (
            CapabilityProbeStatus.UNSUPPORTED,
            "PROBE_OBJECT_OR_SYNTAX_UNSUPPORTED",
        )
    if isinstance(error, ConnectionError | TimeoutError):
        return (
            CapabilityProbeStatus.DEGRADED,
            "PROBE_CONNECTION_FAILED",
        )
    return CapabilityProbeStatus.UNKNOWN, "RUNTIME_PROBE_FAILED"


def _row_value(
    row: Mapping[str, Any],
    *names: str,
) -> Any | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _component_version(value: Any) -> DorisVersion:
    raw = "" if value is None else str(value).strip()
    if not raw:
        return parse_doris_version_comment("")
    if "doris" not in raw.lower():
        raw = f"Doris version doris-{raw}"
    return parse_doris_version_comment(raw)


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes"}


def _frontend_versions(
    rows: Sequence[Mapping[str, Any]],
    *,
    fallback: DorisVersion,
) -> tuple[DorisVersion, tuple[DorisVersion, ...]]:
    observed: list[tuple[DorisVersion, bool]] = []
    for row in rows:
        version = _component_version(
            _row_value(row, "Version", "FeVersion")
        )
        observed.append(
            (
                version,
                _truthy(_row_value(row, "IsMaster", "Master")),
            )
        )
    master_index = next(
        (
            index
            for index, (_, is_master) in enumerate(observed)
            if is_master
        ),
        None,
    )
    if master_index is None:
        return fallback, tuple(version for version, _ in observed)

    master = observed[master_index][0]
    if not master.raw:
        master = fallback
    followers = tuple(
        version
        for index, (version, _) in enumerate(observed)
        if index != master_index
    )
    return master, followers


def _backend_versions(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[DorisVersion, ...]:
    return tuple(
        _component_version(_row_value(row, "Version", "BeVersion"))
        for row in rows
    )


def _cluster_fingerprint(
    route: DorisRouteIdentity,
    frontend_rows: Sequence[Mapping[str, Any]],
    backend_rows: Sequence[Mapping[str, Any]],
) -> str:
    def node_values(
        rows: Sequence[Mapping[str, Any]],
        identifiers: tuple[str, ...],
    ) -> list[str]:
        values: list[str] = []
        for row in rows:
            values.append(
                "\x1f".join(
                    str(_row_value(row, identifier) or "")
                    for identifier in identifiers
                )
            )
        return sorted(values)

    payload = {
        "endpoint": route.endpoint_fingerprint,
        "frontends": node_values(
            frontend_rows,
            ("Name", "Host", "Role", "IsMaster", "Version"),
        ),
        "backends": node_values(
            backend_rows,
            ("BackendId", "Host", "Version"),
        ),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


__all__ = [
    "CapabilityDetectionError",
    "CapabilityProbeEvidence",
    "CapabilityProbeStatus",
    "CapabilityRouteChangedError",
    "DorisCapabilityDetector",
    "DorisCapabilitySnapshot",
]

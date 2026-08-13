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
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import Any
from urllib.parse import quote

from ..utils.adbc_query_tools import DorisADBCQueryTools
from ..utils.db import DorisConnection, DorisConnectionManager, DorisRouteIdentity
from ..utils.doris_http_client import (
    DorisHTTPClient,
    DorisHTTPPolicyError,
    DorisHTTPRequestError,
    DorisHTTPResponse,
    configured_fe_http_hosts,
    database_config_for_request,
)
from ..utils.sql_security_utils import (
    SQLSecurityError,
    quote_identifier,
    validate_identifier,
)
from .doris_feature_matrix import DorisClusterVersionVector
from .doris_version import (
    DorisVersion,
    parse_doris_version_comment,
    probe_doris_version,
)

_NATIVE_LINEAGE_MINIMUM = parse_doris_version_comment(
    "Doris version doris-4.0.6"
)
_ADBC_RECOMMENDED_MINIMUM = parse_doris_version_comment(
    "Doris version doris-2.1.5"
)
_LINEAGE_STORE_REQUIRED_COLUMNS = frozenset(
    {
        "event_id",
        "event_time",
        "source_object",
        "target_object",
    }
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
        return "cap." + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

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
            ("SELECT 1 AS table_metadata_probe FROM information_schema.tables LIMIT 1"),
            ("table_metadata_readable",),
        ),
        (
            ("SELECT COLUMN_NAME, DATA_TYPE FROM information_schema.columns LIMIT 1"),
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
        (
            ("SELECT `query_id` FROM internal.__internal_schema.audit_log LIMIT 1"),
            ("audit_log_readable",),
        ),
    ),
    "doris_cluster": (
        (
            'SHOW PROC "/current_queries"',
            (
                "current_queries_proc_readable",
                "unified_task_progress_readable",
            ),
        ),
        (
            (
                "SELECT 1 AS active_query_probe "
                "FROM information_schema.active_queries LIMIT 1"
            ),
            ("active_queries_view_readable",),
        ),
        (
            "SHOW FULL PROCESSLIST",
            ("processlist_readable",),
        ),
        (
            (
                "SELECT BE_ID, METRIC_NAME "
                "FROM information_schema.file_cache_statistics LIMIT 1"
            ),
            (
                "information_schema.file_cache_statistics",
                "file_cache_metrics_readable",
            ),
        ),
        (
            ("SELECT * FROM information_schema.doris_be_compaction_tasks LIMIT 1"),
            (
                "information_schema.doris_be_compaction_tasks",
                "compaction_system_table_or_http_api",
            ),
        ),
        (
            "SHOW WORKLOAD GROUPS",
            ("workload_group_metadata_and_metrics_readable",),
        ),
        (
            "SHOW COMPUTE GROUPS",
            ("compute_group_metadata_readable",),
        ),
    ),
    "doris_pipeline": (
        (
            "SHOW LOAD LIMIT 1",
            ("batch_load_metadata_readable",),
        ),
        (
            "SHOW STREAM LOAD LIMIT 1",
            ("stream_load_metadata_readable",),
        ),
        (
            "SHOW ALL ROUTINE LOAD",
            ("routine_load_metadata_readable",),
        ),
        (
            'SELECT Id, Name, Status FROM jobs("type"="insert") LIMIT 1',
            (
                "insert_job_metadata_readable",
                "continuous_load_metadata_readable",
            ),
        ),
        (
            'SELECT Id, Name, Status FROM jobs("type"="mv") LIMIT 1',
            ("materialized_view_job_metadata_readable",),
        ),
        (
            'SELECT TaskId, Status FROM tasks("type"="mv") LIMIT 1',
            ("materialized_view_task_metadata_readable",),
        ),
        (
            (
                "SELECT `time`, stmt "
                "FROM internal.__internal_schema.audit_log LIMIT 1"
            ),
            (
                "pipeline_audit_log_readable",
                "audit_log_readable",
            ),
        ),
    ),
    "doris_search": (
        (
            "SHOW INDEX FROM information_schema.tables",
            (
                "inverted_index_metadata_readable",
                "ann_index_metadata_readable",
                "search_index_metadata_readable",
            ),
        ),
        (
            (
                "SELECT TOKENIZE('Doris search', "
                "'\"parser\"=\"english\"') AS tokens"
            ),
            ("tokenize_function_or_analyzer_ready",),
        ),
        (
            (
                "SELECT l2_distance_approximate([0.0], [0.0]) "
                "AS distance"
            ),
            ("ann_distance_function_readable",),
        ),
        (
            "EXPLAIN SELECT 1",
            ("search_explain_readable",),
        ),
    ),
    "doris_governance": (
        (
            (
                "SELECT COLUMN_NAME, DATA_TYPE "
                "FROM information_schema.columns LIMIT 1"
            ),
            ("column_statistics_and_safe_sampling_ready",),
        ),
        (
            (
                "SELECT TABLE_NAME, DATA_LENGTH "
                "FROM information_schema.tables LIMIT 1"
            ),
            ("table_storage_metadata_readable",),
        ),
        (
            (
                "SELECT `time`, `query_id`, `stmt` "
                "FROM internal.__internal_schema.audit_log LIMIT 1"
            ),
            (
                "audit_log_readable",
                "audit_history_readable",
                "audit_lineage_provider_status_readable",
                "enhanced_audit_fields_present",
            ),
        ),
        (
            "SHOW GLOBAL FULL FUNCTIONS",
            (
                "udf_metadata_readable",
                "python_udf_metadata_readable",
            ),
        ),
        (
            "SHOW FRONTEND CONFIG LIKE 'ldap_authentication_enabled'",
            ("ldap_mapping_status_readable",),
        ),
        (
            "SELECT * FROM information_schema.role_mappings LIMIT 1",
            ("oidc_and_role_mapping_status_readable",),
        ),
        (
            "SHOW FRONTEND CONFIG LIKE 'activate_lineage_plugin'",
            ("lineage_plugin_config_readable",),
        ),
    ),
    "doris_lakehouse": (
        (
            "SHOW CATALOGS",
            ("external_catalog_metadata_readable",),
        ),
        (
            (
                "SELECT TABLE_CATALOG, TABLE_SCHEMA, TABLE_NAME "
                "FROM information_schema.tables LIMIT 1"
            ),
            ("lakehouse_table_metadata_readable",),
        ),
        (
            (
                "SELECT COLUMN_NAME, DATA_TYPE "
                "FROM information_schema.columns LIMIT 1"
            ),
            ("variant_column_type_readable",),
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
        adbc_query_tools: DorisADBCQueryTools | None = None,
        clock: Any | None = None,
    ) -> None:
        self._connection_manager = connection_manager
        self._probe_timeout_seconds = probe_timeout_seconds
        self._snapshot_ttl_seconds = snapshot_ttl_seconds
        self._stale_grace_seconds = stale_grace_seconds
        self._adbc_query_tools = adbc_query_tools
        self._clock = clock or (lambda: datetime.now(UTC))

    def route_identity(self, auth_context: Any | None) -> DorisRouteIdentity:
        route = self._connection_manager.get_route_identity(auth_context)
        if not isinstance(route, DorisRouteIdentity):
            raise CapabilityDetectionError("Doris route identity is unavailable")
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
                    session_id = f"capability-base:{requested_route.fingerprint[:16]}"
                    async with (
                        self._connection_manager.get_connection_context_for_auth_context(
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

            async with asyncio.timeout(self._probe_timeout_seconds):
                probes = dict(base.probes)
                for index, (sql, probe_ids) in enumerate(
                    _DOMAIN_PROBES.get(domain_name, ())
                ):
                    current_route = self.route_identity(auth_context)
                    if current_route.fingerprint != base.route.fingerprint:
                        raise CapabilityRouteChangedError(
                            "Doris route changed during domain capability probing"
                        )
                    session_id = (
                        f"capability-domain:{domain_name}:{index}:"
                        f"{requested_route.fingerprint[:12]}"
                    )
                    async with (
                        self._connection_manager
                        .get_connection_context_for_auth_context(
                            session_id,
                            auth_context,
                        ) as connection
                    ):
                        evidence = await self._probe_statement(
                            connection,
                            sql,
                            probe_ids,
                        )
                    probes.update(evidence)
                if domain_name == "doris_query":
                    probes.update(await self._probe_query_services(auth_context))
                    probes["adbc_release_maturity"] = _adbc_release_maturity_probe(
                        base.version_vector.master_fe
                    )
                    probes["profile_or_audit_readable"] = _combine_query_evidence_probe(
                        probes
                    )
                elif domain_name == "doris_cluster":
                    probes.update(
                        await self._probe_cluster_history_sources(auth_context)
                    )
                    probes.update(await self._safe_probe_cluster_services(auth_context))
                    probes.update(_combine_cluster_evidence_probes(probes))
                elif domain_name == "doris_pipeline":
                    probes.update(_combine_pipeline_evidence_probes(probes))
                elif domain_name == "doris_search":
                    match_probe = await self._probe_search_match_syntax(
                        auth_context
                    )
                    probes[match_probe.probe_id] = match_probe
                    probes.update(_combine_search_evidence_probes(probes))
                elif domain_name == "doris_governance":
                    plugin_probe = await self._probe_lineage_plugin_status(
                        auth_context,
                        base.version_vector,
                    )
                    probes[plugin_probe.probe_id] = plugin_probe
                    store_probe = await self._probe_lineage_store(auth_context)
                    probes[store_probe.probe_id] = store_probe
                    probes.update(
                        _combine_governance_evidence_probes(probes)
                    )
                elif domain_name == "doris_lakehouse":
                    probes.update(
                        _combine_lakehouse_evidence_probes(probes)
                    )
                elif domain_name == "doris_semantic":
                    probes.update(_semantic_adapter_evidence_probes())
                completed_route = self.route_identity(auth_context)
                if completed_route.fingerprint != base.route.fingerprint:
                    raise CapabilityRouteChangedError(
                        "Doris route changed during domain capability probing"
                    )
                return replace(
                    base,
                    probes=probes,
                    probed_domains=(base.probed_domains | frozenset({domain_name})),
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
                "VERSION_PROBE_PARSED" if version.is_parsed else "DORIS_VERSION_UNKNOWN"
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
            "FE_BE_VERSIONS_OBSERVED" if nodes_ready else "FE_BE_VERSIONS_INCOMPLETE"
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
                seconds=(self._snapshot_ttl_seconds + self._stale_grace_seconds)
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
            rows = tuple(row for row in (result.data or ()) if isinstance(row, Mapping))
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

    async def _probe_query_services(
        self,
        auth_context: Any | None,
    ) -> dict[str, CapabilityProbeEvidence]:
        profile, probes = await asyncio.gather(
            self._safe_probe_profile_api(auth_context),
            self._safe_probe_adbc_services(auth_context),
        )
        probes["query_profile_api_readable"] = profile
        probes["fe_profile_api"] = CapabilityProbeEvidence(
            probe_id="fe_profile_api",
            status=profile.status,
            reason_code=profile.reason_code,
            evidence_sources=profile.evidence_sources,
        )
        return probes

    async def _probe_cluster_history_sources(
        self,
        auth_context: Any | None,
    ) -> dict[str, CapabilityProbeEvidence]:
        """Require recorded history, not merely readable metadata objects."""
        contracts = (
            (
                "metrics_history_readable",
                "SELECT COUNT(DISTINCT DATE(`time`)) AS evidence_bucket_count "
                "FROM internal.__internal_schema.audit_log "
                "WHERE `time` >= DATE_SUB(NOW(), INTERVAL 3650 DAY)",
                "AUDIT_HISTORY_RECORDED",
                "AUDIT_HISTORY_INSUFFICIENT",
            ),
            (
                "resource_storage_history_readable",
                "SELECT COUNT(DISTINCT DATE(CREATE_TIME)) "
                "AS evidence_bucket_count "
                "FROM information_schema.partitions "
                "WHERE CREATE_TIME >= DATE_SUB(NOW(), INTERVAL 3650 DAY)",
                "PARTITION_CREATION_HISTORY_RECORDED",
                "PARTITION_CREATION_HISTORY_INSUFFICIENT",
            ),
        )
        evidence: dict[str, CapabilityProbeEvidence] = {}
        route = self.route_identity(auth_context)
        for index, (
            probe_id,
            statement,
            supported_reason,
            insufficient_reason,
        ) in enumerate(contracts):
            session_id = (
                f"capability-cluster:history:{index}:"
                f"{route.fingerprint[:12]}"
            )
            async with (
                self._connection_manager.get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                rows, probe = await self._probe_rows(
                    connection,
                    statement,
                    probe_id,
                )
            if probe.status is CapabilityProbeStatus.SUPPORTED:
                bucket_count = _nonnegative_int(
                    _row_value(rows[0], "evidence_bucket_count")
                    if rows
                    else None
                )
                probe = CapabilityProbeEvidence(
                    probe_id=probe_id,
                    status=(
                        CapabilityProbeStatus.SUPPORTED
                        if bucket_count >= 2
                        else CapabilityProbeStatus.UNKNOWN
                    ),
                    reason_code=(
                        supported_reason
                        if bucket_count >= 2
                        else insufficient_reason
                    ),
                    evidence_sources=("recorded_history_probe",),
                )
            evidence[probe_id] = probe
        return evidence

    async def _probe_search_match_syntax(
        self,
        auth_context: Any | None,
    ) -> CapabilityProbeEvidence:
        """Probe MATCH against one visible OLAP string column without writes."""
        discovery_sql = (
            "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME "
            "FROM information_schema.columns "
            "WHERE DATA_TYPE IN ('char', 'varchar', 'string', 'text') "
            "AND TABLE_SCHEMA NOT IN ('information_schema', 'mysql') "
            "ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION LIMIT 8"
        )
        route = self.route_identity(auth_context)
        try:
            session_id = (
                "capability-search:match-target:"
                f"{route.fingerprint[:12]}"
            )
            async with (
                self._connection_manager.get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                result = await connection.execute(
                    discovery_sql,
                    mask_result=False,
                    max_rows=8,
                    max_bytes=32 * 1024,
                )
                rows = tuple(
                    row
                    for row in (result.data or ())
                    if isinstance(row, Mapping)
                )
        except Exception as exc:
            status, reason = _classify_probe_error(exc)
            return CapabilityProbeEvidence(
                probe_id="text_match_syntax_readable",
                status=status,
                reason_code=reason,
            )

        if not rows:
            return CapabilityProbeEvidence(
                probe_id="text_match_syntax_readable",
                status=CapabilityProbeStatus.DEGRADED,
                reason_code="SEARCH_MATCH_PROBE_TARGET_NOT_VISIBLE",
            )

        last_evidence: CapabilityProbeEvidence | None = None
        for offset, row in enumerate(rows):
            try:
                database = validate_identifier(
                    str(_row_value(row, "TABLE_SCHEMA")),
                    "database name",
                )
                table = validate_identifier(
                    str(_row_value(row, "TABLE_NAME")),
                    "table name",
                )
                column = validate_identifier(
                    str(_row_value(row, "COLUMN_NAME")),
                    "column name",
                )
            except SQLSecurityError:
                continue
            # SQL sink audit: all three metadata identifiers pass the strict
            # identifier validator and are quoted before _probe_statement sends
            # the read-only EXPLAIN to connection.execute.
            statement = (
                f"EXPLAIN SELECT {quote_identifier(column, 'column name')} "  # nosec B608
                f"FROM {quote_identifier(database, 'database name')}."
                f"{quote_identifier(table, 'table name')} "
                f"WHERE {quote_identifier(column, 'column name')} "
                "MATCH_ANY 'doris' LIMIT 1"
            )
            session_id = (
                f"capability-search:match:{offset}:"
                f"{route.fingerprint[:12]}"
            )
            try:
                async with (
                    self._connection_manager
                    .get_connection_context_for_auth_context(
                        session_id,
                        auth_context,
                    ) as connection
                ):
                    evidence = await self._probe_statement(
                        connection,
                        statement,
                        ("text_match_syntax_readable",),
                    )
                last_evidence = evidence["text_match_syntax_readable"]
            except Exception as exc:
                status, reason = _classify_probe_error(exc)
                last_evidence = CapabilityProbeEvidence(
                    probe_id="text_match_syntax_readable",
                    status=status,
                    reason_code=reason,
                )
            if last_evidence.status is CapabilityProbeStatus.SUPPORTED:
                return last_evidence
        return last_evidence or CapabilityProbeEvidence(
            probe_id="text_match_syntax_readable",
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="SEARCH_MATCH_PROBE_TARGET_INVALID",
        )

    async def _safe_probe_profile_api(
        self,
        auth_context: Any | None,
    ) -> CapabilityProbeEvidence:
        try:
            async with asyncio.timeout(self._optional_probe_timeout()):
                return await self._probe_profile_api(auth_context)
        except TimeoutError:
            return CapabilityProbeEvidence(
                probe_id="query_profile_api_readable",
                status=CapabilityProbeStatus.DEGRADED,
                reason_code="PROFILE_API_PROBE_TIMED_OUT",
                evidence_sources=("doris_fe_http", "runtime_probe"),
            )
        except Exception:
            return CapabilityProbeEvidence(
                probe_id="query_profile_api_readable",
                status=CapabilityProbeStatus.UNKNOWN,
                reason_code="PROFILE_API_PROBE_FAILED",
                evidence_sources=("doris_fe_http", "runtime_probe"),
            )

    async def _probe_profile_api(
        self,
        auth_context: Any | None,
    ) -> CapabilityProbeEvidence:
        if getattr(auth_context, "auth_method", "") == "doris_oauth":
            return CapabilityProbeEvidence(
                probe_id="query_profile_api_readable",
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="PROFILE_API_CREDENTIAL_ROUTE_UNAVAILABLE",
                evidence_sources=("credential_route_policy",),
            )
        trace_id = uuid.uuid4().hex
        try:
            route = self.route_identity(auth_context)
            session_id = f"capability-profile:{route.fingerprint[:16]}"
            async with (
                self._connection_manager.get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                try:
                    await connection.execute(
                        f'SET session_context="trace_id:{trace_id}"',
                        auth_context=None,
                        mask_result=False,
                        internal_session_control=True,
                    )
                    await connection.execute(
                        "SET enable_profile=true",
                        auth_context=None,
                        mask_result=False,
                        internal_session_control=True,
                    )
                    await connection.execute(
                        "SELECT 1 AS capability_probe",
                        auth_context=auth_context,
                        mask_result=False,
                        max_rows=1,
                        max_bytes=1024,
                    )
                finally:
                    connection.is_healthy = False
            config_resolver = getattr(
                self._connection_manager,
                "get_database_config_for_auth_context",
                None,
            )
            db_config = (
                config_resolver(auth_context)
                if callable(config_resolver)
                else database_config_for_request(self._connection_manager)
            )
            client = DorisHTTPClient.from_database_config(db_config)
            hosts = configured_fe_http_hosts(db_config)
            query_id = await self._resolve_profile_probe_query_id(
                client,
                hosts=hosts,
                port=db_config.fe_http_port,
                trace_id=trace_id,
            )
            if query_id is None:
                return CapabilityProbeEvidence(
                    probe_id="query_profile_api_readable",
                    status=CapabilityProbeStatus.DEGRADED,
                    reason_code="PROFILE_API_QUERY_ID_UNAVAILABLE",
                    evidence_sources=("doris_fe_http", "runtime_probe"),
                )
            response = await client.get_first_available(
                role="fe",
                hosts=hosts,
                port=db_config.fe_http_port,
                path=(
                    "/rest/v2/manager/query/profile/text/"
                    f"{quote(query_id, safe='')}"
                ),
                headers={"Accept": "application/json, text/plain"},
            )
        except DorisHTTPPolicyError:
            status = CapabilityProbeStatus.MISCONFIGURED
            reason = "PROFILE_API_ENDPOINT_MISCONFIGURED"
        except DorisHTTPRequestError:
            status = CapabilityProbeStatus.DEGRADED
            reason = "PROFILE_API_UNREACHABLE"
        except Exception:
            status = CapabilityProbeStatus.UNKNOWN
            reason = "PROFILE_API_PROBE_FAILED"
        else:
            payload: Mapping[str, Any] | None = None
            if response.status == 200:
                try:
                    parsed = json.loads(response.text())
                except json.JSONDecodeError:
                    parsed = None
                if isinstance(parsed, Mapping):
                    payload = parsed
            status, reason = _classify_profile_api_response(
                response.status,
                payload,
            )
        return CapabilityProbeEvidence(
            probe_id="query_profile_api_readable",
            status=status,
            reason_code=reason,
            evidence_sources=("doris_fe_http", "runtime_probe"),
        )

    async def _resolve_profile_probe_query_id(
        self,
        client: DorisHTTPClient,
        *,
        hosts: tuple[str, ...],
        port: int,
        trace_id: str,
    ) -> str | None:
        for delay in (0.0, 0.2, 0.5):
            if delay:
                await asyncio.sleep(delay)
            response = await client.get_first_available(
                role="fe",
                hosts=hosts,
                port=port,
                path=f"/rest/v2/manager/query/trace_id/{trace_id}",
                headers={"Accept": "application/json"},
            )
            if response.status != 200:
                continue
            try:
                payload = json.loads(response.text())
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, Mapping) or _profile_api_code(payload) != 0:
                continue
            query_id = payload.get("data")
            if isinstance(query_id, str) and query_id.strip():
                return query_id.strip()
        return None

    async def _probe_lineage_plugin_status(
        self,
        auth_context: Any | None,
        versions: DorisClusterVersionVector,
    ) -> CapabilityProbeEvidence:
        fe_versions = (versions.master_fe, *versions.follower_fes)
        if not fe_versions or any(
            not version.is_parsed for version in fe_versions
        ):
            return CapabilityProbeEvidence(
                probe_id="all_fe_lineage_plugin_compatible",
                status=CapabilityProbeStatus.UNKNOWN,
                reason_code="LINEAGE_FE_VERSION_COVERAGE_INCOMPLETE",
                evidence_sources=("show_frontends", "runtime_probe"),
            )
        if any(
            not version.is_at_least(_NATIVE_LINEAGE_MINIMUM)
            for version in fe_versions
        ):
            return CapabilityProbeEvidence(
                probe_id="all_fe_lineage_plugin_compatible",
                status=CapabilityProbeStatus.UNSUPPORTED,
                reason_code="LINEAGE_SPI_VERSION_UNSUPPORTED",
                evidence_sources=("show_frontends", "runtime_probe"),
            )
        session_id = (
            "capability-governance:lineage-plugin:"
            + (self.route_identity(auth_context).fingerprint[:12])
        )
        try:
            async with (
                self._connection_manager
                .get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                rows, probe = await self._probe_rows(
                    connection,
                    "SHOW FRONTEND CONFIG LIKE 'activate_lineage_plugin'",
                    "lineage_plugin_config_readable",
                )
        except Exception as exc:
            status, reason = _classify_probe_error(exc)
            return CapabilityProbeEvidence(
                probe_id="all_fe_lineage_plugin_compatible",
                status=status,
                reason_code=reason,
            )
        if probe.status is not CapabilityProbeStatus.SUPPORTED:
            return CapabilityProbeEvidence(
                probe_id="all_fe_lineage_plugin_compatible",
                status=probe.status,
                reason_code=probe.reason_code,
                evidence_sources=probe.evidence_sources,
            )
        active_names = tuple(
            name.strip()
            for row in rows
            for name in str(_row_value(row, "Value") or "").split(",")
            if name.strip()
        )
        if not active_names:
            return CapabilityProbeEvidence(
                probe_id="all_fe_lineage_plugin_compatible",
                status=CapabilityProbeStatus.DEGRADED,
                reason_code="LINEAGE_PLUGIN_NOT_EXPLICITLY_CONFIGURED",
                evidence_sources=(
                    "show_frontend_config",
                    "runtime_probe",
                ),
            )
        return CapabilityProbeEvidence(
            probe_id="all_fe_lineage_plugin_compatible",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="LINEAGE_SPI_AND_PLUGIN_CONFIG_OBSERVED",
            evidence_sources=(
                "show_frontends",
                "show_frontend_config",
                "runtime_probe",
            ),
        )

    async def _probe_lineage_store(
        self,
        auth_context: Any | None,
    ) -> CapabilityProbeEvidence:
        configured_store = getattr(
            getattr(
                getattr(self._connection_manager, "config", None),
                "governance",
                None,
            ),
            "lineage_store_table",
            None,
        )
        raw_table = (
            configured_store.strip()
            if isinstance(configured_store, str)
            else ""
        )
        if not raw_table:
            return CapabilityProbeEvidence(
                probe_id="lineage_store_readable",
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="LINEAGE_STORE_NOT_CONFIGURED",
                evidence_sources=("server_config",),
            )
        try:
            parts = tuple(
                validate_identifier(
                    part.strip().strip("`"),
                    "lineage store identifier",
                )
                for part in raw_table.split(".")
            )
            if len(parts) not in {2, 3}:
                raise SQLSecurityError(
                    "lineage store requires "
                    "database.table or catalog.database.table"
                )
            table = ".".join(
                quote_identifier(part, "lineage store identifier")
                for part in parts
            )
        except SQLSecurityError:
            return CapabilityProbeEvidence(
                probe_id="lineage_store_readable",
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="LINEAGE_STORE_IDENTIFIER_INVALID",
                evidence_sources=("server_config",),
            )
        session_id = (
            "capability-governance:lineage-store:"
            + (self.route_identity(auth_context).fingerprint[:12])
        )
        try:
            async with (
                self._connection_manager
                .get_connection_context_for_auth_context(
                    session_id,
                    auth_context,
                ) as connection
            ):
                # SQL sink audit: every configured lineage-store identifier was
                # strictly validated and quoted above before _probe_rows sends
                # this read-only DESC statement to connection.execute.
                rows, probe = await self._probe_rows(
                    connection,
                    f"DESC {table}",  # nosec B608
                    "lineage_store_readable",
                )
        except Exception as exc:
            status, reason = _classify_probe_error(exc)
            return CapabilityProbeEvidence(
                probe_id="lineage_store_readable",
                status=status,
                reason_code=reason,
            )
        if probe.status is not CapabilityProbeStatus.SUPPORTED:
            return probe
        observed = {
            str(_row_value(row, "Field") or "").casefold()
            for row in rows
        }
        if not _LINEAGE_STORE_REQUIRED_COLUMNS <= observed:
            return CapabilityProbeEvidence(
                probe_id="lineage_store_readable",
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="LINEAGE_STORE_SCHEMA_INVALID",
                evidence_sources=("lineage_store", "runtime_probe"),
            )
        return CapabilityProbeEvidence(
            probe_id="lineage_store_readable",
            status=CapabilityProbeStatus.SUPPORTED,
            reason_code="LINEAGE_STORE_SCHEMA_READABLE",
            evidence_sources=("lineage_store", "runtime_probe"),
        )

    async def _probe_adbc_services(
        self,
        auth_context: Any | None,
    ) -> dict[str, CapabilityProbeEvidence]:
        if getattr(auth_context, "auth_method", "") == "doris_oauth":
            return _adbc_probe_evidence(
                driver_status=CapabilityProbeStatus.MISCONFIGURED,
                driver_reason="ADBC_CREDENTIAL_ROUTE_UNAVAILABLE",
                endpoint_status=CapabilityProbeStatus.MISCONFIGURED,
                endpoint_reason="ADBC_CREDENTIAL_ROUTE_UNAVAILABLE",
            )
        global_database_config = getattr(
            getattr(self._connection_manager, "config", None),
            "database",
            None,
        )
        config_resolver = getattr(
            self._connection_manager,
            "get_database_config_for_auth_context",
            None,
        )
        if global_database_config is not None and callable(config_resolver):
            selected_database_config = config_resolver(auth_context)
            if selected_database_config is not global_database_config:
                return _adbc_probe_evidence(
                    driver_status=CapabilityProbeStatus.MISCONFIGURED,
                    driver_reason="ADBC_CREDENTIAL_ROUTE_UNAVAILABLE",
                    endpoint_status=CapabilityProbeStatus.MISCONFIGURED,
                    endpoint_reason="ADBC_CREDENTIAL_ROUTE_UNAVAILABLE",
                )
        enabled = bool(
            getattr(
                getattr(
                    getattr(self._connection_manager, "config", None),
                    "adbc",
                    None,
                ),
                "enabled",
                False,
            )
        )
        if not enabled:
            return _adbc_probe_evidence(
                driver_status=CapabilityProbeStatus.MISCONFIGURED,
                driver_reason="ADBC_PROVIDER_NOT_CONFIGURED",
                endpoint_status=CapabilityProbeStatus.MISCONFIGURED,
                endpoint_reason="ADBC_PROVIDER_NOT_CONFIGURED",
            )
        if self._adbc_query_tools is None:
            return _adbc_probe_evidence(
                driver_status=CapabilityProbeStatus.UNKNOWN,
                driver_reason="ADBC_RUNTIME_PROBE_PENDING",
                endpoint_status=CapabilityProbeStatus.UNKNOWN,
                endpoint_reason="ADBC_RUNTIME_PROBE_PENDING",
            )

        module_result = await self._adbc_query_tools._import_adbc_modules()
        port_result = await self._adbc_query_tools._check_arrow_flight_ports(
            connectivity_timeout=max(
                0.25,
                min(1.0, self._probe_timeout_seconds / 4),
            )
        )
        driver_ready = bool(module_result.get("success"))
        endpoint_ready = bool(port_result.get("success"))
        endpoint_error_type = str(port_result.get("error_type", ""))
        endpoint_status = (
            CapabilityProbeStatus.SUPPORTED
            if endpoint_ready
            else (
                CapabilityProbeStatus.MISCONFIGURED
                if endpoint_error_type
                in {
                    "missing_fe_port_config",
                    "missing_be_port_config",
                    "invalid_port_format",
                }
                else CapabilityProbeStatus.DEGRADED
            )
        )
        return _adbc_probe_evidence(
            driver_status=(
                CapabilityProbeStatus.SUPPORTED
                if driver_ready
                else CapabilityProbeStatus.MISCONFIGURED
            ),
            driver_reason=(
                "ADBC_DRIVER_READY" if driver_ready else "ADBC_DRIVER_NOT_READY"
            ),
            endpoint_status=endpoint_status,
            endpoint_reason=(
                "FLIGHT_SQL_REACHABLE"
                if endpoint_ready
                else (
                    "FLIGHT_SQL_ENDPOINT_MISCONFIGURED"
                    if endpoint_status is CapabilityProbeStatus.MISCONFIGURED
                    else "FLIGHT_SQL_UNREACHABLE"
                )
            ),
        )

    async def _safe_probe_adbc_services(
        self,
        auth_context: Any | None,
    ) -> dict[str, CapabilityProbeEvidence]:
        try:
            async with asyncio.timeout(self._optional_probe_timeout()):
                return await self._probe_adbc_services(auth_context)
        except TimeoutError:
            return _adbc_probe_evidence(
                driver_status=CapabilityProbeStatus.DEGRADED,
                driver_reason="ADBC_RUNTIME_PROBE_TIMED_OUT",
                endpoint_status=CapabilityProbeStatus.DEGRADED,
                endpoint_reason="ADBC_RUNTIME_PROBE_TIMED_OUT",
            )
        except Exception:
            return _adbc_probe_evidence(
                driver_status=CapabilityProbeStatus.UNKNOWN,
                driver_reason="ADBC_RUNTIME_PROBE_FAILED",
                endpoint_status=CapabilityProbeStatus.UNKNOWN,
                endpoint_reason="ADBC_RUNTIME_PROBE_FAILED",
            )

    async def _safe_probe_cluster_services(
        self,
        auth_context: Any | None,
    ) -> dict[str, CapabilityProbeEvidence]:
        try:
            async with asyncio.timeout(self._optional_probe_timeout()):
                return await self._probe_cluster_services(auth_context)
        except TimeoutError:
            return _cluster_http_probe_failure(
                status=CapabilityProbeStatus.DEGRADED,
                reason_code="CLUSTER_HTTP_PROBE_TIMED_OUT",
            )
        except DorisHTTPPolicyError:
            return _cluster_http_probe_failure(
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="CLUSTER_HTTP_ENDPOINT_MISCONFIGURED",
            )
        except DorisHTTPRequestError:
            return _cluster_http_probe_failure(
                status=CapabilityProbeStatus.DEGRADED,
                reason_code="CLUSTER_HTTP_ENDPOINT_UNREACHABLE",
            )
        except Exception:
            return _cluster_http_probe_failure(
                status=CapabilityProbeStatus.UNKNOWN,
                reason_code="CLUSTER_HTTP_PROBE_FAILED",
            )

    async def _probe_cluster_services(
        self,
        auth_context: Any | None,
    ) -> dict[str, CapabilityProbeEvidence]:
        if getattr(auth_context, "auth_method", "") == "doris_oauth":
            return _cluster_http_probe_failure(
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="CLUSTER_HTTP_CREDENTIAL_ROUTE_UNAVAILABLE",
            )
        config_resolver = getattr(
            self._connection_manager,
            "get_database_config_for_auth_context",
            None,
        )
        db_config = (
            config_resolver(auth_context)
            if callable(config_resolver)
            else database_config_for_request(self._connection_manager)
        )
        client = DorisHTTPClient.from_database_config(db_config)
        fe_hosts = configured_fe_http_hosts(db_config)
        raw_be_hosts = getattr(db_config, "be_hosts", []) or []
        if not isinstance(raw_be_hosts, list) or any(
            not isinstance(host, str) for host in raw_be_hosts
        ):
            return _cluster_http_probe_failure(
                status=CapabilityProbeStatus.MISCONFIGURED,
                reason_code="BE_METRICS_ENDPOINT_MISCONFIGURED",
            )
        be_hosts = tuple(dict.fromkeys(raw_be_hosts))
        fe_response, be_response = await asyncio.gather(
            client.get_first_available(
                role="fe",
                hosts=fe_hosts,
                port=db_config.fe_http_port,
                path="/metrics",
                headers={"Accept": "text/plain"},
            ),
            (
                client.get_first_available(
                    role="be",
                    hosts=be_hosts,
                    port=db_config.be_webserver_port,
                    path="/metrics",
                    headers={"Accept": "text/plain"},
                )
                if be_hosts
                else _missing_be_metrics_response()
            ),
        )
        fe_status, fe_reason = _classify_metrics_response(
            fe_response.status,
            configured=True,
        )
        be_status, be_reason = _classify_metrics_response(
            be_response.status,
            configured=bool(be_hosts),
        )
        fe_names = (
            _prometheus_metric_names(fe_response.text())
            if fe_status is CapabilityProbeStatus.SUPPORTED
            else frozenset()
        )
        be_names = (
            _prometheus_metric_names(be_response.text())
            if be_status is CapabilityProbeStatus.SUPPORTED
            else frozenset()
        )
        return _cluster_http_probe_evidence(
            fe_status=fe_status,
            fe_reason=fe_reason,
            be_status=be_status,
            be_reason=be_reason,
            fe_metric_names=fe_names,
            be_metric_names=be_names,
        )

    def _optional_probe_timeout(self) -> float:
        return max(
            0.25,
            min(2.0, self._probe_timeout_seconds / 2),
        )


def _classify_probe_error(
    error: Exception,
) -> tuple[CapabilityProbeStatus, str]:
    error_code = next(
        (value for value in getattr(error, "args", ()) if isinstance(value, int)),
        None,
    )
    message = str(error).casefold()
    if error_code in {1044, 1045, 1142, 1227} or any(
        marker in message
        for marker in ("access denied", "permission denied", "privilege")
    ):
        return (
            CapabilityProbeStatus.UNKNOWN,
            "PROBE_PERMISSION_DENIED",
        )
    if error_code in {1064, 1109, 1146, 1305}:
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


async def _missing_be_metrics_response() -> DorisHTTPResponse:
    return DorisHTTPResponse(
        status=0,
        headers={},
        body=b"",
        url="",
    )


def _classify_metrics_response(
    status_code: int,
    *,
    configured: bool,
) -> tuple[CapabilityProbeStatus, str]:
    if not configured:
        return (
            CapabilityProbeStatus.MISCONFIGURED,
            "METRICS_ENDPOINT_NOT_CONFIGURED",
        )
    if status_code == 200:
        return CapabilityProbeStatus.SUPPORTED, "METRICS_ENDPOINT_READABLE"
    if status_code in {401, 403}:
        return CapabilityProbeStatus.UNKNOWN, "METRICS_ENDPOINT_PERMISSION_DENIED"
    if status_code in {502, 503, 504}:
        return CapabilityProbeStatus.DEGRADED, "METRICS_ENDPOINT_UNREACHABLE"
    return CapabilityProbeStatus.UNSUPPORTED, "METRICS_ENDPOINT_UNSUPPORTED"


def _prometheus_metric_names(payload: str) -> frozenset[str]:
    names: set[str] = set()
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split(maxsplit=1)[0]
        name = token.split("{", 1)[0]
        if name:
            names.add(name)
        if len(names) >= 10_000:
            break
    return frozenset(names)


def _cluster_http_probe_failure(
    *,
    status: CapabilityProbeStatus,
    reason_code: str,
) -> dict[str, CapabilityProbeEvidence]:
    probe_ids = (
        "fe_metrics",
        "be_metrics",
        "metrics_endpoints_readable",
        "memory_tracker_metrics_readable",
        "legacy_compaction_status_readable",
        "connection_limit_metrics",
        "routine_load_metrics",
        "file_cache_queue_metrics",
        "enhanced_metrics_present",
        "file_cache_queue_metrics_present",
        "condition_cache",
        "parquet_page_cache",
        "advanced_cache_metrics_present",
    )
    return {
        probe_id: CapabilityProbeEvidence(
            probe_id=probe_id,
            status=status,
            reason_code=reason_code,
            evidence_sources=("doris_http_metrics", "runtime_probe"),
        )
        for probe_id in probe_ids
    }


def _cluster_http_probe_evidence(
    *,
    fe_status: CapabilityProbeStatus,
    fe_reason: str,
    be_status: CapabilityProbeStatus,
    be_reason: str,
    fe_metric_names: frozenset[str],
    be_metric_names: frozenset[str],
) -> dict[str, CapabilityProbeEvidence]:
    probes: dict[str, CapabilityProbeEvidence] = {
        "fe_metrics": CapabilityProbeEvidence(
            probe_id="fe_metrics",
            status=fe_status,
            reason_code=fe_reason,
            evidence_sources=("doris_fe_metrics", "runtime_probe"),
        ),
        "be_metrics": CapabilityProbeEvidence(
            probe_id="be_metrics",
            status=be_status,
            reason_code=be_reason,
            evidence_sources=("doris_be_metrics", "runtime_probe"),
        ),
    }
    combined_status, combined_reason = _combine_endpoint_status(
        fe_status,
        be_status,
    )
    probes["metrics_endpoints_readable"] = CapabilityProbeEvidence(
        probe_id="metrics_endpoints_readable",
        status=combined_status,
        reason_code=combined_reason,
        evidence_sources=(
            "doris_fe_metrics",
            "doris_be_metrics",
            "runtime_probe",
        ),
    )

    all_names = fe_metric_names | be_metric_names
    memory_present = _has_metric_marker(
        be_metric_names,
        ("memory", "mem_tracker", "jemalloc"),
    )
    probes["memory_tracker_metrics_readable"] = _metric_presence_evidence(
        "memory_tracker_metrics_readable",
        endpoint_status=be_status,
        present=memory_present,
        present_reason="MEMORY_TRACKER_METRICS_READABLE",
        absent_reason="MEMORY_TRACKER_METRICS_NOT_PRESENT",
        source="doris_be_metrics",
    )

    compaction_present = _has_metric_marker(all_names, ("compaction",))
    if compaction_present:
        probes["legacy_compaction_status_readable"] = CapabilityProbeEvidence(
            probe_id="legacy_compaction_status_readable",
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="LEGACY_COMPACTION_SUMMARY_READABLE",
            evidence_sources=("doris_metrics", "runtime_probe"),
        )
    else:
        probes["legacy_compaction_status_readable"] = _metric_presence_evidence(
            "legacy_compaction_status_readable",
            endpoint_status=combined_status,
            present=False,
            present_reason="LEGACY_COMPACTION_SUMMARY_READABLE",
            absent_reason="LEGACY_COMPACTION_METRICS_NOT_PRESENT",
            source="doris_metrics",
        )

    marker_contracts = {
        "connection_limit_metrics": ("connection", "limit"),
        "routine_load_metrics": ("routine_load",),
        "file_cache_queue_metrics": ("file_cache", "queue"),
        "condition_cache": ("condition_cache",),
        "parquet_page_cache": ("parquet", "page_cache"),
    }
    for probe_id, markers in marker_contracts.items():
        probes[probe_id] = _metric_presence_evidence(
            probe_id,
            endpoint_status=combined_status,
            present=all(marker in " ".join(all_names) for marker in markers),
            present_reason=f"{probe_id.upper()}_PRESENT",
            absent_reason=f"{probe_id.upper()}_NOT_PRESENT",
            source="doris_metrics",
        )

    queue_probe = probes["file_cache_queue_metrics"]
    probes["file_cache_queue_metrics_present"] = CapabilityProbeEvidence(
        probe_id="file_cache_queue_metrics_present",
        status=queue_probe.status,
        reason_code=queue_probe.reason_code,
        evidence_sources=queue_probe.evidence_sources,
    )
    enhanced_candidates = (
        probes["connection_limit_metrics"],
        probes["routine_load_metrics"],
        probes["file_cache_queue_metrics"],
    )
    probes["enhanced_metrics_present"] = _combine_metric_presence(
        "enhanced_metrics_present",
        enhanced_candidates,
        supported_reason="ENHANCED_METRICS_PRESENT",
    )
    advanced_candidates = (
        probes["condition_cache"],
        probes["parquet_page_cache"],
    )
    probes["advanced_cache_metrics_present"] = _combine_metric_presence(
        "advanced_cache_metrics_present",
        advanced_candidates,
        supported_reason="ADVANCED_CACHE_METRICS_PRESENT",
    )
    return probes


def _combine_endpoint_status(
    *statuses: CapabilityProbeStatus,
) -> tuple[CapabilityProbeStatus, str]:
    if all(status is CapabilityProbeStatus.SUPPORTED for status in statuses):
        return (
            CapabilityProbeStatus.SUPPORTED,
            "FE_BE_METRICS_ENDPOINTS_READABLE",
        )
    for status in (
        CapabilityProbeStatus.MISCONFIGURED,
        CapabilityProbeStatus.DEGRADED,
        CapabilityProbeStatus.UNKNOWN,
        CapabilityProbeStatus.UNSUPPORTED,
    ):
        if status in statuses:
            return status, f"FE_BE_METRICS_{status.value.upper()}"
    return CapabilityProbeStatus.UNKNOWN, "FE_BE_METRICS_UNKNOWN"


def _has_metric_marker(
    names: frozenset[str],
    markers: tuple[str, ...],
) -> bool:
    return any(any(marker in name.casefold() for marker in markers) for name in names)


def _metric_presence_evidence(
    probe_id: str,
    *,
    endpoint_status: CapabilityProbeStatus,
    present: bool,
    present_reason: str,
    absent_reason: str,
    source: str,
) -> CapabilityProbeEvidence:
    if present:
        status = CapabilityProbeStatus.SUPPORTED
        reason = present_reason
    elif endpoint_status is CapabilityProbeStatus.SUPPORTED:
        status = CapabilityProbeStatus.UNSUPPORTED
        reason = absent_reason
    else:
        status = endpoint_status
        reason = absent_reason
    return CapabilityProbeEvidence(
        probe_id=probe_id,
        status=status,
        reason_code=reason,
        evidence_sources=(source, "runtime_probe"),
    )


def _combine_metric_presence(
    probe_id: str,
    candidates: tuple[CapabilityProbeEvidence, ...],
    *,
    supported_reason: str,
) -> CapabilityProbeEvidence:
    if all(
        candidate.status is CapabilityProbeStatus.SUPPORTED for candidate in candidates
    ):
        status = CapabilityProbeStatus.SUPPORTED
        reason = supported_reason
    else:
        status = next(
            (
                candidate.status
                for candidate in candidates
                if candidate.status is not CapabilityProbeStatus.SUPPORTED
            ),
            CapabilityProbeStatus.UNKNOWN,
        )
        reason = f"{probe_id.upper()}_INCOMPLETE"
    return CapabilityProbeEvidence(
        probe_id=probe_id,
        status=status,
        reason_code=reason,
        evidence_sources=("doris_metrics", "runtime_probe"),
    )


def _profile_api_code(payload: Mapping[str, Any] | None) -> int | None:
    if payload is None or "code" not in payload:
        return None
    try:
        return int(payload["code"])
    except (TypeError, ValueError):
        return None


def _classify_profile_api_response(
    status_code: int,
    payload: Mapping[str, Any] | None,
) -> tuple[CapabilityProbeStatus, str]:
    api_code = _profile_api_code(payload)
    if status_code == 200 and api_code == 0:
        return CapabilityProbeStatus.SUPPORTED, "PROFILE_API_READABLE"
    if status_code in {401, 403} or api_code in {401, 403}:
        return (
            CapabilityProbeStatus.UNKNOWN,
            "PROFILE_API_PERMISSION_DENIED",
        )
    if status_code in {502, 503, 504}:
        return (
            CapabilityProbeStatus.DEGRADED,
            "PROFILE_API_UNREACHABLE",
        )
    if status_code == 200:
        return (
            CapabilityProbeStatus.UNKNOWN,
            "PROFILE_API_INVALID_RESPONSE",
        )
    return CapabilityProbeStatus.UNSUPPORTED, "PROFILE_API_UNSUPPORTED"


def _adbc_probe_evidence(
    *,
    driver_status: CapabilityProbeStatus,
    driver_reason: str,
    endpoint_status: CapabilityProbeStatus,
    endpoint_reason: str,
) -> dict[str, CapabilityProbeEvidence]:
    return {
        "adbc_driver_ready": CapabilityProbeEvidence(
            probe_id="adbc_driver_ready",
            status=driver_status,
            reason_code=driver_reason,
            evidence_sources=("adbc_runtime_probe",),
        ),
        "flight_sql_reachable": CapabilityProbeEvidence(
            probe_id="flight_sql_reachable",
            status=endpoint_status,
            reason_code=endpoint_reason,
            evidence_sources=("adbc_runtime_probe",),
        ),
        "flight_sql": CapabilityProbeEvidence(
            probe_id="flight_sql",
            status=endpoint_status,
            reason_code=endpoint_reason,
            evidence_sources=("adbc_runtime_probe",),
        ),
    }


def _adbc_release_maturity_probe(
    version: DorisVersion,
) -> CapabilityProbeEvidence:
    """Mark Doris 2.1.0-2.1.4 ADBC as early and runtime-gated."""
    if not version.is_parsed:
        status = CapabilityProbeStatus.UNKNOWN
        reason = "DORIS_VERSION_UNKNOWN"
    elif version.compare(_ADBC_RECOMMENDED_MINIMUM) < 0:
        status = CapabilityProbeStatus.DEGRADED
        reason = "ADBC_EARLY_2_1_RELEASE"
    else:
        status = CapabilityProbeStatus.SUPPORTED
        reason = "ADBC_RECOMMENDED_RELEASE_BASELINE"
    return CapabilityProbeEvidence(
        probe_id="adbc_release_maturity",
        status=status,
        reason_code=reason,
        evidence_sources=("doris_arrow_flight_sql_guide",),
    )


def _combine_query_evidence_probe(
    probes: Mapping[str, CapabilityProbeEvidence],
) -> CapabilityProbeEvidence:
    candidates = tuple(
        probe
        for probe_id in (
            "query_profile_api_readable",
            "audit_log_readable",
        )
        if (probe := probes.get(probe_id)) is not None
    )
    if any(probe.status is CapabilityProbeStatus.SUPPORTED for probe in candidates):
        status = CapabilityProbeStatus.SUPPORTED
        reason = "PROFILE_OR_AUDIT_EVIDENCE_READABLE"
    elif any(probe.status is CapabilityProbeStatus.DEGRADED for probe in candidates):
        status = CapabilityProbeStatus.DEGRADED
        reason = "PROFILE_OR_AUDIT_EVIDENCE_DEGRADED"
    elif any(
        probe.status is CapabilityProbeStatus.MISCONFIGURED for probe in candidates
    ):
        status = CapabilityProbeStatus.MISCONFIGURED
        reason = "PROFILE_OR_AUDIT_EVIDENCE_MISCONFIGURED"
    elif any(probe.status is CapabilityProbeStatus.UNSUPPORTED for probe in candidates):
        status = CapabilityProbeStatus.UNSUPPORTED
        reason = "PROFILE_OR_AUDIT_EVIDENCE_UNSUPPORTED"
    else:
        status = CapabilityProbeStatus.UNKNOWN
        reason = "PROFILE_OR_AUDIT_EVIDENCE_UNKNOWN"
    return CapabilityProbeEvidence(
        probe_id="profile_or_audit_readable",
        status=status,
        reason_code=reason,
        evidence_sources=("runtime_probe",),
    )


def _combine_cluster_evidence_probes(
    probes: Mapping[str, CapabilityProbeEvidence],
) -> dict[str, CapabilityProbeEvidence]:
    active_tasks = _combine_any_runtime_probe(
        "legacy_task_views_readable",
        probes,
        (
            "current_queries_proc_readable",
            "active_queries_view_readable",
            "processlist_readable",
        ),
        supported_reason="LEGACY_TASK_VIEW_READABLE",
    )
    audit = probes.get("metrics_history_readable")
    storage = probes.get("resource_storage_history_readable")
    full = (
        _combine_all_evidence(
            "resource_history_all_sources_readable",
            (audit, storage),
            supported_reason="ALL_RESOURCE_HISTORY_SOURCES_READABLE",
        )
        if audit is not None and storage is not None
        else CapabilityProbeEvidence(
            probe_id="resource_history_all_sources_readable",
            status=CapabilityProbeStatus.UNKNOWN,
            reason_code="CAPABILITY_PROBE_PENDING",
            evidence_sources=("runtime_probe",),
        )
    )
    if audit is not None and storage is not None and not any(
        source.status is CapabilityProbeStatus.SUPPORTED
        for source in (audit, storage)
    ):
        full = CapabilityProbeEvidence(
            probe_id=full.probe_id,
            status=full.status,
            reason_code="RESOURCE_HISTORY_UNAVAILABLE",
            evidence_sources=full.evidence_sources,
        )

    def partial_source(
        probe_id: str,
        source: CapabilityProbeEvidence | None,
        *,
        reason_code: str,
    ) -> CapabilityProbeEvidence:
        if source is None:
            return CapabilityProbeEvidence(
                probe_id=probe_id,
                status=CapabilityProbeStatus.UNKNOWN,
                reason_code="CAPABILITY_PROBE_PENDING",
                evidence_sources=("runtime_probe",),
            )
        return CapabilityProbeEvidence(
            probe_id=probe_id,
            status=(
                CapabilityProbeStatus.DEGRADED
                if source.status is CapabilityProbeStatus.SUPPORTED
                else source.status
            ),
            reason_code=(
                reason_code
                if source.status is CapabilityProbeStatus.SUPPORTED
                else source.reason_code
            ),
            evidence_sources=source.evidence_sources or ("runtime_probe",),
        )

    audit_only = partial_source(
        "resource_growth_audit_history_readable",
        audit,
        reason_code="AUDIT_RESOURCE_HISTORY_ONLY",
    )
    storage_only = partial_source(
        "resource_growth_storage_history_readable",
        storage,
        reason_code="PARTITION_CREATION_HISTORY_ONLY",
    )
    return {
        active_tasks.probe_id: active_tasks,
        full.probe_id: full,
        audit_only.probe_id: audit_only,
        storage_only.probe_id: storage_only,
    }


def _combine_pipeline_evidence_probes(
    probes: Mapping[str, CapabilityProbeEvidence],
) -> dict[str, CapabilityProbeEvidence]:
    ingestion_source_ids = (
        "batch_load_metadata_readable",
        "stream_load_metadata_readable",
        "routine_load_metadata_readable",
    )
    all_ingestion_source_ids = (
        *ingestion_source_ids,
        "insert_job_metadata_readable",
    )
    ingestion = _combine_any_runtime_probe(
        "stream_broker_routine_load_readable",
        probes,
        ingestion_source_ids,
        supported_reason="LOAD_JOB_METADATA_READABLE",
    )
    ingestion_status = _combine_any_runtime_probe(
        "ingestion_status_readable",
        probes,
        all_ingestion_source_ids,
        supported_reason="INGESTION_STATUS_READABLE",
    )
    materialized_views = _combine_any_runtime_probe(
        "materialized_view_tasks_readable",
        probes,
        (
            "materialized_view_job_metadata_readable",
            "materialized_view_task_metadata_readable",
        ),
        supported_reason="MATERIALIZED_VIEW_METADATA_READABLE",
    )

    freshness_candidates = tuple(
        probe
        for probe_id in (
            "routine_load_metadata_readable",
            "pipeline_audit_log_readable",
        )
        if (probe := probes.get(probe_id)) is not None
    )
    if any(
        probe.probe_id == "routine_load_metadata_readable"
        and probe.status is CapabilityProbeStatus.SUPPORTED
        for probe in freshness_candidates
    ):
        freshness_status = CapabilityProbeStatus.SUPPORTED
        freshness_reason = "LOAD_OFFSET_OR_TIME_EVIDENCE_READABLE"
    elif any(
        probe.status is CapabilityProbeStatus.SUPPORTED
        for probe in freshness_candidates
    ):
        freshness_status = CapabilityProbeStatus.DEGRADED
        freshness_reason = "AUDIT_TIME_FALLBACK_READABLE"
    else:
        freshness_status, freshness_reason = _best_candidate_status(
            freshness_candidates,
            reason_prefix="FRESHNESS_EVIDENCE",
        )
    freshness = CapabilityProbeEvidence(
        probe_id="freshness_evidence_readable",
        status=freshness_status,
        reason_code=freshness_reason,
        evidence_sources=("runtime_probe",),
    )
    load_offset = CapabilityProbeEvidence(
        probe_id="load_offset_or_time_evidence_readable",
        status=freshness_status,
        reason_code=freshness_reason,
        evidence_sources=("runtime_probe",),
    )
    return {
        ingestion.probe_id: ingestion,
        ingestion_status.probe_id: ingestion_status,
        materialized_views.probe_id: materialized_views,
        freshness.probe_id: freshness,
        load_offset.probe_id: load_offset,
    }


def _combine_search_evidence_probes(
    probes: Mapping[str, CapabilityProbeEvidence],
) -> dict[str, CapabilityProbeEvidence]:
    text = _combine_all_runtime_probes(
        "inverted_index_and_search_syntax_ready",
        probes,
        (
            "inverted_index_metadata_readable",
            "tokenize_function_or_analyzer_ready",
            "text_match_syntax_readable",
        ),
        supported_reason="INVERTED_INDEX_AND_MATCH_READY",
    )
    ann = _combine_all_runtime_probes(
        "ann_index_and_metric_compatible",
        probes,
        (
            "ann_index_metadata_readable",
            "ann_distance_function_readable",
        ),
        supported_reason="ANN_INDEX_AND_DISTANCE_READY",
    )
    hybrid = _combine_all_evidence(
        "hybrid_search",
        (text, ann),
        supported_reason="TEXT_AND_ANN_SEARCH_READY",
    )
    diagnosis = _combine_all_runtime_probes(
        "search_index_and_explain_readable",
        probes,
        (
            "search_index_metadata_readable",
            "search_explain_readable",
        ),
        supported_reason="SEARCH_INDEX_AND_EXPLAIN_READABLE",
    )
    plan = CapabilityProbeEvidence(
        probe_id="search_plan_facets_readable",
        status=diagnosis.status,
        reason_code=diagnosis.reason_code,
        evidence_sources=diagnosis.evidence_sources,
    )
    ann_feature = CapabilityProbeEvidence(
        probe_id="ann_index",
        status=ann.status,
        reason_code=ann.reason_code,
        evidence_sources=ann.evidence_sources,
    )
    return {
        text.probe_id: text,
        ann.probe_id: ann,
        ann_feature.probe_id: ann_feature,
        hybrid.probe_id: hybrid,
        diagnosis.probe_id: diagnosis,
        plan.probe_id: plan,
    }


def _combine_governance_evidence_probes(
    probes: Mapping[str, CapabilityProbeEvidence],
) -> dict[str, CapabilityProbeEvidence]:
    storage = probes.get("table_storage_metadata_readable")
    audit = probes.get("audit_log_readable")
    udf = probes.get("udf_metadata_readable")
    derived: dict[str, CapabilityProbeEvidence] = {}
    if storage is not None:
        for probe_id in (
            "storage_v3_variant_properties_readable",
            "storage_v3",
            "variant_sparse",
            "variant_doc",
        ):
            derived[probe_id] = CapabilityProbeEvidence(
                probe_id=probe_id,
                status=(
                    CapabilityProbeStatus.DEGRADED
                    if storage.status is CapabilityProbeStatus.SUPPORTED
                    else storage.status
                ),
                reason_code=(
                    "TARGET_STORAGE_FACETS_REQUIRE_CALL_TIME_VALIDATION"
                    if storage.status is CapabilityProbeStatus.SUPPORTED
                    else storage.reason_code
                ),
                evidence_sources=storage.evidence_sources,
            )
    if audit is not None:
        for probe_id in (
            "set_var_audit",
            "enhanced_secret_masking",
        ):
            derived[probe_id] = CapabilityProbeEvidence(
                probe_id=probe_id,
                status=(
                    CapabilityProbeStatus.DEGRADED
                    if audit.status is CapabilityProbeStatus.SUPPORTED
                    else audit.status
                ),
                reason_code=(
                    "ENHANCED_AUDIT_FIELDS_REQUIRE_CALL_TIME_VALIDATION"
                    if audit.status is CapabilityProbeStatus.SUPPORTED
                    else audit.reason_code
                ),
                evidence_sources=audit.evidence_sources,
            )
    if udf is not None:
        for probe_id in (
            "python_udf",
            "python_udaf",
            "python_udtf",
        ):
            derived[probe_id] = CapabilityProbeEvidence(
                probe_id=probe_id,
                status=udf.status,
                reason_code=udf.reason_code,
                evidence_sources=udf.evidence_sources,
            )
    return derived


def _combine_lakehouse_evidence_probes(
    probes: Mapping[str, CapabilityProbeEvidence],
) -> dict[str, CapabilityProbeEvidence]:
    """Derive target-sensitive 4.1 facets from readable metadata surfaces."""
    derived: dict[str, CapabilityProbeEvidence] = {}
    table_metadata = probes.get("lakehouse_table_metadata_readable")
    if table_metadata is not None:
        for probe_id in (
            "lakehouse_snapshot_features_readable",
            "iceberg_deletion_vector",
            "iceberg_row_lineage",
        ):
            derived[probe_id] = CapabilityProbeEvidence(
                probe_id=probe_id,
                status=(
                    CapabilityProbeStatus.DEGRADED
                    if table_metadata.status is CapabilityProbeStatus.SUPPORTED
                    else table_metadata.status
                ),
                reason_code=(
                    "TARGET_LAKEHOUSE_FORMAT_REQUIRES_CALL_TIME_VALIDATION"
                    if table_metadata.status is CapabilityProbeStatus.SUPPORTED
                    else table_metadata.reason_code
                ),
                evidence_sources=table_metadata.evidence_sources,
            )
    variant_metadata = probes.get("variant_column_type_readable")
    if variant_metadata is not None:
        for probe_id in (
            "variant_advanced_properties_readable",
            "variant_sparse_sharding",
            "variant_sparse_cache",
            "variant_doc_mode",
            "storage_v3",
        ):
            derived[probe_id] = CapabilityProbeEvidence(
                probe_id=probe_id,
                status=(
                    CapabilityProbeStatus.DEGRADED
                    if variant_metadata.status
                    is CapabilityProbeStatus.SUPPORTED
                    else variant_metadata.status
                ),
                reason_code=(
                    "TARGET_VARIANT_PROPERTIES_REQUIRE_CALL_TIME_VALIDATION"
                    if variant_metadata.status
                    is CapabilityProbeStatus.SUPPORTED
                    else variant_metadata.reason_code
                ),
                evidence_sources=variant_metadata.evidence_sources,
            )
    return derived


def _semantic_adapter_evidence_probes() -> dict[str, CapabilityProbeEvidence]:
    """Expose server capability while validating exact models at call time."""
    supported = CapabilityProbeEvidence(
        probe_id="ossie_spec_and_registry_ready",
        status=CapabilityProbeStatus.SUPPORTED,
        reason_code="PINNED_OSSIE_ADAPTER_READY",
        evidence_sources=("pinned_ossie_schema", "provider_registry"),
    )
    derived = {
        supported.probe_id: supported,
    }
    for probe_id in (
        "explicit_model_ref_valid",
        "ossie_model_valid",
        "semantic_policy_ready",
        "doris_binding_metadata_readable",
    ):
        derived[probe_id] = CapabilityProbeEvidence(
            probe_id=probe_id,
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="SEMANTIC_TARGET_REQUIRES_CALL_TIME_VALIDATION",
            evidence_sources=("pinned_ossie_schema", "active_doris_route"),
        )
    derived["metricflow_provider_protocol_ready"] = CapabilityProbeEvidence(
        probe_id="metricflow_provider_protocol_ready",
        status=CapabilityProbeStatus.DEGRADED,
        reason_code="METRICFLOW_PROVIDER_REQUIRES_CALL_TIME_VALIDATION",
        evidence_sources=("provider_registry", "metricflow_provider_protocol"),
    )
    for probe_id in (
        "explicit_metricflow_model_ref_valid",
        "metricflow_model_metadata_readable",
        "metricflow_compile_ready",
        "metricflow_doris_dialect_ready",
    ):
        derived[probe_id] = CapabilityProbeEvidence(
            probe_id=probe_id,
            status=CapabilityProbeStatus.DEGRADED,
            reason_code="METRICFLOW_TARGET_REQUIRES_CALL_TIME_VALIDATION",
            evidence_sources=(
                "metricflow_provider_protocol",
                "active_doris_route",
            ),
        )
    return derived


def _combine_all_runtime_probes(
    probe_id: str,
    probes: Mapping[str, CapabilityProbeEvidence],
    candidate_ids: Sequence[str],
    *,
    supported_reason: str,
) -> CapabilityProbeEvidence:
    candidates = tuple(
        probe
        for candidate_id in candidate_ids
        if (probe := probes.get(candidate_id)) is not None
    )
    return _combine_all_evidence(
        probe_id,
        candidates,
        supported_reason=supported_reason,
    )


def _combine_all_evidence(
    probe_id: str,
    candidates: Sequence[CapabilityProbeEvidence],
    *,
    supported_reason: str,
) -> CapabilityProbeEvidence:
    if candidates and all(
        probe.status is CapabilityProbeStatus.SUPPORTED
        for probe in candidates
    ):
        status = CapabilityProbeStatus.SUPPORTED
        reason = supported_reason
    else:
        status = next(
            (
                candidate_status
                for candidate_status in (
                    CapabilityProbeStatus.MISCONFIGURED,
                    CapabilityProbeStatus.UNSUPPORTED,
                    CapabilityProbeStatus.UNKNOWN,
                    CapabilityProbeStatus.DEGRADED,
                )
                if any(
                    probe.status is candidate_status
                    for probe in candidates
                )
            ),
            CapabilityProbeStatus.UNKNOWN,
        )
        reason = f"{probe_id.upper()}_{status.value.upper()}"
    return CapabilityProbeEvidence(
        probe_id=probe_id,
        status=status,
        reason_code=reason,
        evidence_sources=("runtime_probe",),
    )


def _combine_any_runtime_probe(
    probe_id: str,
    probes: Mapping[str, CapabilityProbeEvidence],
    candidate_ids: Sequence[str],
    *,
    supported_reason: str,
) -> CapabilityProbeEvidence:
    candidates = tuple(
        probe
        for candidate_id in candidate_ids
        if (probe := probes.get(candidate_id)) is not None
    )
    if any(
        probe.status is CapabilityProbeStatus.SUPPORTED for probe in candidates
    ):
        status = CapabilityProbeStatus.SUPPORTED
        reason = supported_reason
    else:
        status, reason = _best_candidate_status(
            candidates,
            reason_prefix=probe_id.upper(),
        )
    return CapabilityProbeEvidence(
        probe_id=probe_id,
        status=status,
        reason_code=reason,
        evidence_sources=("runtime_probe",),
    )


def _best_candidate_status(
    candidates: Sequence[CapabilityProbeEvidence],
    *,
    reason_prefix: str,
) -> tuple[CapabilityProbeStatus, str]:
    for status in (
        CapabilityProbeStatus.DEGRADED,
        CapabilityProbeStatus.MISCONFIGURED,
        CapabilityProbeStatus.UNKNOWN,
        CapabilityProbeStatus.UNSUPPORTED,
    ):
        if any(probe.status is status for probe in candidates):
            return status, f"{reason_prefix}_{status.value.upper()}"
    return CapabilityProbeStatus.UNKNOWN, f"{reason_prefix}_UNKNOWN"


def _row_value(
    row: Mapping[str, Any],
    *names: str,
) -> Any | None:
    lowered = {str(key).lower(): value for key, value in row.items()}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _nonnegative_int(value: Any | None) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = int(value.strip())
        except ValueError:
            return 0
    else:
        return 0
    return max(0, parsed)


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
        if not _component_is_active(row):
            continue
        version = _component_version(_row_value(row, "Version", "FeVersion"))
        observed.append(
            (
                version,
                _truthy(_row_value(row, "IsMaster", "Master")),
            )
        )
    master_index = next(
        (index for index, (_, is_master) in enumerate(observed) if is_master),
        None,
    )
    if master_index is None:
        return fallback, tuple(version for version, _ in observed)

    master = observed[master_index][0]
    if not master.raw:
        master = fallback
    followers = tuple(
        version for index, (version, _) in enumerate(observed) if index != master_index
    )
    return master, followers


def _backend_versions(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[DorisVersion, ...]:
    return tuple(
        _component_version(_row_value(row, "Version", "BeVersion"))
        for row in rows
        if _component_is_active(row)
    )


def _component_is_active(row: Mapping[str, Any]) -> bool:
    alive = _row_value(row, "Alive")
    return alive is None or str(alive).strip() == "" or _truthy(alive)


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
                    str(_row_value(row, identifier) or "") for identifier in identifiers
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

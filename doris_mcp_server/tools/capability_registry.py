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
"""Capability snapshot cache and deterministic child availability evaluation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import Any

from ..utils.db import DorisRouteIdentity
from .capability_detector import (
    CapabilityDetectionError,
    CapabilityProbeEvidence,
    CapabilityProbeStatus,
    CapabilityRouteChangedError,
    DorisCapabilityDetector,
    DorisCapabilitySnapshot,
)
from .domain_dispatcher import BoundHandlerAvailabilityProvider
from .domain_manifest import (
    DomainAvailabilityResolution,
    authorized_child_execution,
)
from .domain_models import (
    Availability,
    AvailabilityStatus,
    CapabilityVariant,
    ChildToolDefinition,
    DomainDefinition,
)
from .doris_feature_matrix import (
    CapabilityVersionScope,
    DorisClusterVersionVector,
    DorisFeatureMatrix,
    VersionCertificationStatus,
)
from .doris_version import parse_doris_version_comment

_STALE_RETRY_SECONDS = 30


@dataclass(frozen=True, slots=True)
class CapabilityProviderEvidence:
    """Private readiness state for one runtime provider."""

    provider_id: str
    status: CapabilityProbeStatus
    reason_code: str
    evidence_sources: tuple[str, ...] = ("provider_registry",)


@dataclass(frozen=True, slots=True)
class CapabilityProviderSnapshot:
    """Immutable provider state used in one availability calculation."""

    providers: Mapping[str, CapabilityProviderEvidence]
    generation: str


class CapabilityProviderRegistry:
    """Track provider readiness without publishing provider configuration."""

    def __init__(
        self,
        providers: Mapping[str, CapabilityProviderEvidence],
    ) -> None:
        self._providers = dict(providers)

    @classmethod
    def from_runtime(
        cls,
        *,
        matrix: DorisFeatureMatrix,
        bound_handlers: BoundHandlerAvailabilityProvider,
        config: Any | None,
    ) -> CapabilityProviderRegistry:
        provider_features: dict[str, set[str]] = {}
        for feature in matrix.features:
            for variant in feature.support_contract.variants:
                for provider_id in variant.required_providers:
                    provider_features.setdefault(provider_id, set()).add(
                        feature.feature_id
                    )

        configured_adbc = bool(
            getattr(getattr(config, "adbc", None), "enabled", False)
        )
        providers: dict[str, CapabilityProviderEvidence] = {}
        for provider_id, feature_ids in provider_features.items():
            has_bound_consumer = bool(
                feature_ids & bound_handlers.bound_feature_ids
            )
            configured = has_bound_consumer
            if provider_id == "adbc_provider":
                configured = configured and configured_adbc
            elif provider_id == "lineage_event_store":
                configured_store = getattr(
                    getattr(config, "governance", None),
                    "lineage_store_table",
                    None,
                )
                configured = (
                    configured
                    and isinstance(configured_store, str)
                    and bool(configured_store.strip())
                )
            providers[provider_id] = CapabilityProviderEvidence(
                provider_id=provider_id,
                status=(
                    CapabilityProbeStatus.SUPPORTED
                    if configured
                    else CapabilityProbeStatus.MISCONFIGURED
                ),
                reason_code=(
                    "PROVIDER_CONFIGURED"
                    if configured
                    else "PROVIDER_NOT_CONFIGURED"
                ),
            )
        return cls(providers)

    def set_provider(
        self,
        provider_id: str,
        *,
        status: CapabilityProbeStatus,
        reason_code: str,
        evidence_sources: tuple[str, ...] = ("provider_registry",),
    ) -> None:
        """Replace one provider state and thereby advance its generation."""
        self._providers[provider_id] = CapabilityProviderEvidence(
            provider_id=provider_id,
            status=status,
            reason_code=reason_code,
            evidence_sources=evidence_sources,
        )

    def snapshot(self) -> CapabilityProviderSnapshot:
        providers = MappingProxyType(dict(self._providers))
        payload = {
            provider_id: {
                "status": evidence.status.value,
                "reason_code": evidence.reason_code,
                "evidence_sources": evidence.evidence_sources,
            }
            for provider_id, evidence in sorted(providers.items())
        }
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
        generation = "provider." + hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()[:16]
        return CapabilityProviderSnapshot(
            providers=providers,
            generation=generation,
        )


@dataclass(frozen=True, slots=True)
class _CandidateFailure:
    status: AvailabilityStatus
    reason_code: str
    evidence_sources: tuple[str, ...]
    limitations: tuple[str, ...]


class CapabilityEvaluator:
    """Merge version, provider, probe, handler, and auth facts."""

    def __init__(
        self,
        *,
        matrix: DorisFeatureMatrix,
        bound_handlers: BoundHandlerAvailabilityProvider,
    ) -> None:
        self._matrix = matrix
        self._bound_handlers = bound_handlers

    def evaluate(
        self,
        *,
        snapshot: DorisCapabilitySnapshot,
        providers: CapabilityProviderSnapshot,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        detected_versions = _detected_versions(snapshot)
        if not self._bound_handlers.is_bound(domain.name, child.name):
            return Availability(
                status=AvailabilityStatus.UNKNOWN,
                callable=False,
                reason_code="HANDLER_NOT_BOUND",
                detected_versions=detected_versions,
                evidence_sources=(
                    "catalog_contract",
                    "handler_registry",
                ),
            )

        feature = self._matrix.get_feature(domain.name, child.name)
        if (
            snapshot.mixed_versions
            and feature.version_scope
            not in {
                CapabilityVersionScope.MASTER_FE,
                CapabilityVersionScope.PROVIDER_WITH_MASTER_FE_BASELINE,
            }
        ):
            return Availability(
                status=AvailabilityStatus.UNAVAILABLE,
                callable=False,
                reason_code="MIXED_DORIS_VERSIONS",
                detected_versions=detected_versions,
                evidence_sources=(
                    "version_probe",
                    "show_frontends",
                    "show_backends",
                ),
                limitations=(
                    "The required Doris component versions are mixed.",
                ),
            )

        failures: list[_CandidateFailure] = []
        for variant in child.support_contract.variants:
            version_result = self._matrix.evaluate(
                domain=domain.name,
                child_name=child.name,
                versions=snapshot.version_vector,
                variant_name=variant.name,
            )
            if not version_result.compatible:
                failures.append(
                    _CandidateFailure(
                        status=(
                            AvailabilityStatus.UNKNOWN
                            if version_result.reason_code
                            == "DORIS_VERSION_UNKNOWN"
                            else AvailabilityStatus.UNAVAILABLE
                        ),
                        reason_code=version_result.reason_code,
                        evidence_sources=_normalized_source_ids(
                            version_result.source_ids
                        ),
                        limitations=(),
                    )
                )
                continue

            candidate = self._evaluate_runtime_requirements(
                snapshot=snapshot,
                providers=providers,
                variant=variant,
                version_sources=_normalized_source_ids(
                    version_result.source_ids
                ),
            )
            if isinstance(candidate, _CandidateFailure):
                failures.append(candidate)
                continue

            degraded, evidence_sources, limitations = candidate
            if not authorized_child_execution(auth_context, domain, child):
                return Availability(
                    status=AvailabilityStatus.UNAVAILABLE,
                    callable=False,
                    reason_code="CHILD_CALL_PERMISSION_DENIED",
                    detected_versions=detected_versions,
                    evidence_sources=_ordered_unique(
                        (*evidence_sources, "authorization_policy")
                    ),
                    limitations=limitations,
                )

            uncertified = (
                version_result.certification_status
                is not VersionCertificationStatus.CERTIFIED
            )
            if snapshot.stale:
                degraded = True
                limitations = _ordered_unique(
                    (
                        *limitations,
                        "The capability snapshot is stale.",
                    )
                )
            return Availability(
                status=(
                    AvailabilityStatus.DEGRADED
                    if degraded
                    else AvailabilityStatus.AVAILABLE
                ),
                callable=True,
                reason_code=(
                    "CAPABILITY_VERIFIED_DEGRADED_UNCERTIFIED"
                    if degraded and uncertified
                    else (
                        "CAPABILITY_VERIFIED_DEGRADED"
                        if degraded
                        else (
                            "CAPABILITY_VERIFIED_UNCERTIFIED"
                            if uncertified
                            else "CAPABILITY_VERIFIED"
                        )
                    )
                ),
                detected_versions=detected_versions,
                active_variant=variant.name,
                evidence_sources=evidence_sources,
                limitations=limitations,
            )

        failure = _select_failure(failures)
        return Availability(
            status=failure.status,
            callable=False,
            reason_code=failure.reason_code,
            detected_versions=detected_versions,
            evidence_sources=failure.evidence_sources,
            limitations=failure.limitations,
        )

    def _evaluate_runtime_requirements(
        self,
        *,
        snapshot: DorisCapabilitySnapshot,
        providers: CapabilityProviderSnapshot,
        variant: CapabilityVariant,
        version_sources: tuple[str, ...],
    ) -> (
        tuple[bool, tuple[str, ...], tuple[str, ...]]
        | _CandidateFailure
    ):
        evidence_sources = list(version_sources)
        limitations: list[str] = []
        degraded = False

        if variant.deployment_modes:
            if snapshot.deployment_mode == "unknown":
                return _CandidateFailure(
                    status=AvailabilityStatus.UNKNOWN,
                    reason_code="DEPLOYMENT_MODE_UNKNOWN",
                    evidence_sources=tuple(version_sources),
                    limitations=(),
                )
            if snapshot.deployment_mode not in variant.deployment_modes:
                return _CandidateFailure(
                    status=AvailabilityStatus.UNAVAILABLE,
                    reason_code="DEPLOYMENT_MODE_NOT_SUPPORTED",
                    evidence_sources=tuple(version_sources),
                    limitations=(),
                )

        for provider_id in variant.required_providers:
            provider = providers.providers.get(provider_id)
            if provider is None or (
                provider.status is CapabilityProbeStatus.MISCONFIGURED
            ):
                return _CandidateFailure(
                    status=AvailabilityStatus.MISCONFIGURED,
                    reason_code="PROVIDER_NOT_CONFIGURED",
                    evidence_sources=_ordered_unique(
                        (*version_sources, "provider_registry")
                    ),
                    limitations=(),
                )
            evidence_sources.extend(provider.evidence_sources)
            evidence_sources.append(provider_id)
            if provider.status is CapabilityProbeStatus.UNSUPPORTED:
                return _CandidateFailure(
                    status=AvailabilityStatus.UNAVAILABLE,
                    reason_code=provider.reason_code,
                    evidence_sources=_ordered_unique(evidence_sources),
                    limitations=(),
                )
            if provider.status is CapabilityProbeStatus.UNKNOWN:
                return _CandidateFailure(
                    status=AvailabilityStatus.UNKNOWN,
                    reason_code=provider.reason_code,
                    evidence_sources=_ordered_unique(evidence_sources),
                    limitations=(),
                )
            if provider.status is CapabilityProbeStatus.DEGRADED:
                degraded = True
                limitations.append(
                    f"Provider {provider_id} is degraded."
                )

        requirement_ids = _ordered_unique(
            (
                *variant.required_features,
                *variant.required_system_objects,
                *variant.required_endpoints,
                *variant.required_probes,
            )
        )
        for requirement_id in requirement_ids:
            probe = snapshot.probe(requirement_id)
            if probe is None:
                return _CandidateFailure(
                    status=AvailabilityStatus.UNKNOWN,
                    reason_code="CAPABILITY_PROBE_PENDING",
                    evidence_sources=_ordered_unique(
                        (*evidence_sources, "runtime_probe")
                    ),
                    limitations=(),
                )
            evidence_sources.extend(probe.evidence_sources)
            evidence_sources.append(_public_evidence_source_id(probe.probe_id))
            if probe.status is CapabilityProbeStatus.MISCONFIGURED:
                return _CandidateFailure(
                    status=AvailabilityStatus.MISCONFIGURED,
                    reason_code=probe.reason_code,
                    evidence_sources=_ordered_unique(evidence_sources),
                    limitations=(),
                )
            if probe.status is CapabilityProbeStatus.UNSUPPORTED:
                return _CandidateFailure(
                    status=AvailabilityStatus.UNAVAILABLE,
                    reason_code=probe.reason_code,
                    evidence_sources=_ordered_unique(evidence_sources),
                    limitations=(),
                )
            if probe.status is CapabilityProbeStatus.UNKNOWN:
                return _CandidateFailure(
                    status=AvailabilityStatus.UNKNOWN,
                    reason_code=probe.reason_code,
                    evidence_sources=_ordered_unique(evidence_sources),
                    limitations=(),
                )
            if probe.status is CapabilityProbeStatus.DEGRADED:
                degraded = True
                limitations.append(
                    f"Probe {requirement_id} is degraded."
                )

        if degraded and not variant.callable_when_degraded:
            return _CandidateFailure(
                status=AvailabilityStatus.DEGRADED,
                reason_code="CAPABILITY_DEGRADED",
                evidence_sources=_ordered_unique(evidence_sources),
                limitations=_ordered_unique(limitations),
            )
        return (
            degraded,
            _ordered_unique(evidence_sources),
            _ordered_unique(limitations),
        )


class CapabilityRegistry:
    """Route-private snapshot cache implementing Manifest availability."""

    def __init__(
        self,
        *,
        detector: DorisCapabilityDetector,
        provider_registry: CapabilityProviderRegistry,
        evaluator: CapabilityEvaluator,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._detector = detector
        self._provider_registry = provider_registry
        self._evaluator = evaluator
        self._clock = clock or (lambda: datetime.now(UTC))
        self._capability_generation = 1
        self._base_cache: dict[str, DorisCapabilitySnapshot] = {}
        self._domain_cache: dict[str, DorisCapabilitySnapshot] = {}
        self._latest_domain: dict[
            tuple[str, str],
            DorisCapabilitySnapshot,
        ] = {}
        self._inflight: dict[
            str,
            asyncio.Task[DorisCapabilitySnapshot],
        ] = {}
        self._lock = asyncio.Lock()

    @property
    def capability_generation(self) -> int:
        return self._capability_generation

    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        providers = self._provider_registry.snapshot()
        snapshot = await self._ensure_fresh(
            domain.name,
            auth_context,
            providers,
        )
        return self._evaluator.evaluate(
            snapshot=snapshot,
            providers=providers,
            domain=domain,
            child=child,
            auth_context=auth_context,
        )

    async def resolve_domain(
        self,
        domain: DomainDefinition,
        children: Sequence[ChildToolDefinition],
        auth_context: Any | None,
    ) -> DomainAvailabilityResolution:
        """Resolve every authorized child against one immutable generation."""
        providers = self._provider_registry.snapshot()
        snapshot = await self._ensure_fresh(
            domain.name,
            auth_context,
            providers,
        )
        availabilities = MappingProxyType(
            {
                child.name: self._evaluator.evaluate(
                    snapshot=snapshot,
                    providers=providers,
                    domain=domain,
                    child=child,
                    auth_context=auth_context,
                )
                for child in children
            }
        )
        return DomainAvailabilityResolution(
            availabilities=availabilities,
            generation_fingerprint=snapshot.generation_fingerprint,
        )

    async def manifest_generation(
        self,
        domain: DomainDefinition,
        auth_context: Any | None,
    ) -> str:
        snapshot = await self.ensure_fresh(domain.name, auth_context)
        return snapshot.generation_fingerprint

    async def ensure_fresh(
        self,
        domain_name: str,
        auth_context: Any | None,
    ) -> DorisCapabilitySnapshot:
        providers = self._provider_registry.snapshot()
        return await self._ensure_fresh(
            domain_name,
            auth_context,
            providers,
        )

    async def _ensure_fresh(
        self,
        domain_name: str,
        auth_context: Any | None,
        providers: CapabilityProviderSnapshot,
    ) -> DorisCapabilitySnapshot:
        route = self._safe_route_identity(auth_context)
        capability_generation = self._capability_generation
        base_key = self._base_key(
            route.fingerprint,
            providers.generation,
            capability_generation,
        )
        base = self._base_cache.get(base_key)
        now = self._clock()
        if base is None or now >= base.expires_at:
            base = await self._singleflight(
                f"base:{base_key}",
                lambda: self._refresh_base(
                    base_key,
                    base,
                    auth_context,
                    providers.generation,
                    capability_generation,
                ),
            )

        domain_key = (
            f"{base.generation_fingerprint}:{domain_name}"
        )
        domain_snapshot = self._domain_cache.get(domain_key)
        if (
            domain_snapshot is not None
            and now < domain_snapshot.expires_at
        ):
            return domain_snapshot
        return await self._singleflight(
            f"domain:{domain_key}",
            lambda: self._refresh_domain(
                domain_key,
                base,
                domain_name,
                auth_context,
            ),
        )

    async def invalidate_route(self, route_fingerprint: str) -> None:
        """Drop one route's private snapshots without affecting other tenants."""
        async with self._lock:
            self._base_cache = {
                key: snapshot
                for key, snapshot in self._base_cache.items()
                if snapshot.route.fingerprint != route_fingerprint
            }
            self._domain_cache = {
                key: snapshot
                for key, snapshot in self._domain_cache.items()
                if snapshot.route.fingerprint != route_fingerprint
            }
            self._latest_domain = {
                key: snapshot
                for key, snapshot in self._latest_domain.items()
                if key[0] != route_fingerprint
            }

    async def bump_generation(self) -> int:
        """Invalidate all snapshots after a capability policy change."""
        async with self._lock:
            self._capability_generation += 1
            self._base_cache.clear()
            self._domain_cache.clear()
            self._latest_domain.clear()
            return self._capability_generation

    async def close(self) -> None:
        async with self._lock:
            tasks = tuple(self._inflight.values())
            self._inflight.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _refresh_base(
        self,
        requested_key: str,
        previous: DorisCapabilitySnapshot | None,
        auth_context: Any | None,
        provider_generation: str,
        capability_generation: int,
    ) -> DorisCapabilitySnapshot:
        try:
            snapshot = await self._detector.detect_base(
                auth_context,
                capability_generation=capability_generation,
                provider_generation=provider_generation,
            )
        except CapabilityRouteChangedError:
            now = self._clock()
            snapshot = _unknown_snapshot(
                route=self._safe_route_identity(auth_context),
                capability_generation=capability_generation,
                provider_generation=provider_generation,
                now=now,
            )
        except CapabilityDetectionError:
            now = self._clock()
            if previous is not None and now < previous.stale_until:
                snapshot = previous.as_stale(
                    retry_at=now
                    + timedelta(seconds=_STALE_RETRY_SECONDS)
                )
            else:
                route = self._safe_route_identity(auth_context)
                snapshot = _unknown_snapshot(
                    route=route,
                    capability_generation=capability_generation,
                    provider_generation=provider_generation,
                    now=now,
                )

        actual_key = self._base_key(
            snapshot.route.fingerprint,
            provider_generation,
            snapshot.capability_generation,
        )
        if snapshot.capability_generation == self._capability_generation:
            self._base_cache[actual_key] = snapshot
        return snapshot

    async def _refresh_domain(
        self,
        domain_key: str,
        base: DorisCapabilitySnapshot,
        domain_name: str,
        auth_context: Any | None,
    ) -> DorisCapabilitySnapshot:
        previous = self._latest_domain.get(
            (base.route.fingerprint, domain_name)
        )
        try:
            snapshot = await self._detector.detect_domain(
                base,
                domain_name,
                auth_context,
            )
        except CapabilityRouteChangedError:
            await self.invalidate_route(base.route.fingerprint)
            return await self.ensure_fresh(domain_name, auth_context)
        except CapabilityDetectionError:
            now = self._clock()
            if (
                previous is not None
                and previous.capability_generation
                == base.capability_generation
                and previous.provider_generation
                == base.provider_generation
                and now < previous.stale_until
            ):
                snapshot = previous.as_stale(
                    retry_at=now
                    + timedelta(seconds=_STALE_RETRY_SECONDS)
                )
            else:
                retry_at = min(
                    now + timedelta(seconds=_STALE_RETRY_SECONDS),
                    base.stale_until,
                )
                snapshot = DorisCapabilitySnapshot(
                    route=base.route,
                    capability_generation=base.capability_generation,
                    provider_generation=base.provider_generation,
                    cluster_fingerprint=base.cluster_fingerprint,
                    version_vector=base.version_vector,
                    deployment_mode=base.deployment_mode,
                    mixed_versions=base.mixed_versions,
                    probes=base.probes,
                    probed_domains=frozenset({domain_name}),
                    created_at=base.created_at,
                    expires_at=retry_at,
                    stale_until=base.stale_until,
                    stale=True,
                )
        if snapshot.capability_generation == self._capability_generation:
            self._domain_cache[domain_key] = snapshot
            self._latest_domain[
                (snapshot.route.fingerprint, domain_name)
            ] = snapshot
        return snapshot

    async def _singleflight(
        self,
        key: str,
        factory: Callable[
            [],
            Coroutine[Any, Any, DorisCapabilitySnapshot],
        ],
    ) -> DorisCapabilitySnapshot:
        async with self._lock:
            task = self._inflight.get(key)
            if task is None:
                task = asyncio.create_task(factory())
                self._inflight[key] = task
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                async with self._lock:
                    if self._inflight.get(key) is task:
                        self._inflight.pop(key, None)

    def _base_key(
        self,
        route_fingerprint: str,
        provider_generation: str,
        capability_generation: int,
    ) -> str:
        return (
            f"{route_fingerprint}:"
            f"{capability_generation}:"
            f"{provider_generation}"
        )

    def _safe_route_identity(
        self,
        auth_context: Any | None,
    ) -> DorisRouteIdentity:
        try:
            route = self._detector.route_identity(auth_context)
        except Exception:
            route = None
        if isinstance(route, DorisRouteIdentity):
            return route

        principal_material = "\x1f".join(
            str(getattr(auth_context, name, "") or "")
            for name in (
                "auth_method",
                "token_id",
                "user_id",
                "oauth_token_id",
                "pool_key",
            )
        )
        fingerprint = hashlib.sha256(
            principal_material.encode("utf-8")
        ).hexdigest()
        return DorisRouteIdentity(
            route_key="unresolved",
            generation=0,
            endpoint_fingerprint=fingerprint,
            fingerprint=f"unresolved-{fingerprint}",
        )


def _unknown_snapshot(
    *,
    route: Any,
    capability_generation: int,
    provider_generation: str,
    now: datetime,
) -> DorisCapabilitySnapshot:
    unknown_version = parse_doris_version_comment("")
    return DorisCapabilitySnapshot(
        route=route,
        capability_generation=capability_generation,
        provider_generation=provider_generation,
        cluster_fingerprint=route.endpoint_fingerprint,
        version_vector=DorisClusterVersionVector(
            master_fe=unknown_version,
        ),
        deployment_mode="unknown",
        mixed_versions=False,
        probes={
            "version_probe_completed": CapabilityProbeEvidence(
                probe_id="version_probe_completed",
                status=CapabilityProbeStatus.UNKNOWN,
                reason_code="CAPABILITY_SNAPSHOT_UNAVAILABLE",
            )
        },
        probed_domains=frozenset(),
        created_at=now,
        expires_at=now + timedelta(seconds=30),
        stale_until=now + timedelta(seconds=30),
    )


def _detected_versions(
    snapshot: DorisCapabilitySnapshot,
) -> dict[str, tuple[str, ...]]:
    def values(versions: tuple[Any, ...]) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                value
                for version in versions
                if (value := version.normalized or version.raw)
            )
        )

    detected: dict[str, tuple[str, ...]] = {}
    master = values((snapshot.version_vector.master_fe,))
    followers = values(snapshot.version_vector.follower_fes)
    backends = values(snapshot.version_vector.backends)
    if master:
        detected["master_fe"] = master
    if followers:
        detected["follower_fe"] = followers
    if backends:
        detected["be"] = backends
    return detected


def _ordered_unique(values: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value for value in values if value))


def _normalized_source_ids(values: tuple[str, ...]) -> tuple[str, ...]:
    return _ordered_unique([value.lower() for value in values])


def _public_evidence_source_id(value: str) -> str:
    """Normalize private probe keys into public Manifest identifiers."""
    normalized = re.sub(r"[^a-z0-9_]+", "_", value.lower()).strip("_")
    return normalized or "runtime_probe"


def _select_failure(
    failures: list[_CandidateFailure],
) -> _CandidateFailure:
    if not failures:
        return _CandidateFailure(
            status=AvailabilityStatus.UNKNOWN,
            reason_code="CAPABILITY_SNAPSHOT_UNAVAILABLE",
            evidence_sources=("catalog_contract",),
            limitations=(),
        )
    priority = {
        AvailabilityStatus.MISCONFIGURED: 4,
        AvailabilityStatus.DEGRADED: 3,
        AvailabilityStatus.UNKNOWN: 2,
        AvailabilityStatus.UNAVAILABLE: 1,
        AvailabilityStatus.AVAILABLE: 0,
    }
    return max(failures, key=lambda failure: priority[failure.status])


__all__ = [
    "CapabilityEvaluator",
    "CapabilityProviderEvidence",
    "CapabilityProviderRegistry",
    "CapabilityProviderSnapshot",
    "CapabilityRegistry",
]

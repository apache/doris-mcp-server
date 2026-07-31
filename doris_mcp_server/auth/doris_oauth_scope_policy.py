#!/usr/bin/env python3
"""Scope issuance policy for Doris-backed OAuth."""

from collections.abc import Iterable
from typing import TYPE_CHECKING

from ..tools.domain_catalog import FORMAL_CHILD_FEATURE_IDS
from .doris_oauth_types import TokenEndpointError

if TYPE_CHECKING:
    from ..utils.config import SecurityConfig

BASE_DORIS_OAUTH_SCOPES = frozenset({"tool:list"})
RESOURCE_SCOPES = frozenset({"resource:list", "resource:read"})
SEMANTIC_SCOPES = frozenset({"semantic:read"})


def child_call_scope(feature_id: str) -> str:
    """Return the canonical execution scope for one formal child feature."""
    domain, child = feature_id.split(".", 1)
    return f"child:call:{domain}:{child}"


def child_discovery_scope(feature_id: str) -> str:
    """Return the canonical discovery-only scope for one formal child feature."""
    domain, child = feature_id.split(".", 1)
    return f"child:discover:{domain}:{child}"


CHILD_CALL_SCOPES = frozenset(
    child_call_scope(feature_id)
    for feature_id in FORMAL_CHILD_FEATURE_IDS
)
CHILD_DISCOVERY_SCOPES = frozenset(
    child_discovery_scope(feature_id)
    for feature_id in FORMAL_CHILD_FEATURE_IDS
)
KNOWN_CHILD_SCOPES = CHILD_CALL_SCOPES | CHILD_DISCOVERY_SCOPES

FORBIDDEN_DORIS_OAUTH_SCOPES = frozenset(
    {
        "*",
        "scope:admin",
        "scope:service_account",
        "scope:profile:read",
        "scope:monitoring:read",
        "scope:adbc:execute",
        "scope:audit:read",
        "scope:governance:read",
        "scope:performance:read",
        "prompt:list",
        "prompt:get",
    }
)


class DorisOAuthScopePolicy:
    """Doris OAuth scope issuance policy.

    Doris OAuth binds runtime database access to the logged-in Doris user.
    Scopes are therefore a client capability envelope, not a replacement for
    Doris RBAC. When no scope is requested, grant the configured safe server
    allowlist so standard MCP clients can work without hand-authored scopes.
    """

    def __init__(
        self,
        security_config: "SecurityConfig | None" = None,
        server_allowed_scopes: set[str] | None = None,
        *,
        semantic_read_enabled: bool = False,
    ) -> None:
        if server_allowed_scopes is None:
            self.server_allowed_scopes = self._build_server_allowed_scopes(
                security_config,
                semantic_read_enabled=semantic_read_enabled,
            )
        else:
            self.server_allowed_scopes = set(server_allowed_scopes)
        self.server_default_scopes = {
            scope
            for scope in self.server_allowed_scopes
            if not scope.startswith("child:discover:")
        }
        self.forbidden_scopes = set(FORBIDDEN_DORIS_OAUTH_SCOPES)
        self.known_scopes = (
            set(BASE_DORIS_OAUTH_SCOPES)
            | set(RESOURCE_SCOPES)
            | set(SEMANTIC_SCOPES)
            | set(KNOWN_CHILD_SCOPES)
            | set(FORBIDDEN_DORIS_OAUTH_SCOPES)
        )

    def _build_server_allowed_scopes(
        self,
        security_config: "SecurityConfig | None",
        *,
        semantic_read_enabled: bool,
    ) -> set[str]:
        allowed = set(BASE_DORIS_OAUTH_SCOPES)
        allowed.update(RESOURCE_SCOPES)
        if semantic_read_enabled:
            allowed.update(SEMANTIC_SCOPES)

        if getattr(
            security_config,
            "doris_oauth_child_tools_enabled",
            False,
        ):
            feature_ids = self._configured_feature_ids(
                getattr(
                    security_config,
                    "doris_oauth_child_tool_allowlist",
                    FORMAL_CHILD_FEATURE_IDS,
                )
            )
            formal_features = set(FORMAL_CHILD_FEATURE_IDS)
            for feature_id in feature_ids:
                if feature_id not in formal_features:
                    continue
                allowed.add(child_call_scope(feature_id))
                allowed.add(child_discovery_scope(feature_id))

        return allowed

    def _configured_feature_ids(
        self, configured_features: str | Iterable[object]
    ) -> list[str]:
        if isinstance(configured_features, str):
            return [
                part.strip()
                for part in configured_features.split(",")
                if part.strip()
            ]
        return [
            str(feature).strip()
            for feature in configured_features
            if str(feature).strip()
        ]

    def parse_scope(self, scope: str | None) -> tuple[str, ...]:
        if scope is None:
            return ()
        return tuple(part for part in str(scope).split() if part)

    def grant_client_scopes(self, requested_scope: str | None, *, explicit: bool) -> tuple[str, ...]:
        requested = self.parse_scope(requested_scope)
        return self._grant(requested, explicit=explicit, client_allowed_scopes=self.server_allowed_scopes)

    def grant_authorized_scopes(
        self,
        requested_scope: str | None,
        *,
        client_allowed_scopes: tuple[str, ...],
        explicit: bool,
    ) -> tuple[str, ...]:
        requested = self.parse_scope(requested_scope)
        return self._grant(
            requested,
            explicit=explicit,
            client_allowed_scopes=set(client_allowed_scopes),
        )

    def validate_refresh_scope(
        self,
        requested_scope: str | None,
        original_scopes: tuple[str, ...],
    ) -> tuple[str, ...]:
        requested = self.parse_scope(requested_scope)
        if not requested:
            return original_scopes
        original = set(original_scopes)
        requested_set = set(requested)
        if not requested_set <= original:
            raise TokenEndpointError(
                "invalid_scope",
                "Requested scope cannot exceed the original grant",
                status_code=400,
            )
        return tuple(scope for scope in original_scopes if scope in requested_set)

    def _grant(
        self,
        requested: tuple[str, ...],
        *,
        explicit: bool,
        client_allowed_scopes: set[str],
    ) -> tuple[str, ...]:
        requested_set = set(requested)
        if not requested_set:
            requested_set = set(self.server_default_scopes)

        unknown = requested_set - self.known_scopes
        forbidden = requested_set & self.forbidden_scopes
        not_allowed = requested_set - self.server_allowed_scopes
        client_denied = requested_set - client_allowed_scopes

        if explicit and (unknown or forbidden or not_allowed or client_denied):
            raise TokenEndpointError(
                "invalid_scope",
                "Requested scope is not allowed",
                status_code=400,
            )

        granted = requested_set & self.server_allowed_scopes & client_allowed_scopes
        if not granted:
            raise TokenEndpointError(
                "invalid_scope",
                "Requested scope is not allowed",
                status_code=400,
            )
        return tuple(sorted(granted))

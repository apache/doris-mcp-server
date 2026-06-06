#!/usr/bin/env python3
"""Scope issuance policy for Doris-backed OAuth."""

from .doris_oauth_types import TokenEndpointError


BASE_DORIS_OAUTH_SCOPES = frozenset({"tool:list"})
RESOURCE_SCOPES = frozenset({"resource:list", "resource:read"})

DORIS_OAUTH_METADATA_TOOLS = (
    "get_db_list",
    "get_db_table_list",
    "get_table_schema",
    "get_table_comment",
    "get_table_column_comments",
    "get_table_indexes",
    "get_catalog_list",
)

METADATA_DB_SCOPES = frozenset(
    {
        f"tool:call:{tool_name}" for tool_name in DORIS_OAUTH_METADATA_TOOLS
    }
)

QUERY_DB_SCOPES = frozenset({"tool:call:exec_query"})
EXPLAIN_DB_SCOPES = frozenset({"tool:call:get_sql_explain"})
PENDING_DB_SCOPES = METADATA_DB_SCOPES | QUERY_DB_SCOPES | EXPLAIN_DB_SCOPES
TOOL_SCOPE_ALIASES = {
    tool_name: f"tool:call:{tool_name}"
    for tool_name in (*DORIS_OAUTH_METADATA_TOOLS, "exec_query", "get_sql_explain")
}

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

    def __init__(self, security_config=None, server_allowed_scopes: set[str] | None = None):
        if server_allowed_scopes is None:
            self.server_allowed_scopes = self._build_server_allowed_scopes(security_config)
        else:
            self.server_allowed_scopes = set(server_allowed_scopes)
        self.server_default_scopes = set(self.server_allowed_scopes)
        self.forbidden_scopes = set(FORBIDDEN_DORIS_OAUTH_SCOPES)
        self.known_scopes = (
            set(BASE_DORIS_OAUTH_SCOPES)
            | set(RESOURCE_SCOPES)
            | set(PENDING_DB_SCOPES)
            | set(FORBIDDEN_DORIS_OAUTH_SCOPES)
        )

    def _build_server_allowed_scopes(self, security_config) -> set[str]:
        allowed = set(BASE_DORIS_OAUTH_SCOPES)
        allowed.update(RESOURCE_SCOPES)

        if getattr(security_config, "doris_oauth_db_tools_enabled", False):
            tool_names = self._configured_tool_names(
                getattr(
                    security_config,
                    "doris_oauth_db_tool_allowlist",
                    DORIS_OAUTH_METADATA_TOOLS,
                )
            )
            metadata_tool_set = set(DORIS_OAUTH_METADATA_TOOLS)
            allowed.update(f"tool:call:{tool_name}" for tool_name in tool_names if tool_name in metadata_tool_set)

        if getattr(security_config, "doris_oauth_query_tools_enabled", False):
            tool_names = self._configured_tool_names(
                getattr(security_config, "doris_oauth_query_tool_allowlist", ("exec_query",))
            )
            if "exec_query" in tool_names:
                allowed.update(QUERY_DB_SCOPES)

        if getattr(security_config, "doris_oauth_explain_tools_enabled", False):
            tool_names = self._configured_tool_names(
                getattr(security_config, "doris_oauth_explain_tool_allowlist", ("get_sql_explain",))
            )
            if "get_sql_explain" in tool_names:
                allowed.update(EXPLAIN_DB_SCOPES)

        return allowed

    def _configured_tool_names(self, configured_tools) -> list[str]:
        if isinstance(configured_tools, str):
            return [part.strip() for part in configured_tools.split(",") if part.strip()]
        return [str(tool).strip() for tool in configured_tools if str(tool).strip()]

    def parse_scope(self, scope: str | None) -> tuple[str, ...]:
        if scope is None:
            return ()
        return tuple(
            TOOL_SCOPE_ALIASES.get(part, part)
            for part in str(scope).split()
            if part
        )

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

#!/usr/bin/env python3
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
"""
Doris Configuration Management Module
Implements configuration loading, validation and management functionality
"""

import json
import logging
import multiprocessing
import os
import secrets
from dataclasses import dataclass, field
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dotenv import load_dotenv

from .._version import __version__
from ..result_limits import (
    ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS,
    ABSOLUTE_MAX_RESULT_BYTES,
    ABSOLUTE_MAX_RESULT_ROWS,
    DEFAULT_MAX_RESULT_BYTES,
    DEFAULT_MAX_RESULT_ROWS,
    DEFAULT_RESULT_ROWS,
    MIN_RESULT_BYTES,
)
from ..tools.admin_domain import administration_config_errors
from ..tools.tool_provider import (
    ToolProviderError,
    normalize_tool_provider_names,
)
from ..tools.tool_registry import (
    DORIS_OAUTH_EXPLAIN_TOOL_SET,
    DORIS_OAUTH_METADATA_TOOL_NAMES,
    DORIS_OAUTH_METADATA_TOOL_SET,
    DORIS_OAUTH_QUERY_TOOL_SET,
)
from .logger import get_logger
from .secret_policy import (
    is_static_token_environment_variable,
    normalize_token_digest,
    normalize_token_hash_algorithm,
    validate_high_entropy_secret,
)


class AuthConfigError(ValueError):
    """Raised when authentication configuration is inconsistent."""


DORIS_OAUTH_METADATA_TOOL_ALLOWLIST_DEFAULT = list(
    DORIS_OAUTH_METADATA_TOOL_NAMES
)


def _default_doris_oauth_child_tool_allowlist() -> list[str]:
    """Load formal child feature IDs without creating a config import cycle."""
    from ..tools.domain_catalog import FORMAL_CHILD_FEATURE_IDS

    return list(FORMAL_CHILD_FEATURE_IDS)


EXTERNAL_OAUTH_SECURITY_LEVELS = frozenset(
    {"public", "internal", "confidential", "secret"}
)
DEFAULT_EXTERNAL_OAUTH_ROLE_SECURITY_LEVELS = {
    "admin": "secret",
    "administrator": "secret",
    "data_admin": "secret",
    "super_admin": "secret",
    "data_analyst": "confidential",
    "developer": "confidential",
    "manager": "confidential",
}
DEFAULT_EXTERNAL_OAUTH_ROLE_PERMISSIONS = {
    "admin": ["admin", "read_data", "write_data", "manage_users"],
    "administrator": ["admin", "read_data", "write_data", "manage_users"],
    "data_admin": ["admin", "read_data", "write_data"],
    "super_admin": [
        "admin",
        "read_data",
        "write_data",
        "manage_users",
        "system_admin",
    ],
    "data_analyst": ["read_data", "query_database"],
    "developer": ["read_data", "query_database", "debug"],
    "viewer": ["read_data"],
    "user": ["read_data"],
    "oauth_user": ["read_data"],
}


@dataclass(frozen=True)
class ConfigValue:
    """Configuration value with source metadata."""

    value: Any
    source: str = "default"
    explicit: bool = False


@dataclass(frozen=True)
class AuthConfigInputs:
    """Authentication-related config inputs before normalization."""

    enable_token_auth: ConfigValue
    enable_jwt_auth: ConfigValue
    enable_external_oauth_auth: ConfigValue
    oauth_enabled: ConfigValue
    enable_doris_oauth_auth: ConfigValue
    legacy_auth_type: ConfigValue
    transport: ConfigValue
    workers: ConfigValue


@dataclass(frozen=True)
class EffectiveAuthConfig:
    """Normalized authentication configuration used by runtime code."""

    enable_token_auth: bool
    enable_jwt_auth: bool
    enable_external_oauth_auth: bool
    enable_doris_oauth_auth: bool
    auth_methods: tuple[str, ...]
    oauth_discovery_mode: str
    transport: str
    requested_workers: int
    effective_workers: int
    legacy_auth_type: str
    auth_config_warnings: tuple[str, ...] = ()
    doris_oauth_base_url: str = ""
    external_oauth_issuer: str = ""
    external_oauth_resource: str = ""
    external_oauth_scopes: tuple[str, ...] = ()
    external_oauth_required_scopes: tuple[str, ...] = ()
    source_summary: dict[str, str] = field(default_factory=dict)


def _str_to_bool(value: Any) -> bool:
    """Convert common config values to bool."""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or str(value).strip() == "":
        return default
    return int(value)


def _env_optional_int(name: str, default: int | None) -> int | None:
    value = os.getenv(name)
    if value is None:
        return default
    value = str(value).strip()
    if value == "":
        return None
    return int(value)


def _env_csv(name: str, default: list[str]) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default
    return [part.strip() for part in value.split(",") if part.strip()]


def _env_json_string_map(
    name: str,
    default: dict[str, str],
) -> dict[str, str]:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AuthConfigError(f"{name} must be a valid JSON object") from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str) or not isinstance(item, str)
        for key, item in parsed.items()
    ):
        raise AuthConfigError(f"{name} must map strings to strings")
    return {
        key.strip(): item.strip()
        for key, item in parsed.items()
    }


def _env_json_string_list_map(
    name: str,
    default: dict[str, list[str]],
) -> dict[str, list[str]]:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise AuthConfigError(f"{name} must be a valid JSON object") from exc
    if not isinstance(parsed, dict) or any(
        not isinstance(key, str)
        or not isinstance(items, list)
        or any(not isinstance(item, str) for item in items)
        for key, items in parsed.items()
    ):
        raise AuthConfigError(f"{name} must map strings to arrays of strings")
    return {
        key.strip(): [item.strip() for item in items]
        for key, items in parsed.items()
    }


def _coerce_csv_config(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return [str(part).strip() for part in value if str(part).strip()]


def _coerce_scope_config(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [
            part
            for part in value.replace(",", " ").split()
            if part
        ]
    return [str(part).strip() for part in value if str(part).strip()]


def _validate_doris_oauth_metadata_tool_allowlist(tools: Any) -> list[str]:
    """Validate the Phase 4 metadata-only Doris OAuth tool allowlist."""
    normalized = []
    seen = set()
    invalid = []
    for tool in _coerce_csv_config(tools):
        tool_name = str(tool).strip()
        if not tool_name:
            continue
        if tool_name not in DORIS_OAUTH_METADATA_TOOL_SET:
            invalid.append(tool_name)
            continue
        if tool_name not in seen:
            normalized.append(tool_name)
            seen.add(tool_name)

    if invalid:
        invalid_list = ", ".join(sorted(set(invalid)))
        raise AuthConfigError(
            "DORIS_OAUTH_DB_TOOL_ALLOWLIST can only contain Phase 4 metadata tools; "
            f"invalid entries: {invalid_list}"
        )
    return normalized


def _is_loopback_url(url: str) -> bool:
    parsed = urlparse(url)
    return (parsed.hostname or "").lower() in {"127.0.0.1", "localhost", "::1"}


def _validate_external_oauth_url(
    value: str,
    *,
    setting: str,
    allow_query: bool = False,
) -> str:
    normalized = str(value or "").strip()
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        raise AuthConfigError(f"{setting} must be an absolute URL")
    if parsed.fragment:
        raise AuthConfigError(f"{setting} must not contain a fragment")
    if parsed.query and not allow_query:
        raise AuthConfigError(f"{setting} must not contain a query")
    if parsed.scheme == "http":
        if not _is_loopback_url(normalized):
            raise AuthConfigError(f"{setting} must use HTTPS outside loopback")
    elif parsed.scheme != "https":
        raise AuthConfigError(f"{setting} must use HTTP or HTTPS")
    return normalized


def _is_loopback_bind_host(host: str) -> bool:
    """Return whether a bind host is explicitly confined to loopback."""
    normalized = str(host or "").strip().lower()
    if normalized in {"localhost", "localhost."}:
        return True
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_http_bind_auth_policy(
    *,
    transport: str,
    host: str,
    auth_methods: tuple[str, ...],
    allow_unauthenticated_non_loopback: bool,
) -> str | None:
    """Reject unauthenticated HTTP exposure outside explicit loopback binds."""
    if str(transport).strip().lower() != "http":
        return None
    if auth_methods or _is_loopback_bind_host(host):
        return None

    bind_host = str(host or "").strip() or "<empty>"
    if allow_unauthenticated_non_loopback:
        return (
            "DANGEROUS: ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true permits "
            f"unauthenticated HTTP exposure on non-loopback host '{bind_host}'"
        )

    raise AuthConfigError(
        f"Refusing unauthenticated HTTP bind to non-loopback host '{bind_host}'. "
        "Enable an authentication method or bind to 127.0.0.1, localhost, or ::1. "
        "ALLOW_UNAUTHENTICATED_NON_LOOPBACK=true is an explicit dangerous override."
    )


def _ensure_source_maps(config: Any) -> None:
    if not hasattr(config, "_explicit_sources"):
        config._explicit_sources = {}


def _mark_source(config: Any, field_name: str, source: str) -> None:
    _ensure_source_maps(config)
    config._explicit_sources[field_name] = source


def _config_value(config: Any, field_name: str, value: Any) -> ConfigValue:
    _ensure_source_maps(config)
    source = config._explicit_sources.get(field_name, "default")
    return ConfigValue(value=value, source=source, explicit=source != "default")


@dataclass
class DatabaseConfig:
    """Database connection configuration"""

    host: str = "localhost"
    # Ordered FE MySQL endpoints for one Doris cluster. When populated, the
    # connection manager tries these hosts in order and keeps ``host`` as the
    # backward-compatible primary endpoint.
    hosts: list[str] = field(default_factory=list)
    port: int = 9030
    user: str = "root"
    password: str = ""
    database: str = "information_schema"
    charset: str = "UTF8"

    # FE HTTP API endpoint for profile and other HTTP APIs. An empty host keeps
    # backward compatibility by falling back to the SQL host.
    fe_http_host: str = ""
    fe_http_hosts: list[str] = field(default_factory=list)
    fe_http_port: int = 8030

    # BE HTTP nodes must be configured explicitly. SQL metadata is not trusted
    # as an outbound HTTP allowlist.
    be_hosts: list[str] = field(default_factory=list)
    be_webserver_port: int = 8040

    # Shared FE/BE HTTP safety limits. Runtime enforcement also applies hard
    # caps so unsafe config values cannot remove the boundary.
    http_connect_timeout_seconds: float = 3.0
    http_read_timeout_seconds: float = 15.0
    http_total_timeout_seconds: float = 30.0
    http_max_response_bytes: int = 4 * 1024 * 1024

    # Arrow Flight SQL Configuration (Required for ADBC tools)
    fe_arrow_flight_sql_port: int | None = None
    be_arrow_flight_sql_port: int | None = None

    # Connection pool configuration
    # Note: min_connections is fixed at 0 to avoid at_eof connection issues
    # This prevents pre-creation of connections which can cause state problems
    _min_connections: int = field(default=0, init=False)  # Internal use only, always 0
    max_connections: int = 20
    connection_timeout: int = 30
    health_check_interval: int = 60
    max_connection_age: int = 3600

    @property
    def min_connections(self) -> int:
        """Minimum connections is always 0 to prevent at_eof issues"""
        return self._min_connections


@dataclass
class SecurityConfig:
    """Security configuration"""

    # Independent authentication switches - any one enabled allows that method
    enable_token_auth: bool = False  # Enable token-based authentication (default: disabled)
    enable_jwt_auth: bool = False    # Enable JWT authentication (default: disabled)
    enable_oauth_auth: bool = False  # Enable OAuth 2.0/OIDC authentication (default: disabled)
    enable_doris_oauth_auth: bool = False  # Enable Doris-backed OAuth (default: disabled)
    allow_unauthenticated_non_loopback: bool = False
    doris_oauth_base_url: str = ""  # Public base URL for future Doris OAuth metadata
    doris_oauth_child_tools_enabled: bool = False
    doris_oauth_child_tool_allowlist: list[str] = field(
        default_factory=_default_doris_oauth_child_tool_allowlist
    )
    doris_oauth_db_tools_enabled: bool = False
    doris_oauth_db_tool_allowlist: list[str] = field(
        default_factory=lambda: list(DORIS_OAUTH_METADATA_TOOL_ALLOWLIST_DEFAULT)
    )
    doris_oauth_query_tools_enabled: bool = False
    doris_oauth_query_tool_allowlist: list[str] = field(default_factory=lambda: ["exec_query"])
    doris_oauth_explain_tools_enabled: bool = False
    doris_oauth_explain_tool_allowlist: list[str] = field(default_factory=lambda: ["get_sql_explain"])
    doris_oauth_access_token_expire_seconds: int = 900
    doris_oauth_refresh_token_expire_seconds: int = 86400
    doris_oauth_auth_code_expire_seconds: int = 300
    doris_oauth_gc_interval_seconds: int = 60
    doris_oauth_idle_timeout_seconds: int | None = None
    doris_oauth_login_page_title: str = "Doris MCP Login"
    doris_oauth_allowed_redirect_uris: list[str] = field(default_factory=list)
    doris_oauth_clients_file: str = ""
    doris_oauth_cimd_fetch_timeout_seconds: int = 5
    doris_oauth_cimd_max_document_bytes: int = 5120
    doris_oauth_cimd_default_cache_seconds: int = 300
    doris_oauth_cimd_max_cache_seconds: int = 3600
    doris_oauth_cimd_max_clients: int = 1000
    doris_oauth_dynamic_client_registration_mode: str = "auto"
    enable_doris_oauth_production_dcr: bool = False
    enable_doris_oauth_production_wildcard_redirects: bool = False
    doris_oauth_allow_insecure_http: bool = False
    doris_oauth_trust_proxy_headers: bool = False
    doris_oauth_trusted_proxy_cidrs: list[str] = field(default_factory=list)
    doris_oauth_rate_limit_window_seconds: int = 300
    doris_oauth_login_rate_limit_per_ip: int = 20
    doris_oauth_login_rate_limit_per_user: int = 10
    doris_oauth_login_rate_limit_per_client: int = 30
    doris_oauth_login_rate_limit_per_txn: int = 5
    doris_oauth_dcr_rate_limit_per_ip: int = 30
    doris_oauth_authorize_rate_limit_per_ip: int = 120
    doris_oauth_token_rate_limit_per_ip: int = 120
    doris_oauth_token_rate_limit_per_client: int = 240
    doris_oauth_revoke_rate_limit_per_ip: int = 120
    doris_oauth_revoke_rate_limit_per_client: int = 240
    doris_oauth_api_auth_token_rate_limit_per_ip: int = 20
    doris_oauth_api_auth_token_rate_limit_per_user: int = 10
    doris_oauth_api_auth_refresh_rate_limit_per_ip: int = 120
    doris_oauth_api_auth_refresh_rate_limit_per_client: int = 240
    doris_oauth_dcr_max_clients: int = 1000
    doris_oauth_dcr_client_ttl_seconds: int = 86400

    # Legacy configuration (kept for backward compatibility)
    auth_type: str = "token"  # jwt, token, basic, oauth (deprecated: use individual switches)
    token_secret: str = ""  # Deprecated legacy field; no usable default secret
    token_expiry: int = 3600

    # Enhanced Token Authentication Configuration
    token_file_path: str = "tokens.json"  # Path to token configuration file
    enable_token_expiry: bool = True  # Enable token expiration
    default_token_expiry_hours: int = 24 * 30  # Default expiry: 30 days
    token_hash_algorithm: str = "sha256"  # Token hashing algorithm: sha256, sha512
    token_db_validation_ttl_seconds: int = 30

    # Token Management Security (New in v0.6.0)
    enable_http_token_management: bool = False  # Enable HTTP token management endpoints (default: disabled for security)
    token_management_admin_token: str = ""  # Admin token for token management endpoints (required if HTTP management enabled)
    token_management_allowed_ips: list[str] = field(default_factory=lambda: ["127.0.0.1", "::1", "localhost"])  # Allowed IPs for token management
    require_admin_auth: bool = True  # Require admin authentication for token management (default: true)

    # JWT Configuration
    jwt_algorithm: str = "RS256"  # RS256, ES256, HS256
    jwt_issuer: str = "doris-mcp-server"
    jwt_audience: str = "doris-mcp-client"
    jwt_private_key_path: str = ""
    jwt_public_key_path: str = ""
    jwt_secret_key: str = ""  # Only used for HS256 algorithm
    jwt_access_token_expiry: int = 3600  # 1 hour
    jwt_refresh_token_expiry: int = 86400  # 24 hours
    enable_token_refresh: bool = True
    enable_token_revocation: bool = True
    key_rotation_interval: int = 30 * 24 * 3600  # 30 days in seconds

    # JWT Security Features
    jwt_require_iat: bool = True  # Require "issued at" claim
    jwt_require_exp: bool = True  # Require "expires at" claim
    jwt_require_nbf: bool = False  # Require "not before" claim
    jwt_leeway: int = 10  # Clock skew tolerance in seconds
    jwt_verify_signature: bool = True  # Verify JWT signature
    jwt_verify_audience: bool = True  # Verify audience claim
    jwt_verify_issuer: bool = True  # Verify issuer claim

    # SQL security configuration
    enable_security_check: bool = True  # Main switch: whether to enable SQL security check
    blocked_keywords: list[str] = field(
        default_factory=lambda: [
            # DDL Operations (Data Definition Language)
            "DROP",
            "CREATE",
            "ALTER",
            "TRUNCATE",
            # DML Operations (Data Manipulation Language)
            "DELETE",
            "INSERT",
            "UPDATE",
            # DCL Operations (Data Control Language)
            "GRANT",
            "REVOKE",
            # System Operations
            "EXEC",
            "EXECUTE",
            "SHUTDOWN",
            "KILL",
        ]
    )
    max_query_complexity: int = 100
    max_result_rows: int = 10000

    # Sensitive table configuration
    sensitive_tables: dict[str, str] = field(default_factory=dict)

    # Data masking configuration
    enable_masking: bool = True
    masking_rules: list[dict[str, Any]] = field(default_factory=list)

    # OAuth 2.0/OIDC Configuration
    oauth_enabled: bool = False
    oauth_provider: str = ""  # 'google', 'microsoft', 'github', 'custom'
    oauth_client_id: str = ""
    oauth_client_secret: str = ""
    oauth_redirect_uri: str = "http://localhost:3000/auth/callback"

    # OIDC Discovery
    oidc_discovery_url: str = ""  # e.g., https://accounts.google.com/.well-known/openid_configuration
    oauth_authorization_endpoint: str = ""
    oauth_token_endpoint: str = ""
    oauth_introspection_endpoint: str = ""
    oauth_introspection_client_id: str = ""
    oauth_introspection_client_secret: str = ""
    oauth_userinfo_endpoint: str = ""
    oauth_jwks_uri: str = ""
    oauth_issuer: str = ""
    oauth_resource: str = ""
    oauth_audience: str = ""

    # OAuth Scopes and Settings
    oauth_scopes: list[str] = field(default_factory=list)
    oauth_required_scopes: list[str] = field(default_factory=list)
    oauth_state_expiry: int = 600  # State parameter expiry in seconds (10 minutes)
    oauth_pkce_enabled: bool = True  # Enable PKCE for better security
    oauth_nonce_enabled: bool = True  # Enable nonce for OIDC

    # User Mapping Configuration
    oauth_user_id_claim: str = "sub"  # JWT claim for user ID
    oauth_email_claim: str = "email"
    oauth_name_claim: str = "name"
    oauth_roles_claim: str = "roles"  # Custom claim for roles
    oauth_default_roles: list[str] = field(default_factory=lambda: ["oauth_user"])
    oauth_default_security_level: str = "internal"
    oauth_trusted_domains: list[str] = field(default_factory=list)
    oauth_trusted_domain_security_level: str = "confidential"
    oauth_role_security_levels: dict[str, str] = field(
        default_factory=lambda: dict(DEFAULT_EXTERNAL_OAUTH_ROLE_SECURITY_LEVELS)
    )
    oauth_role_permissions: dict[str, list[str]] = field(
        default_factory=lambda: {
            role: list(permissions)
            for role, permissions in DEFAULT_EXTERNAL_OAUTH_ROLE_PERMISSIONS.items()
        }
    )
    oauth_default_permissions: list[str] = field(
        default_factory=lambda: ["read_data"]
    )

    def __post_init__(self) -> None:
        """Initialize default OAuth scopes based on provider"""
        if not self.oauth_scopes and self.oauth_provider:
            if self.oauth_provider == "google":
                self.oauth_scopes = ["openid", "email", "profile"]
            elif self.oauth_provider == "microsoft":
                self.oauth_scopes = ["openid", "profile", "email", "User.Read"]
            elif self.oauth_provider == "github":
                self.oauth_scopes = ["user:email", "read:user"]
            else:
                self.oauth_scopes = ["openid", "email", "profile"]


def _normalize_external_oauth_authorization_config(
    security: SecurityConfig,
) -> None:
    """Normalize and validate external OAuth authorization mappings."""

    def normalize_security_level(value: Any, setting: str) -> str:
        normalized = str(value or "").strip().lower()
        if normalized not in EXTERNAL_OAUTH_SECURITY_LEVELS:
            allowed = ", ".join(sorted(EXTERNAL_OAUTH_SECURITY_LEVELS))
            raise AuthConfigError(f"{setting} must be one of {allowed}")
        return normalized

    security.oauth_default_security_level = normalize_security_level(
        security.oauth_default_security_level,
        "OAUTH_DEFAULT_SECURITY_LEVEL",
    )
    security.oauth_trusted_domain_security_level = normalize_security_level(
        security.oauth_trusted_domain_security_level,
        "OAUTH_TRUSTED_DOMAIN_SECURITY_LEVEL",
    )

    if not isinstance(security.oauth_trusted_domains, list) or any(
        not isinstance(domain, str)
        for domain in security.oauth_trusted_domains
    ):
        raise AuthConfigError(
            "OAUTH_TRUSTED_DOMAINS must be a comma-separated list of domains"
        )
    normalized_domains = []
    for configured_domain in security.oauth_trusted_domains:
        domain = str(configured_domain).strip().lower().removeprefix("@")
        if (
            not domain
            or "@" in domain
            or any(character.isspace() for character in domain)
        ):
            raise AuthConfigError(
                "OAUTH_TRUSTED_DOMAINS must contain exact email domains"
            )
        if domain not in normalized_domains:
            normalized_domains.append(domain)
    security.oauth_trusted_domains = normalized_domains

    normalized_role_levels: dict[str, str] = {}
    if not isinstance(security.oauth_role_security_levels, dict):
        raise AuthConfigError(
            "OAUTH_ROLE_SECURITY_LEVELS_JSON must be a JSON object"
        )
    for configured_role, configured_level in (
        security.oauth_role_security_levels.items()
    ):
        if not isinstance(configured_role, str) or not isinstance(
            configured_level,
            str,
        ):
            raise AuthConfigError(
                "OAUTH_ROLE_SECURITY_LEVELS_JSON must map strings to strings"
            )
        role = configured_role.strip().lower()
        if not role:
            raise AuthConfigError(
                "OAUTH_ROLE_SECURITY_LEVELS_JSON contains an empty role"
            )
        normalized_role_levels[role] = normalize_security_level(
            configured_level,
            f"OAUTH_ROLE_SECURITY_LEVELS_JSON[{role}]",
        )
    security.oauth_role_security_levels = normalized_role_levels

    normalized_role_permissions: dict[str, list[str]] = {}
    if not isinstance(security.oauth_role_permissions, dict):
        raise AuthConfigError(
            "OAUTH_ROLE_PERMISSIONS_JSON must be a JSON object"
        )
    for configured_role, configured_permissions in (
        security.oauth_role_permissions.items()
    ):
        if not isinstance(configured_role, str):
            raise AuthConfigError(
                "OAUTH_ROLE_PERMISSIONS_JSON role names must be strings"
            )
        role = configured_role.strip().lower()
        if not role:
            raise AuthConfigError(
                "OAUTH_ROLE_PERMISSIONS_JSON contains an empty role"
            )
        if not isinstance(configured_permissions, list) or any(
            not isinstance(permission, str)
            for permission in configured_permissions
        ):
            raise AuthConfigError(
                f"OAUTH_ROLE_PERMISSIONS_JSON[{role}] must be an array of strings"
            )
        permissions = []
        for configured_permission in configured_permissions:
            permission = configured_permission.strip()
            if not permission:
                raise AuthConfigError(
                    f"OAUTH_ROLE_PERMISSIONS_JSON[{role}] contains an "
                    "empty permission"
                )
            if permission not in permissions:
                permissions.append(permission)
        normalized_role_permissions[role] = permissions
    security.oauth_role_permissions = normalized_role_permissions

    if not isinstance(security.oauth_default_roles, list) or any(
        not isinstance(role, str)
        for role in security.oauth_default_roles
    ):
        raise AuthConfigError(
            "OAUTH_DEFAULT_ROLES must be a comma-separated list"
        )
    if not isinstance(security.oauth_default_permissions, list) or any(
        not isinstance(permission, str)
        for permission in security.oauth_default_permissions
    ):
        raise AuthConfigError(
            "OAUTH_DEFAULT_PERMISSIONS must be a comma-separated list"
        )
    security.oauth_default_roles = list(
        dict.fromkeys(
            role.strip()
            for role in security.oauth_default_roles
            if role.strip()
        )
    )
    security.oauth_default_permissions = list(
        dict.fromkeys(
            permission.strip()
            for permission in security.oauth_default_permissions
            if permission.strip()
        )
    )


@dataclass
class PerformanceConfig:
    """Performance configuration"""

    # Query cache configuration
    enable_query_cache: bool = True
    cache_ttl: int = 300
    max_cache_size: int = 1000

    # Concurrency control configuration
    max_concurrent_queries: int = 50
    query_timeout: int = 300
    default_result_rows: int = DEFAULT_RESULT_ROWS
    max_result_bytes: int = DEFAULT_MAX_RESULT_BYTES

    # Connection pool optimization configuration
    connection_pool_size: int = 20
    idle_timeout: int = 1800

    # Response content size limit (characters)
    max_response_content_size: int = 4096


@dataclass
class DataQualityConfig:
    """Data quality analysis configuration"""

    # Column analysis configuration
    max_columns_per_batch: int = 20  # Maximum columns to analyze in a single batch
    default_sample_size: int = 100000  # Default sample size for analysis

    # Sampling strategy configuration
    small_table_threshold: int = 100000  # Tables smaller than this use full table analysis
    medium_table_threshold: int = 1000000  # Tables smaller than this use simple LIMIT sampling
    # Tables larger than medium_table_threshold use systematic sampling

    # Performance optimization
    enable_batch_analysis: bool = True  # Enable batch analysis for multiple columns
    batch_timeout: int = 300  # Timeout for batch analysis in seconds

    # Accuracy vs Performance trade-off
    enable_fast_mode: bool = False  # Use approximate algorithms for faster results
    fast_mode_sample_size: int = 10000  # Sample size for fast mode

    # Statistical analysis configuration
    enable_distribution_analysis: bool = True  # Enable distribution analysis
    histogram_bins: int = 20  # Number of bins for histogram analysis
    percentile_levels: list[float] = field(default_factory=lambda: [0.25, 0.5, 0.75, 0.95, 0.99])  # Percentile levels to calculate


@dataclass
class ADBCConfig:
    """ADBC (Arrow Flight SQL) configuration"""

    # Default query parameters
    default_max_rows: int = DEFAULT_MAX_RESULT_ROWS
    default_timeout: int = 60
    default_return_format: str = "arrow"  # "arrow", "pandas", "dict"

    # Connection timeout for ADBC
    connection_timeout: int = 30

    # Whether to enable ADBC tools
    enabled: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration"""

    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_path: str | None = None
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5

    # Audit log configuration
    enable_audit: bool = True
    audit_file_path: str | None = None

    # Log cleanup configuration
    enable_cleanup: bool = True
    max_age_days: int = 30
    cleanup_interval_hours: int = 24


@dataclass
class MonitoringConfig:
    """Monitoring configuration"""

    # Metrics collection configuration
    enable_metrics: bool = True
    metrics_port: int = 3001
    metrics_path: str = "/metrics"

    # Health check configuration
    health_check_port: int = 3002
    health_check_path: str = "/health"

    # Alert configuration
    enable_alerts: bool = False
    alert_webhook_url: str | None = None


@dataclass
class ToolExposureConfig:
    """Public MCP tool-list shape."""

    mode: str = "hierarchical"


@dataclass
class AdministrationConfig:
    """Fail-closed reservation for future Doris-changing actions."""

    enabled: bool = False
    require_confirmation: bool = True


@dataclass
class CapabilityConfig:
    """Private Doris capability snapshot controls."""

    snapshot_ttl_seconds: int = 300
    probe_timeout_seconds: int = 5
    stale_grace_seconds: int = 900


@dataclass
class GovernanceConfig:
    """Read-only Governance runtime limits and optional lineage store."""

    max_sample_ratio: float = 0.25
    max_audit_window_days: int = 30
    max_lineage_edges: int = 500
    lineage_store_table: str = ""
    lineage_recent_event_minutes: int = 1440


@dataclass
class LakehouseConfig:
    """Read-only Lakehouse runtime collection and sampling limits."""

    max_catalog_objects: int = 50
    max_catalog_databases: int = 20
    max_snapshots: int = 50
    max_partitions: int = 100
    max_variant_sample_rows: int = 20
    max_variant_paths: int = 200


@dataclass
class SemanticConfig:
    """Opt-in Apache Ossie adapter and bounded semantic context controls."""

    enabled: bool = False
    model_directory: str = ""
    binding_manifest: str = ""
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 8 * 1024 * 1024
    max_models: int = 64
    max_depth: int = 32
    max_aliases: int = 32
    max_string_bytes: int = 16 * 1024
    max_expression_bytes: int = 4096
    context_max_bytes: int = 16 * 1024
    context_hard_max_bytes: int = 64 * 1024
    oauth_tools_enabled: bool = False
    oauth_resources_enabled: bool = False


@dataclass
class DorisConfig:
    """Doris MCP Server complete configuration"""

    # Basic configuration
    server_name: str = "doris-mcp-server"
    server_version: str = field(default=__version__, init=False)
    server_host: str = "localhost"
    server_port: int = 3000
    mcp_allowed_hosts: list[str] = field(default_factory=list)
    mcp_allowed_origins: list[str] = field(default_factory=list)
    enable_legacy_http_adapter: bool = False
    mcp_list_page_size: int = 100
    mcp_tool_providers: list[str] = field(default_factory=list)
    mcp_state_handle_secret: str = field(
        default_factory=lambda: secrets.token_urlsafe(32),
        repr=False,
    )
    mcp_state_handle_ttl_seconds: int = 300
    transport: str = "stdio"
    workers: int = 1

    # Temporary files configuration
    temp_files_dir: str = "tmp"  # Temporary files directory for Explain and Profile outputs

    # Sub-configuration modules
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    data_quality: DataQualityConfig = field(default_factory=DataQualityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    adbc: ADBCConfig = field(default_factory=ADBCConfig)
    tool_exposure: ToolExposureConfig = field(
        default_factory=ToolExposureConfig
    )
    administration: AdministrationConfig = field(
        default_factory=AdministrationConfig
    )
    capability: CapabilityConfig = field(
        default_factory=CapabilityConfig
    )
    governance: GovernanceConfig = field(default_factory=GovernanceConfig)
    lakehouse: LakehouseConfig = field(default_factory=LakehouseConfig)
    semantic: SemanticConfig = field(default_factory=SemanticConfig)

    # Custom configuration
    custom_config: dict[str, Any] = field(default_factory=dict)
    effective_auth: EffectiveAuthConfig | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _auth_inputs: AuthConfigInputs | None = field(
        default=None,
        init=False,
        repr=False,
    )

    @classmethod
    def from_file(cls, config_path: str) -> "DorisConfig":
        """Load configuration from file"""
        config_file = Path(config_path)

        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file does not exist: {config_path}")

        try:
            with open(config_file, encoding="utf-8") as f:
                if config_file.suffix.lower() == ".json":
                    config_data = json.load(f)
                else:
                    # Support other formats (like YAML)
                    raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")

            return cls._from_dict(config_data)

        except Exception as e:
            raise ValueError(f"Failed to load configuration file: {e}")

    @classmethod
    def from_env(cls, env_file: str | None = None) -> "DorisConfig":
        """Load configuration from environment variables

        The kv pairs in the. env file will be loaded as environment variables,
        but the existing environment variables will not be overridden.

        Args:
            env_file: .env file path, if None, search in the following order:
                     .env, .env.local, .env.production, .env.development
        """
        # Load .env file
        if env_file:
            # Load specified .env file
            if Path(env_file).exists():
                load_dotenv(env_file)
                logging.getLogger(__name__).info(f"Loaded environment configuration file: {env_file}")
            else:
                logging.getLogger(__name__).warning(f"Environment configuration file does not exist: {env_file}")
        else:
            # Load .env files in priority order
            env_files = [".env", ".env.local", ".env.production", ".env.development"]
            for env_path in env_files:
                if Path(env_path).exists():
                    load_dotenv(env_path, override=False)
                    logging.getLogger(__name__).info(f"Loaded environment configuration file: {env_path}")
                    break
            else:
                logging.getLogger(__name__).info("No .env configuration file found, using system environment variables")

        config = cls()

        # Database configuration - handle empty strings properly
        doris_host = os.getenv("DORIS_HOST", "").strip()
        config.database.host = doris_host if doris_host else config.database.host

        doris_hosts_env = os.getenv("DORIS_HOSTS", "")
        if doris_hosts_env:
            doris_hosts = [
                host.strip()
                for host in doris_hosts_env.split(",")
                if host.strip()
            ]
            if doris_host:
                doris_hosts = list(dict.fromkeys([doris_host, *doris_hosts]))
            if doris_hosts:
                config.database.hosts = doris_hosts
                config.database.host = doris_hosts[0]

        doris_port = os.getenv("DORIS_PORT", "").strip()
        if doris_port and doris_port.isdigit():
            config.database.port = int(doris_port)

        doris_user = os.getenv("DORIS_USER", "").strip()
        config.database.user = doris_user if doris_user else config.database.user

        doris_password = os.getenv("DORIS_PASSWORD", "")
        config.database.password = doris_password if doris_password else config.database.password

        doris_database = os.getenv("DORIS_DATABASE", "").strip()
        config.database.database = doris_database if doris_database else config.database.database

        doris_fe_http_host = os.getenv("DORIS_FE_HTTP_HOST", "").strip()
        config.database.fe_http_host = doris_fe_http_host

        doris_fe_http_hosts_env = os.getenv("DORIS_FE_HTTP_HOSTS", "")
        if doris_fe_http_hosts_env:
            doris_fe_http_hosts = [
                host.strip()
                for host in doris_fe_http_hosts_env.split(",")
                if host.strip()
            ]
            if doris_fe_http_host:
                doris_fe_http_hosts = list(
                    dict.fromkeys([doris_fe_http_host, *doris_fe_http_hosts])
                )
            if doris_fe_http_hosts:
                config.database.fe_http_hosts = doris_fe_http_hosts
                config.database.fe_http_host = doris_fe_http_hosts[0]

        doris_fe_http_port = os.getenv("DORIS_FE_HTTP_PORT", "").strip()
        if doris_fe_http_port and doris_fe_http_port.isdigit():
            config.database.fe_http_port = int(doris_fe_http_port)

        # BE nodes configuration
        be_hosts_env = os.getenv("DORIS_BE_HOSTS", "")
        if be_hosts_env:
            config.database.be_hosts = [host.strip() for host in be_hosts_env.split(",") if host.strip()]
        be_webserver_port = os.getenv("DORIS_BE_WEBSERVER_PORT", "").strip()
        if be_webserver_port and be_webserver_port.isdigit():
            config.database.be_webserver_port = int(be_webserver_port)

        config.database.http_connect_timeout_seconds = float(
            os.getenv(
                "DORIS_HTTP_CONNECT_TIMEOUT_SECONDS",
                str(config.database.http_connect_timeout_seconds),
            )
        )
        config.database.http_read_timeout_seconds = float(
            os.getenv(
                "DORIS_HTTP_READ_TIMEOUT_SECONDS",
                str(config.database.http_read_timeout_seconds),
            )
        )
        config.database.http_total_timeout_seconds = float(
            os.getenv(
                "DORIS_HTTP_TOTAL_TIMEOUT_SECONDS",
                str(config.database.http_total_timeout_seconds),
            )
        )
        config.database.http_max_response_bytes = int(
            os.getenv(
                "DORIS_HTTP_MAX_RESPONSE_BYTES",
                str(config.database.http_max_response_bytes),
            )
        )

        # Arrow Flight SQL Configuration
        fe_arrow_port_env = os.getenv("FE_ARROW_FLIGHT_SQL_PORT")
        if fe_arrow_port_env:
            config.database.fe_arrow_flight_sql_port = int(fe_arrow_port_env)

        be_arrow_port_env = os.getenv("BE_ARROW_FLIGHT_SQL_PORT")
        if be_arrow_port_env:
            config.database.be_arrow_flight_sql_port = int(be_arrow_port_env)

        # Connection pool configuration
        config.database.max_connections = int(
            os.getenv("DORIS_MAX_CONNECTIONS", str(config.database.max_connections))
        )
        config.database.connection_timeout = int(
            os.getenv("DORIS_CONNECTION_TIMEOUT", str(config.database.connection_timeout))
        )
        config.database.health_check_interval = int(
            os.getenv("DORIS_HEALTH_CHECK_INTERVAL", str(config.database.health_check_interval))
        )
        config.database.max_connection_age = int(
            os.getenv("DORIS_MAX_CONNECTION_AGE", str(config.database.max_connection_age))
        )

        # Security configuration
        # Independent authentication switches
        if "ENABLE_TOKEN_AUTH" in os.environ:
            config.security.enable_token_auth = _str_to_bool(os.getenv("ENABLE_TOKEN_AUTH"))
            _mark_source(config, "enable_token_auth", "env")
        if "ENABLE_JWT_AUTH" in os.environ:
            config.security.enable_jwt_auth = _str_to_bool(os.getenv("ENABLE_JWT_AUTH"))
            _mark_source(config, "enable_jwt_auth", "env")
        if "ENABLE_OAUTH_AUTH" in os.environ:
            config.security.enable_oauth_auth = _str_to_bool(os.getenv("ENABLE_OAUTH_AUTH"))
            _mark_source(config, "enable_oauth_auth", "env")
        if "OAUTH_ENABLED" in os.environ:
            config.security.oauth_enabled = _str_to_bool(os.getenv("OAUTH_ENABLED"))
            _mark_source(config, "oauth_enabled", "env")
        external_oauth_env = {
            "OAUTH_PROVIDER_TYPE": "oauth_provider",
            "OAUTH_CLIENT_ID": "oauth_client_id",
            "OAUTH_CLIENT_SECRET": "oauth_client_secret",
            "OAUTH_REDIRECT_URI": "oauth_redirect_uri",
            "OAUTH_DISCOVERY_URL": "oidc_discovery_url",
            "OAUTH_AUTHORIZATION_URL": "oauth_authorization_endpoint",
            "OAUTH_TOKEN_URL": "oauth_token_endpoint",
            "OAUTH_INTROSPECTION_URL": "oauth_introspection_endpoint",
            "OAUTH_INTROSPECTION_CLIENT_ID": "oauth_introspection_client_id",
            "OAUTH_INTROSPECTION_CLIENT_SECRET": "oauth_introspection_client_secret",
            "OAUTH_USERINFO_URL": "oauth_userinfo_endpoint",
            "OAUTH_JWKS_URL": "oauth_jwks_uri",
            "OAUTH_ISSUER": "oauth_issuer",
            "OAUTH_RESOURCE": "oauth_resource",
            "OAUTH_AUDIENCE": "oauth_audience",
            "OAUTH_USER_ID_CLAIM": "oauth_user_id_claim",
            "OAUTH_EMAIL_CLAIM": "oauth_email_claim",
            "OAUTH_ROLES_CLAIM": "oauth_roles_claim",
        }
        for env_name, field_name in external_oauth_env.items():
            if env_name in os.environ:
                setattr(
                    config.security,
                    field_name,
                    os.getenv(env_name, "").strip(),
                )
                _mark_source(config, field_name, "env")
        if "OAUTH_SCOPE" in os.environ:
            config.security.oauth_scopes = _coerce_scope_config(
                os.getenv("OAUTH_SCOPE")
            )
            _mark_source(config, "oauth_scopes", "env")
        if "OAUTH_REQUIRED_SCOPE" in os.environ:
            config.security.oauth_required_scopes = _coerce_scope_config(
                os.getenv("OAUTH_REQUIRED_SCOPE")
            )
            _mark_source(config, "oauth_required_scopes", "env")
        if "OAUTH_DEFAULT_ROLES" in os.environ:
            config.security.oauth_default_roles = _env_csv(
                "OAUTH_DEFAULT_ROLES",
                config.security.oauth_default_roles,
            )
            _mark_source(config, "oauth_default_roles", "env")
        if "OAUTH_DEFAULT_SECURITY_LEVEL" in os.environ:
            config.security.oauth_default_security_level = os.getenv(
                "OAUTH_DEFAULT_SECURITY_LEVEL",
                config.security.oauth_default_security_level,
            ).strip()
            _mark_source(config, "oauth_default_security_level", "env")
        if "OAUTH_TRUSTED_DOMAINS" in os.environ:
            config.security.oauth_trusted_domains = _env_csv(
                "OAUTH_TRUSTED_DOMAINS",
                config.security.oauth_trusted_domains,
            )
            _mark_source(config, "oauth_trusted_domains", "env")
        if "OAUTH_TRUSTED_DOMAIN_SECURITY_LEVEL" in os.environ:
            config.security.oauth_trusted_domain_security_level = os.getenv(
                "OAUTH_TRUSTED_DOMAIN_SECURITY_LEVEL",
                config.security.oauth_trusted_domain_security_level,
            ).strip()
            _mark_source(
                config,
                "oauth_trusted_domain_security_level",
                "env",
            )
        if "OAUTH_ROLE_SECURITY_LEVELS_JSON" in os.environ:
            config.security.oauth_role_security_levels = _env_json_string_map(
                "OAUTH_ROLE_SECURITY_LEVELS_JSON",
                config.security.oauth_role_security_levels,
            )
            _mark_source(config, "oauth_role_security_levels", "env")
        if "OAUTH_ROLE_PERMISSIONS_JSON" in os.environ:
            config.security.oauth_role_permissions = _env_json_string_list_map(
                "OAUTH_ROLE_PERMISSIONS_JSON",
                config.security.oauth_role_permissions,
            )
            _mark_source(config, "oauth_role_permissions", "env")
        if "OAUTH_DEFAULT_PERMISSIONS" in os.environ:
            config.security.oauth_default_permissions = _env_csv(
                "OAUTH_DEFAULT_PERMISSIONS",
                config.security.oauth_default_permissions,
            )
            _mark_source(config, "oauth_default_permissions", "env")
        if "ENABLE_DORIS_OAUTH_AUTH" in os.environ:
            config.security.enable_doris_oauth_auth = _str_to_bool(os.getenv("ENABLE_DORIS_OAUTH_AUTH"))
            _mark_source(config, "enable_doris_oauth_auth", "env")
        if "ALLOW_UNAUTHENTICATED_NON_LOOPBACK" in os.environ:
            config.security.allow_unauthenticated_non_loopback = _str_to_bool(
                os.getenv("ALLOW_UNAUTHENTICATED_NON_LOOPBACK")
            )
            _mark_source(config, "allow_unauthenticated_non_loopback", "env")
        if "DORIS_OAUTH_BASE_URL" in os.environ:
            config.security.doris_oauth_base_url = os.getenv("DORIS_OAUTH_BASE_URL", "").strip()
            _mark_source(config, "doris_oauth_base_url", "env")
        if "DORIS_OAUTH_CHILD_TOOLS_ENABLED" in os.environ:
            config.security.doris_oauth_child_tools_enabled = _str_to_bool(
                os.getenv("DORIS_OAUTH_CHILD_TOOLS_ENABLED")
            )
            _mark_source(config, "doris_oauth_child_tools_enabled", "env")
        if "DORIS_OAUTH_CHILD_TOOL_ALLOWLIST" in os.environ:
            config.security.doris_oauth_child_tool_allowlist = _env_csv(
                "DORIS_OAUTH_CHILD_TOOL_ALLOWLIST",
                config.security.doris_oauth_child_tool_allowlist,
            )
            _mark_source(config, "doris_oauth_child_tool_allowlist", "env")
        if "DORIS_OAUTH_DB_TOOLS_ENABLED" in os.environ:
            config.security.doris_oauth_db_tools_enabled = _str_to_bool(os.getenv("DORIS_OAUTH_DB_TOOLS_ENABLED"))
            _mark_source(config, "doris_oauth_db_tools_enabled", "env")
        if "DORIS_OAUTH_DB_TOOL_ALLOWLIST" in os.environ:
            config.security.doris_oauth_db_tool_allowlist = _env_csv(
                "DORIS_OAUTH_DB_TOOL_ALLOWLIST",
                config.security.doris_oauth_db_tool_allowlist,
            )
            _mark_source(config, "doris_oauth_db_tool_allowlist", "env")
        if "DORIS_OAUTH_QUERY_TOOLS_ENABLED" in os.environ:
            config.security.doris_oauth_query_tools_enabled = _str_to_bool(
                os.getenv("DORIS_OAUTH_QUERY_TOOLS_ENABLED")
            )
            _mark_source(config, "doris_oauth_query_tools_enabled", "env")
        if "DORIS_OAUTH_QUERY_TOOL_ALLOWLIST" in os.environ:
            config.security.doris_oauth_query_tool_allowlist = _env_csv(
                "DORIS_OAUTH_QUERY_TOOL_ALLOWLIST",
                config.security.doris_oauth_query_tool_allowlist,
            )
            _mark_source(config, "doris_oauth_query_tool_allowlist", "env")
        if "DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED" in os.environ:
            config.security.doris_oauth_explain_tools_enabled = _str_to_bool(
                os.getenv("DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED")
            )
            _mark_source(config, "doris_oauth_explain_tools_enabled", "env")
        if "DORIS_OAUTH_EXPLAIN_TOOL_ALLOWLIST" in os.environ:
            config.security.doris_oauth_explain_tool_allowlist = _env_csv(
                "DORIS_OAUTH_EXPLAIN_TOOL_ALLOWLIST",
                config.security.doris_oauth_explain_tool_allowlist,
            )
            _mark_source(config, "doris_oauth_explain_tool_allowlist", "env")
        config.security.doris_oauth_access_token_expire_seconds = _env_int(
            "DORIS_OAUTH_ACCESS_TOKEN_EXPIRE_SECONDS",
            config.security.doris_oauth_access_token_expire_seconds,
        )
        config.security.doris_oauth_refresh_token_expire_seconds = _env_int(
            "DORIS_OAUTH_REFRESH_TOKEN_EXPIRE_SECONDS",
            config.security.doris_oauth_refresh_token_expire_seconds,
        )
        config.security.doris_oauth_auth_code_expire_seconds = _env_int(
            "DORIS_OAUTH_AUTH_CODE_EXPIRE_SECONDS",
            config.security.doris_oauth_auth_code_expire_seconds,
        )
        config.security.doris_oauth_gc_interval_seconds = _env_int(
            "DORIS_OAUTH_GC_INTERVAL_SECONDS",
            config.security.doris_oauth_gc_interval_seconds,
        )
        config.security.doris_oauth_idle_timeout_seconds = _env_optional_int(
            "DORIS_OAUTH_IDLE_TIMEOUT_SECONDS",
            config.security.doris_oauth_idle_timeout_seconds,
        )
        config.security.doris_oauth_login_page_title = os.getenv(
            "DORIS_OAUTH_LOGIN_PAGE_TITLE",
            config.security.doris_oauth_login_page_title,
        )
        config.security.doris_oauth_allowed_redirect_uris = _env_csv(
            "DORIS_OAUTH_ALLOWED_REDIRECT_URIS",
            config.security.doris_oauth_allowed_redirect_uris,
        )
        config.security.doris_oauth_clients_file = os.getenv(
            "DORIS_OAUTH_CLIENTS_FILE",
            config.security.doris_oauth_clients_file,
        )
        for env_name, field_name in {
            "DORIS_OAUTH_CIMD_FETCH_TIMEOUT_SECONDS": "doris_oauth_cimd_fetch_timeout_seconds",
            "DORIS_OAUTH_CIMD_MAX_DOCUMENT_BYTES": "doris_oauth_cimd_max_document_bytes",
            "DORIS_OAUTH_CIMD_DEFAULT_CACHE_SECONDS": "doris_oauth_cimd_default_cache_seconds",
            "DORIS_OAUTH_CIMD_MAX_CACHE_SECONDS": "doris_oauth_cimd_max_cache_seconds",
            "DORIS_OAUTH_CIMD_MAX_CLIENTS": "doris_oauth_cimd_max_clients",
        }.items():
            setattr(
                config.security,
                field_name,
                _env_int(env_name, getattr(config.security, field_name)),
            )
        config.security.doris_oauth_dynamic_client_registration_mode = os.getenv(
            "DORIS_OAUTH_DYNAMIC_CLIENT_REGISTRATION_MODE",
            config.security.doris_oauth_dynamic_client_registration_mode,
        )
        config.security.enable_doris_oauth_production_dcr = _str_to_bool(
            os.getenv(
                "ENABLE_DORIS_OAUTH_PRODUCTION_DCR",
                config.security.enable_doris_oauth_production_dcr,
            )
        )
        config.security.enable_doris_oauth_production_wildcard_redirects = _str_to_bool(
            os.getenv(
                "ENABLE_DORIS_OAUTH_PRODUCTION_WILDCARD_REDIRECTS",
                config.security.enable_doris_oauth_production_wildcard_redirects,
            )
        )
        config.security.doris_oauth_allow_insecure_http = _str_to_bool(
            os.getenv(
                "DORIS_OAUTH_ALLOW_INSECURE_HTTP",
                config.security.doris_oauth_allow_insecure_http,
            )
        )
        config.security.doris_oauth_trust_proxy_headers = _str_to_bool(
            os.getenv(
                "DORIS_OAUTH_TRUST_PROXY_HEADERS",
                config.security.doris_oauth_trust_proxy_headers,
            )
        )
        config.security.doris_oauth_trusted_proxy_cidrs = _env_csv(
            "DORIS_OAUTH_TRUSTED_PROXY_CIDRS",
            config.security.doris_oauth_trusted_proxy_cidrs,
        )
        for env_name, field_name in {
            "DORIS_OAUTH_RATE_LIMIT_WINDOW_SECONDS": "doris_oauth_rate_limit_window_seconds",
            "DORIS_OAUTH_LOGIN_RATE_LIMIT_PER_IP": "doris_oauth_login_rate_limit_per_ip",
            "DORIS_OAUTH_LOGIN_RATE_LIMIT_PER_USER": "doris_oauth_login_rate_limit_per_user",
            "DORIS_OAUTH_LOGIN_RATE_LIMIT_PER_CLIENT": "doris_oauth_login_rate_limit_per_client",
            "DORIS_OAUTH_LOGIN_RATE_LIMIT_PER_TXN": "doris_oauth_login_rate_limit_per_txn",
            "DORIS_OAUTH_DCR_RATE_LIMIT_PER_IP": "doris_oauth_dcr_rate_limit_per_ip",
            "DORIS_OAUTH_AUTHORIZE_RATE_LIMIT_PER_IP": "doris_oauth_authorize_rate_limit_per_ip",
            "DORIS_OAUTH_TOKEN_RATE_LIMIT_PER_IP": "doris_oauth_token_rate_limit_per_ip",
            "DORIS_OAUTH_TOKEN_RATE_LIMIT_PER_CLIENT": "doris_oauth_token_rate_limit_per_client",
            "DORIS_OAUTH_REVOKE_RATE_LIMIT_PER_IP": "doris_oauth_revoke_rate_limit_per_ip",
            "DORIS_OAUTH_REVOKE_RATE_LIMIT_PER_CLIENT": "doris_oauth_revoke_rate_limit_per_client",
            "DORIS_OAUTH_API_AUTH_TOKEN_RATE_LIMIT_PER_IP": "doris_oauth_api_auth_token_rate_limit_per_ip",
            "DORIS_OAUTH_API_AUTH_TOKEN_RATE_LIMIT_PER_USER": "doris_oauth_api_auth_token_rate_limit_per_user",
            "DORIS_OAUTH_API_AUTH_REFRESH_RATE_LIMIT_PER_IP": "doris_oauth_api_auth_refresh_rate_limit_per_ip",
            "DORIS_OAUTH_API_AUTH_REFRESH_RATE_LIMIT_PER_CLIENT": "doris_oauth_api_auth_refresh_rate_limit_per_client",
            "DORIS_OAUTH_DCR_MAX_CLIENTS": "doris_oauth_dcr_max_clients",
            "DORIS_OAUTH_DCR_CLIENT_TTL_SECONDS": "doris_oauth_dcr_client_ttl_seconds",
        }.items():
            setattr(config.security, field_name, _env_int(env_name, getattr(config.security, field_name)))
        config.security.doris_oauth_rate_limit_window_seconds = _env_int(
            "DORIS_OAUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS",
            config.security.doris_oauth_rate_limit_window_seconds,
        )
        if "AUTH_TYPE" in os.environ:
            config.security.auth_type = os.getenv("AUTH_TYPE", config.security.auth_type)
            _mark_source(config, "auth_type", "env")
        config.security.token_secret = os.getenv("TOKEN_SECRET", config.security.token_secret)
        config.security.token_expiry = int(
            os.getenv("TOKEN_EXPIRY", str(config.security.token_expiry))
        )
        config.security.max_result_rows = int(
            os.getenv("MAX_RESULT_ROWS", str(config.security.max_result_rows))
        )
        config.security.max_query_complexity = int(
            os.getenv("MAX_QUERY_COMPLEXITY", str(config.security.max_query_complexity))
        )
        config.security.enable_security_check = (
            os.getenv("ENABLE_SECURITY_CHECK", str(config.security.enable_security_check).lower()).lower() == "true"
        )

        # Handle blocked keywords environment variable configuration
        # Format: BLOCKED_KEYWORDS="DROP,DELETE,TRUNCATE,ALTER,CREATE,INSERT,UPDATE,GRANT,REVOKE"
        blocked_keywords_env = os.getenv("BLOCKED_KEYWORDS", "")
        if blocked_keywords_env:
            # If environment variable is provided, use keywords list from environment variable
            config.security.blocked_keywords = [
                keyword.strip().upper()
                for keyword in blocked_keywords_env.split(",")
                if keyword.strip()
            ]
        # If environment variable is empty, keep default configuration unchanged

        config.security.enable_masking = (
            os.getenv("ENABLE_MASKING", str(config.security.enable_masking).lower()).lower() == "true"
        )

        # Enhanced Token Authentication configuration
        config.security.token_file_path = os.getenv("TOKEN_FILE_PATH", config.security.token_file_path)
        config.security.enable_token_expiry = (
            os.getenv("ENABLE_TOKEN_EXPIRY", str(config.security.enable_token_expiry).lower()).lower() == "true"
        )
        config.security.default_token_expiry_hours = int(
            os.getenv("DEFAULT_TOKEN_EXPIRY_HOURS", str(config.security.default_token_expiry_hours))
        )
        config.security.token_hash_algorithm = os.getenv("TOKEN_HASH_ALGORITHM", config.security.token_hash_algorithm)
        config.security.token_db_validation_ttl_seconds = int(
            os.getenv(
                "TOKEN_DB_VALIDATION_TTL_SECONDS",
                str(config.security.token_db_validation_ttl_seconds),
            )
        )

        # Token Management Security Configuration (New in v0.6.0)
        config.security.enable_http_token_management = (
            os.getenv("ENABLE_HTTP_TOKEN_MANAGEMENT", str(config.security.enable_http_token_management).lower()).lower() == "true"
        )
        config.security.token_management_admin_token = os.getenv("TOKEN_MANAGEMENT_ADMIN_TOKEN", config.security.token_management_admin_token)

        # Parse allowed IPs from comma-separated string
        allowed_ips_str = os.getenv("TOKEN_MANAGEMENT_ALLOWED_IPS", "")
        if allowed_ips_str:
            config.security.token_management_allowed_ips = [ip.strip() for ip in allowed_ips_str.split(",") if ip.strip()]

        config.security.require_admin_auth = (
            os.getenv("REQUIRE_ADMIN_AUTH", str(config.security.require_admin_auth).lower()).lower() == "true"
        )

        # Performance configuration
        config.performance.enable_query_cache = (
            os.getenv("ENABLE_QUERY_CACHE", "true").lower() == "true"
        )
        config.performance.cache_ttl = int(
            os.getenv("CACHE_TTL", str(config.performance.cache_ttl))
        )
        config.performance.max_cache_size = int(
            os.getenv("MAX_CACHE_SIZE", str(config.performance.max_cache_size))
        )
        config.performance.max_concurrent_queries = int(
            os.getenv("MAX_CONCURRENT_QUERIES", str(config.performance.max_concurrent_queries))
            )
        config.performance.query_timeout = int(
            os.getenv("QUERY_TIMEOUT", str(config.performance.query_timeout))
        )
        config.performance.default_result_rows = int(
            os.getenv(
                "DEFAULT_RESULT_ROWS",
                str(config.performance.default_result_rows),
            )
        )
        config.performance.max_result_bytes = int(
            os.getenv(
                "MAX_RESULT_BYTES",
                str(config.performance.max_result_bytes),
            )
        )
        config.performance.max_response_content_size = int(
            os.getenv("MAX_RESPONSE_CONTENT_SIZE", str(config.performance.max_response_content_size))
        )

        # Logging configuration
        config.logging.level = os.getenv("LOG_LEVEL", config.logging.level)
        config.logging.file_path = os.getenv("LOG_FILE_PATH", config.logging.file_path)
        config.logging.enable_audit = (
            os.getenv("ENABLE_AUDIT", str(config.logging.enable_audit).lower()).lower() == "true"
        )
        config.logging.audit_file_path = os.getenv("AUDIT_FILE_PATH", config.logging.audit_file_path)
        config.logging.enable_cleanup = (
            os.getenv("ENABLE_LOG_CLEANUP", str(config.logging.enable_cleanup).lower()).lower() == "true"
        )
        config.logging.max_age_days = int(
            os.getenv("LOG_MAX_AGE_DAYS", str(config.logging.max_age_days))
        )
        config.logging.cleanup_interval_hours = int(
            os.getenv("LOG_CLEANUP_INTERVAL_HOURS", str(config.logging.cleanup_interval_hours))
        )

        # Monitoring configuration
        config.monitoring.enable_metrics = (
            os.getenv("ENABLE_METRICS", "true").lower() == "true"
        )
        config.monitoring.metrics_port = int(
            os.getenv("METRICS_PORT", str(config.monitoring.metrics_port))
        )
        config.monitoring.health_check_port = int(
            os.getenv("HEALTH_CHECK_PORT", str(config.monitoring.health_check_port))
        )
        config.monitoring.enable_alerts = (
            os.getenv("ENABLE_ALERTS", str(config.monitoring.enable_alerts).lower()).lower() == "true"
        )
        config.monitoring.alert_webhook_url = os.getenv("ALERT_WEBHOOK_URL", config.monitoring.alert_webhook_url)

        # ADBC configuration
        config.adbc.default_max_rows = int(
            os.getenv("ADBC_DEFAULT_MAX_ROWS", str(config.adbc.default_max_rows))
        )
        config.adbc.default_timeout = int(
            os.getenv("ADBC_DEFAULT_TIMEOUT", str(config.adbc.default_timeout))
        )
        config.adbc.default_return_format = os.getenv("ADBC_DEFAULT_RETURN_FORMAT", config.adbc.default_return_format)
        config.adbc.connection_timeout = int(
            os.getenv("ADBC_CONNECTION_TIMEOUT", str(config.adbc.connection_timeout))
        )
        config.adbc.enabled = (
            os.getenv("ADBC_ENABLED", str(config.adbc.enabled).lower()).lower() == "true"
        )

        # Data quality configuration
        config.data_quality.max_columns_per_batch = int(
            os.getenv("DATA_QUALITY_MAX_COLUMNS_PER_BATCH", str(config.data_quality.max_columns_per_batch))
        )
        config.data_quality.default_sample_size = int(
            os.getenv("DATA_QUALITY_DEFAULT_SAMPLE_SIZE", str(config.data_quality.default_sample_size))
        )
        config.data_quality.small_table_threshold = int(
            os.getenv("DATA_QUALITY_SMALL_TABLE_THRESHOLD", str(config.data_quality.small_table_threshold))
        )
        config.data_quality.medium_table_threshold = int(
            os.getenv("DATA_QUALITY_MEDIUM_TABLE_THRESHOLD", str(config.data_quality.medium_table_threshold))
        )
        config.data_quality.enable_batch_analysis = (
            os.getenv("DATA_QUALITY_ENABLE_BATCH_ANALYSIS", str(config.data_quality.enable_batch_analysis).lower()).lower() == "true"
        )
        config.data_quality.batch_timeout = int(
            os.getenv("DATA_QUALITY_BATCH_TIMEOUT", str(config.data_quality.batch_timeout))
        )
        config.data_quality.enable_fast_mode = (
            os.getenv("DATA_QUALITY_ENABLE_FAST_MODE", str(config.data_quality.enable_fast_mode).lower()).lower() == "true"
        )
        config.data_quality.fast_mode_sample_size = int(
            os.getenv("DATA_QUALITY_FAST_MODE_SAMPLE_SIZE", str(config.data_quality.fast_mode_sample_size))
        )
        config.data_quality.enable_distribution_analysis = (
            os.getenv("DATA_QUALITY_ENABLE_DISTRIBUTION_ANALYSIS", str(config.data_quality.enable_distribution_analysis).lower()).lower() == "true"
        )
        config.data_quality.histogram_bins = int(
            os.getenv("DATA_QUALITY_HISTOGRAM_BINS", str(config.data_quality.histogram_bins))
        )

        # Server configuration
        config.server_name = os.getenv("SERVER_NAME", config.server_name)
        server_host = os.getenv("SERVER_HOST", "").strip()
        if server_host:
            config.server_host = server_host
        if "TRANSPORT" in os.environ:
            config.transport = os.getenv("TRANSPORT", config.transport)
            _mark_source(config, "transport", "env")
        if "WORKERS" in os.environ:
            config.workers = int(os.getenv("WORKERS", "1"))
            _mark_source(config, "workers", "env")
        server_port = os.getenv("SERVER_PORT", "").strip()
        if server_port and server_port.isdigit():
            config.server_port = int(server_port)
        if "MCP_ALLOWED_HOSTS" in os.environ:
            config.mcp_allowed_hosts = [
                value.strip()
                for value in os.getenv("MCP_ALLOWED_HOSTS", "").split(",")
                if value.strip()
            ]
            _mark_source(config, "mcp_allowed_hosts", "env")
        if "MCP_ALLOWED_ORIGINS" in os.environ:
            config.mcp_allowed_origins = [
                value.strip()
                for value in os.getenv("MCP_ALLOWED_ORIGINS", "").split(",")
                if value.strip()
            ]
            _mark_source(config, "mcp_allowed_origins", "env")
        if "ENABLE_LEGACY_HTTP_ADAPTER" in os.environ:
            config.enable_legacy_http_adapter = (
                os.getenv("ENABLE_LEGACY_HTTP_ADAPTER", "false").lower() == "true"
            )
            _mark_source(config, "enable_legacy_http_adapter", "env")
        if "MCP_LIST_PAGE_SIZE" in os.environ:
            config.mcp_list_page_size = _env_int(
                "MCP_LIST_PAGE_SIZE",
                config.mcp_list_page_size,
            )
            _mark_source(config, "mcp_list_page_size", "env")
        if "MCP_TOOL_PROVIDERS" in os.environ:
            config.mcp_tool_providers = [
                value.strip()
                for value in os.getenv("MCP_TOOL_PROVIDERS", "").split(",")
                if value.strip()
            ]
            _mark_source(config, "mcp_tool_providers", "env")
        if "MCP_TOOL_EXPOSURE_MODE" in os.environ:
            config.tool_exposure.mode = os.getenv(
                "MCP_TOOL_EXPOSURE_MODE",
                config.tool_exposure.mode,
            ).strip()
            _mark_source(config, "mcp_tool_exposure_mode", "env")
        if "MCP_ADMIN_DOMAIN_ENABLED" in os.environ:
            config.administration.enabled = _str_to_bool(
                os.getenv("MCP_ADMIN_DOMAIN_ENABLED")
            )
        if "MCP_ADMIN_REQUIRE_CONFIRMATION" in os.environ:
            config.administration.require_confirmation = _str_to_bool(
                os.getenv("MCP_ADMIN_REQUIRE_CONFIRMATION")
            )
        if "CAPABILITY_SNAPSHOT_TTL_SECONDS" in os.environ:
            config.capability.snapshot_ttl_seconds = _env_int(
                "CAPABILITY_SNAPSHOT_TTL_SECONDS",
                config.capability.snapshot_ttl_seconds,
            )
            _mark_source(config, "capability_snapshot_ttl_seconds", "env")
        if "CAPABILITY_PROBE_TIMEOUT_SECONDS" in os.environ:
            config.capability.probe_timeout_seconds = _env_int(
                "CAPABILITY_PROBE_TIMEOUT_SECONDS",
                config.capability.probe_timeout_seconds,
            )
            _mark_source(config, "capability_probe_timeout_seconds", "env")
        if "CAPABILITY_STALE_GRACE_SECONDS" in os.environ:
            config.capability.stale_grace_seconds = _env_int(
                "CAPABILITY_STALE_GRACE_SECONDS",
                config.capability.stale_grace_seconds,
            )
            _mark_source(config, "capability_stale_grace_seconds", "env")
        if "GOVERNANCE_MAX_SAMPLE_RATIO" in os.environ:
            config.governance.max_sample_ratio = float(
                os.getenv(
                    "GOVERNANCE_MAX_SAMPLE_RATIO",
                    str(config.governance.max_sample_ratio),
                )
            )
        if "GOVERNANCE_MAX_AUDIT_WINDOW_DAYS" in os.environ:
            config.governance.max_audit_window_days = _env_int(
                "GOVERNANCE_MAX_AUDIT_WINDOW_DAYS",
                config.governance.max_audit_window_days,
            )
        if "GOVERNANCE_MAX_LINEAGE_EDGES" in os.environ:
            config.governance.max_lineage_edges = _env_int(
                "GOVERNANCE_MAX_LINEAGE_EDGES",
                config.governance.max_lineage_edges,
            )
        if "GOVERNANCE_LINEAGE_STORE_TABLE" in os.environ:
            config.governance.lineage_store_table = os.getenv(
                "GOVERNANCE_LINEAGE_STORE_TABLE",
                "",
            ).strip()
        if "GOVERNANCE_LINEAGE_RECENT_EVENT_MINUTES" in os.environ:
            config.governance.lineage_recent_event_minutes = _env_int(
                "GOVERNANCE_LINEAGE_RECENT_EVENT_MINUTES",
                config.governance.lineage_recent_event_minutes,
            )
        if "LAKEHOUSE_MAX_CATALOG_OBJECTS" in os.environ:
            config.lakehouse.max_catalog_objects = _env_int(
                "LAKEHOUSE_MAX_CATALOG_OBJECTS",
                config.lakehouse.max_catalog_objects,
            )
        if "LAKEHOUSE_MAX_CATALOG_DATABASES" in os.environ:
            config.lakehouse.max_catalog_databases = _env_int(
                "LAKEHOUSE_MAX_CATALOG_DATABASES",
                config.lakehouse.max_catalog_databases,
            )
        if "LAKEHOUSE_MAX_SNAPSHOTS" in os.environ:
            config.lakehouse.max_snapshots = _env_int(
                "LAKEHOUSE_MAX_SNAPSHOTS",
                config.lakehouse.max_snapshots,
            )
        if "LAKEHOUSE_MAX_PARTITIONS" in os.environ:
            config.lakehouse.max_partitions = _env_int(
                "LAKEHOUSE_MAX_PARTITIONS",
                config.lakehouse.max_partitions,
            )
        if "LAKEHOUSE_MAX_VARIANT_SAMPLE_ROWS" in os.environ:
            config.lakehouse.max_variant_sample_rows = _env_int(
                "LAKEHOUSE_MAX_VARIANT_SAMPLE_ROWS",
                config.lakehouse.max_variant_sample_rows,
            )
        if "LAKEHOUSE_MAX_VARIANT_PATHS" in os.environ:
            config.lakehouse.max_variant_paths = _env_int(
                "LAKEHOUSE_MAX_VARIANT_PATHS",
                config.lakehouse.max_variant_paths,
            )
        if "OSSIE_ENABLED" in os.environ:
            config.semantic.enabled = (
                os.getenv("OSSIE_ENABLED", "false").lower() == "true"
            )
        if "OSSIE_MODEL_DIRECTORY" in os.environ:
            config.semantic.model_directory = os.getenv(
                "OSSIE_MODEL_DIRECTORY",
                "",
            ).strip()
        if "OSSIE_BINDING_MANIFEST" in os.environ:
            config.semantic.binding_manifest = os.getenv(
                "OSSIE_BINDING_MANIFEST",
                "",
            ).strip()
        semantic_integer_env = (
            ("OSSIE_MAX_FILE_BYTES", "max_file_bytes"),
            ("OSSIE_MAX_TOTAL_BYTES", "max_total_bytes"),
            ("OSSIE_MAX_MODELS", "max_models"),
            ("OSSIE_MAX_DEPTH", "max_depth"),
            ("OSSIE_MAX_ALIASES", "max_aliases"),
            ("OSSIE_MAX_STRING_BYTES", "max_string_bytes"),
            ("OSSIE_MAX_EXPRESSION_BYTES", "max_expression_bytes"),
            ("OSSIE_CONTEXT_MAX_BYTES", "context_max_bytes"),
            ("OSSIE_CONTEXT_HARD_MAX_BYTES", "context_hard_max_bytes"),
        )
        for env_name, attribute in semantic_integer_env:
            if env_name in os.environ:
                setattr(
                    config.semantic,
                    attribute,
                    _env_int(
                        env_name,
                        int(getattr(config.semantic, attribute)),
                    ),
                )
        if "DORIS_OAUTH_SEMANTIC_TOOLS_ENABLED" in os.environ:
            config.semantic.oauth_tools_enabled = (
                os.getenv(
                    "DORIS_OAUTH_SEMANTIC_TOOLS_ENABLED",
                    "false",
                ).lower()
                == "true"
            )
        if "DORIS_OAUTH_SEMANTIC_RESOURCES_ENABLED" in os.environ:
            config.semantic.oauth_resources_enabled = (
                os.getenv(
                    "DORIS_OAUTH_SEMANTIC_RESOURCES_ENABLED",
                    "false",
                ).lower()
                == "true"
            )
        if "MCP_STATE_HANDLE_SECRET" in os.environ:
            config.mcp_state_handle_secret = os.getenv(
                "MCP_STATE_HANDLE_SECRET",
                "",
            )
            _mark_source(config, "mcp_state_handle_secret", "env")
        if "MCP_STATE_HANDLE_TTL_SECONDS" in os.environ:
            config.mcp_state_handle_ttl_seconds = _env_int(
                "MCP_STATE_HANDLE_TTL_SECONDS",
                config.mcp_state_handle_ttl_seconds,
            )
            _mark_source(config, "mcp_state_handle_ttl_seconds", "env")
        config.temp_files_dir = os.getenv("TEMP_FILES_DIR", config.temp_files_dir)

        return config

    @classmethod
    def _from_dict(cls, config_data: dict[str, Any]) -> "DorisConfig":
        """Create configuration object from dictionary"""
        config = cls()

        # Update basic configuration
        for key in [
            "server_name",
            "server_host",
            "server_port",
            "mcp_allowed_hosts",
            "mcp_allowed_origins",
            "enable_legacy_http_adapter",
            "mcp_list_page_size",
            "mcp_tool_providers",
            "mcp_state_handle_ttl_seconds",
            "temp_files_dir",
            "transport",
            "workers",
        ]:
            if key in config_data:
                setattr(config, key, config_data[key])
                _mark_source(config, key, "config_file")

        # Update database configuration
        if "database" in config_data:
            db_config = config_data["database"]
            for key, value in db_config.items():
                if hasattr(config.database, key):
                    setattr(config.database, key, value)
            if config.database.hosts and "host" not in db_config:
                config.database.host = config.database.hosts[0]
            if config.database.fe_http_hosts and "fe_http_host" not in db_config:
                config.database.fe_http_host = config.database.fe_http_hosts[0]

        # Update security configuration
        if "security" in config_data:
            sec_config = config_data["security"]
            for key, value in sec_config.items():
                if hasattr(config.security, key):
                    setattr(config.security, key, value)
                    source_key = "auth_type" if key == "auth_type" else key
                    _mark_source(config, source_key, "config_file")

        # Update performance configuration
        if "performance" in config_data:
            perf_config = config_data["performance"]
            for key, value in perf_config.items():
                if hasattr(config.performance, key):
                    setattr(config.performance, key, value)

        # Update data quality configuration
        if "data_quality" in config_data:
            dq_config = config_data["data_quality"]
            for key, value in dq_config.items():
                if hasattr(config.data_quality, key):
                    setattr(config.data_quality, key, value)

        # Update logging configuration
        if "logging" in config_data:
            log_config = config_data["logging"]
            for key, value in log_config.items():
                if hasattr(config.logging, key):
                    setattr(config.logging, key, value)

        # Update monitoring configuration
        if "monitoring" in config_data:
            mon_config = config_data["monitoring"]
            for key, value in mon_config.items():
                if hasattr(config.monitoring, key):
                    setattr(config.monitoring, key, value)

        # Update ADBC configuration
        if "adbc" in config_data:
            adbc_config = config_data["adbc"]
            for key, value in adbc_config.items():
                if hasattr(config.adbc, key):
                    setattr(config.adbc, key, value)

        if "tool_exposure" in config_data:
            exposure_config = config_data["tool_exposure"]
            for key, value in exposure_config.items():
                if hasattr(config.tool_exposure, key):
                    setattr(config.tool_exposure, key, value)
            _mark_source(
                config,
                "mcp_tool_exposure_mode",
                "config_file",
            )

        if "administration" in config_data:
            administration_config = config_data["administration"]
            for key, value in administration_config.items():
                if hasattr(config.administration, key):
                    setattr(config.administration, key, value)

        if "capability" in config_data:
            capability_config = config_data["capability"]
            for key, value in capability_config.items():
                if hasattr(config.capability, key):
                    setattr(config.capability, key, value)

        if "governance" in config_data:
            governance_config = config_data["governance"]
            for key, value in governance_config.items():
                if hasattr(config.governance, key):
                    setattr(config.governance, key, value)

        if "lakehouse" in config_data:
            lakehouse_config = config_data["lakehouse"]
            for key, value in lakehouse_config.items():
                if hasattr(config.lakehouse, key):
                    setattr(config.lakehouse, key, value)

        if "semantic" in config_data:
            semantic_config = config_data["semantic"]
            for key, value in semantic_config.items():
                if hasattr(config.semantic, key):
                    setattr(config.semantic, key, value)

        # Custom configuration
        config.custom_config = config_data.get("custom", {})

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "server_name": self.server_name,
            "server_version": self.server_version,
            "server_host": self.server_host,
            "server_port": self.server_port,
            "mcp_allowed_hosts": self.mcp_allowed_hosts,
            "mcp_allowed_origins": self.mcp_allowed_origins,
            "enable_legacy_http_adapter": self.enable_legacy_http_adapter,
            "mcp_list_page_size": self.mcp_list_page_size,
            "mcp_tool_providers": self.mcp_tool_providers,
            "mcp_state_handle_ttl_seconds": self.mcp_state_handle_ttl_seconds,
            "temp_files_dir": self.temp_files_dir,
            "tool_exposure": {
                "mode": self.tool_exposure.mode,
            },
            "administration": {
                "enabled": self.administration.enabled,
                "require_confirmation": (
                    self.administration.require_confirmation
                ),
            },
            "capability": {
                "snapshot_ttl_seconds": (
                    self.capability.snapshot_ttl_seconds
                ),
                "probe_timeout_seconds": (
                    self.capability.probe_timeout_seconds
                ),
                "stale_grace_seconds": (
                    self.capability.stale_grace_seconds
                ),
            },
            "governance": {
                "max_sample_ratio": self.governance.max_sample_ratio,
                "max_audit_window_days": (
                    self.governance.max_audit_window_days
                ),
                "max_lineage_edges": self.governance.max_lineage_edges,
                "lineage_store_table": self.governance.lineage_store_table,
                "lineage_recent_event_minutes": (
                    self.governance.lineage_recent_event_minutes
                ),
            },
            "lakehouse": {
                "max_catalog_objects": self.lakehouse.max_catalog_objects,
                "max_catalog_databases": (
                    self.lakehouse.max_catalog_databases
                ),
                "max_snapshots": self.lakehouse.max_snapshots,
                "max_partitions": self.lakehouse.max_partitions,
                "max_variant_sample_rows": (
                    self.lakehouse.max_variant_sample_rows
                ),
                "max_variant_paths": self.lakehouse.max_variant_paths,
            },
            "semantic": {
                "enabled": self.semantic.enabled,
                "model_directory": self.semantic.model_directory,
                "binding_manifest": self.semantic.binding_manifest,
                "max_file_bytes": self.semantic.max_file_bytes,
                "max_total_bytes": self.semantic.max_total_bytes,
                "max_models": self.semantic.max_models,
                "max_depth": self.semantic.max_depth,
                "max_aliases": self.semantic.max_aliases,
                "max_string_bytes": self.semantic.max_string_bytes,
                "max_expression_bytes": self.semantic.max_expression_bytes,
                "context_max_bytes": self.semantic.context_max_bytes,
                "context_hard_max_bytes": (
                    self.semantic.context_hard_max_bytes
                ),
                "oauth_tools_enabled": self.semantic.oauth_tools_enabled,
                "oauth_resources_enabled": (
                    self.semantic.oauth_resources_enabled
                ),
            },
            "database": {
                "host": self.database.host,
                "hosts": self.database.hosts,
                "port": self.database.port,
                "user": self.database.user,
                "password": "***",  # Hide password
                "database": self.database.database,
                "charset": self.database.charset,
                "fe_http_host": self.database.fe_http_host,
                "fe_http_hosts": self.database.fe_http_hosts,
                "fe_http_port": self.database.fe_http_port,
                "be_hosts": self.database.be_hosts,
                "be_webserver_port": self.database.be_webserver_port,
                "http_connect_timeout_seconds": self.database.http_connect_timeout_seconds,
                "http_read_timeout_seconds": self.database.http_read_timeout_seconds,
                "http_total_timeout_seconds": self.database.http_total_timeout_seconds,
                "http_max_response_bytes": self.database.http_max_response_bytes,
                "fe_arrow_flight_sql_port": self.database.fe_arrow_flight_sql_port,
                "be_arrow_flight_sql_port": self.database.be_arrow_flight_sql_port,
                "min_connections": self.database.min_connections,  # Always 0, shown for reference
                "max_connections": self.database.max_connections,
                "connection_timeout": self.database.connection_timeout,
                "health_check_interval": self.database.health_check_interval,
                "max_connection_age": self.database.max_connection_age,
            },
            "security": {
                "auth_type": self.security.auth_type,
                "enable_token_auth": self.security.enable_token_auth,
                "enable_jwt_auth": self.security.enable_jwt_auth,
                "enable_oauth_auth": self.security.enable_oauth_auth,
                "oauth_enabled": self.security.oauth_enabled,
                "oauth_provider": self.security.oauth_provider,
                "oauth_issuer": self.security.oauth_issuer,
                "oauth_resource": self.security.oauth_resource,
                "oauth_audience": self.security.oauth_audience,
                "oauth_scopes": self.security.oauth_scopes,
                "oauth_required_scopes": self.security.oauth_required_scopes,
                "oauth_introspection_endpoint": self.security.oauth_introspection_endpoint,
                "oauth_default_roles": self.security.oauth_default_roles,
                "oauth_default_security_level": self.security.oauth_default_security_level,
                "oauth_trusted_domains": self.security.oauth_trusted_domains,
                "oauth_trusted_domain_security_level": self.security.oauth_trusted_domain_security_level,
                "oauth_role_security_levels": self.security.oauth_role_security_levels,
                "oauth_role_permissions": self.security.oauth_role_permissions,
                "oauth_default_permissions": self.security.oauth_default_permissions,
                "enable_doris_oauth_auth": self.security.enable_doris_oauth_auth,
                "allow_unauthenticated_non_loopback": self.security.allow_unauthenticated_non_loopback,
                "doris_oauth_base_url": self.security.doris_oauth_base_url,
                "doris_oauth_child_tools_enabled": self.security.doris_oauth_child_tools_enabled,
                "doris_oauth_child_tool_allowlist": self.security.doris_oauth_child_tool_allowlist,
                "doris_oauth_access_token_expire_seconds": self.security.doris_oauth_access_token_expire_seconds,
                "doris_oauth_refresh_token_expire_seconds": self.security.doris_oauth_refresh_token_expire_seconds,
                "doris_oauth_auth_code_expire_seconds": self.security.doris_oauth_auth_code_expire_seconds,
                "doris_oauth_gc_interval_seconds": self.security.doris_oauth_gc_interval_seconds,
                "doris_oauth_idle_timeout_seconds": self.security.doris_oauth_idle_timeout_seconds,
                "doris_oauth_login_page_title": self.security.doris_oauth_login_page_title,
                "doris_oauth_allowed_redirect_uris": self.security.doris_oauth_allowed_redirect_uris,
                "doris_oauth_clients_file": self.security.doris_oauth_clients_file,
                "doris_oauth_cimd_fetch_timeout_seconds": self.security.doris_oauth_cimd_fetch_timeout_seconds,
                "doris_oauth_cimd_max_document_bytes": self.security.doris_oauth_cimd_max_document_bytes,
                "doris_oauth_cimd_default_cache_seconds": self.security.doris_oauth_cimd_default_cache_seconds,
                "doris_oauth_cimd_max_cache_seconds": self.security.doris_oauth_cimd_max_cache_seconds,
                "doris_oauth_cimd_max_clients": self.security.doris_oauth_cimd_max_clients,
                "doris_oauth_dynamic_client_registration_mode": self.security.doris_oauth_dynamic_client_registration_mode,
                "enable_doris_oauth_production_dcr": self.security.enable_doris_oauth_production_dcr,
                "enable_doris_oauth_production_wildcard_redirects": self.security.enable_doris_oauth_production_wildcard_redirects,
                "doris_oauth_allow_insecure_http": self.security.doris_oauth_allow_insecure_http,
                "doris_oauth_trust_proxy_headers": self.security.doris_oauth_trust_proxy_headers,
                "doris_oauth_trusted_proxy_cidrs": self.security.doris_oauth_trusted_proxy_cidrs,
                "doris_oauth_dcr_max_clients": self.security.doris_oauth_dcr_max_clients,
                "doris_oauth_dcr_client_ttl_seconds": self.security.doris_oauth_dcr_client_ttl_seconds,
                "token_secret": "***",  # Hide secret key
                "token_expiry": self.security.token_expiry,
                "enable_security_check": self.security.enable_security_check,
                "blocked_keywords": self.security.blocked_keywords,
                "max_query_complexity": self.security.max_query_complexity,
                "max_result_rows": self.security.max_result_rows,
                "sensitive_tables": self.security.sensitive_tables,
                "enable_masking": self.security.enable_masking,
                "masking_rules": len(self.security.masking_rules),
            },
            "performance": {
                "enable_query_cache": self.performance.enable_query_cache,
                "cache_ttl": self.performance.cache_ttl,
                "max_cache_size": self.performance.max_cache_size,
                "max_concurrent_queries": self.performance.max_concurrent_queries,
                "query_timeout": self.performance.query_timeout,
                "default_result_rows": self.performance.default_result_rows,
                "max_result_bytes": self.performance.max_result_bytes,
                "connection_pool_size": self.performance.connection_pool_size,
                "idle_timeout": self.performance.idle_timeout,
                "max_response_content_size": self.performance.max_response_content_size,
            },
            "data_quality": {
                "max_columns_per_batch": self.data_quality.max_columns_per_batch,
                "default_sample_size": self.data_quality.default_sample_size,
                "small_table_threshold": self.data_quality.small_table_threshold,
                "medium_table_threshold": self.data_quality.medium_table_threshold,
                "enable_batch_analysis": self.data_quality.enable_batch_analysis,
                "batch_timeout": self.data_quality.batch_timeout,
                "enable_fast_mode": self.data_quality.enable_fast_mode,
                "fast_mode_sample_size": self.data_quality.fast_mode_sample_size,
                "enable_distribution_analysis": self.data_quality.enable_distribution_analysis,
                "histogram_bins": self.data_quality.histogram_bins,
                "percentile_levels": self.data_quality.percentile_levels,
            },
            "logging": {
                "level": self.logging.level,
                "format": self.logging.format,
                "file_path": self.logging.file_path,
                "max_file_size": self.logging.max_file_size,
                "backup_count": self.logging.backup_count,
                "enable_audit": self.logging.enable_audit,
                "audit_file_path": self.logging.audit_file_path,
                "enable_cleanup": self.logging.enable_cleanup,
                "max_age_days": self.logging.max_age_days,
                "cleanup_interval_hours": self.logging.cleanup_interval_hours,
            },
            "monitoring": {
                "enable_metrics": self.monitoring.enable_metrics,
                "metrics_port": self.monitoring.metrics_port,
                "metrics_path": self.monitoring.metrics_path,
                "health_check_port": self.monitoring.health_check_port,
                "health_check_path": self.monitoring.health_check_path,
                "enable_alerts": self.monitoring.enable_alerts,
                "alert_webhook_url": self.monitoring.alert_webhook_url,
            },
            "adbc": {
                "default_max_rows": self.adbc.default_max_rows,
                "default_timeout": self.adbc.default_timeout,
                "default_return_format": self.adbc.default_return_format,
                "connection_timeout": self.adbc.connection_timeout,
                "enabled": self.adbc.enabled,
            },
            "custom": self.custom_config,
        }

    def save_to_file(self, config_path: str) -> None:
        """Save configuration to file"""
        config_file = Path(config_path)
        config_file.parent.mkdir(parents=True, exist_ok=True)

        try:
            with open(config_file, "w", encoding="utf-8") as f:
                if config_file.suffix.lower() == ".json":
                    json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)
                else:
                    raise ValueError(f"Unsupported configuration file format: {config_file.suffix}")

        except Exception as e:
            raise ValueError(f"Failed to save configuration file: {e}")

    def validate(self) -> list[str]:
        """Validate configuration validity"""
        errors = []

        # Validate database configuration
        if not self.database.host:
            errors.append("Database host address cannot be empty")

        database_host_lists: tuple[tuple[str, Any], ...] = (
            ("Doris FE SQL hosts", self.database.hosts),
            ("Doris FE HTTP hosts", self.database.fe_http_hosts),
        )
        for field_name, hosts in database_host_lists:
            if not isinstance(hosts, list):
                errors.append(f"{field_name} must be a list")
                continue
            if len(hosts) > 16:
                errors.append(f"{field_name} cannot contain more than 16 entries")
            if any(
                not isinstance(host, str)
                or host != host.strip()
                or not host
                or "://" in host
                or any(character in host for character in "/\\?#@%")
                for host in hosts
            ):
                errors.append(
                    f"{field_name} must contain only hostname or IP address values"
                )

        if not (1 <= self.database.port <= 65535):
            errors.append("Database port must be in the range 1-65535")

        if not self.database.user:
            errors.append("Database username cannot be empty")

        if self.database.max_connections <= 0:
            errors.append("Maximum connections must be greater than 0")

        if (
            self.database.fe_http_host
            and (
                self.database.fe_http_host != self.database.fe_http_host.strip()
                or "://" in self.database.fe_http_host
                or any(
                    character in self.database.fe_http_host
                    for character in "/\\?#@%"
                )
            )
        ):
            errors.append("Doris FE HTTP host must be a hostname or IP address")

        if not (1 <= self.database.fe_http_port <= 65535):
            errors.append("Doris FE HTTP port must be in the range 1-65535")

        if not (1 <= self.database.be_webserver_port <= 65535):
            errors.append("Doris BE HTTP port must be in the range 1-65535")

        if self.database.http_connect_timeout_seconds <= 0:
            errors.append("Doris HTTP connect timeout must be greater than 0")

        if self.database.http_read_timeout_seconds <= 0:
            errors.append("Doris HTTP read timeout must be greater than 0")

        if self.database.http_total_timeout_seconds <= 0:
            errors.append("Doris HTTP total timeout must be greater than 0")

        if self.database.http_max_response_bytes <= 0:
            errors.append("Doris HTTP response byte limit must be greater than 0")

        if not 1 <= self.mcp_list_page_size <= 1000:
            errors.append("MCP list page size must be in the range 1-1000")

        if self.tool_exposure.mode not in {"hierarchical", "flat"}:
            errors.append(
                "MCP tool exposure mode must be hierarchical or flat"
            )
        errors.extend(
            administration_config_errors(
                enabled=self.administration.enabled,
                require_confirmation=(
                    self.administration.require_confirmation
                ),
            )
        )
        if not 1 <= self.capability.snapshot_ttl_seconds <= 86400:
            errors.append(
                "Capability snapshot TTL must be in the range 1-86400 seconds"
            )
        if not 1 <= self.capability.probe_timeout_seconds <= 60:
            errors.append(
                "Capability probe timeout must be in the range 1-60 seconds"
            )
        if not 0 <= self.capability.stale_grace_seconds <= 86400:
            errors.append(
                "Capability stale grace must be in the range 0-86400 seconds"
            )
        if not 0 < self.governance.max_sample_ratio <= 1:
            errors.append(
                "Governance maximum sample ratio must be in the range (0, 1]"
            )
        if not 1 <= self.governance.max_audit_window_days <= 365:
            errors.append(
                "Governance audit window must be in the range 1-365 days"
            )
        if not 1 <= self.governance.max_lineage_edges <= 5000:
            errors.append(
                "Governance lineage edge limit must be in the range 1-5000"
            )
        if not 1 <= self.governance.lineage_recent_event_minutes <= 525600:
            errors.append(
                "Governance recent lineage event window must be in the range "
                "1-525600 minutes"
            )
        if not 1 <= self.lakehouse.max_catalog_objects <= 500:
            errors.append(
                "Lakehouse catalog object limit must be in the range 1-500"
            )
        if not 1 <= self.lakehouse.max_catalog_databases <= 100:
            errors.append(
                "Lakehouse catalog database limit must be in the range 1-100"
            )
        if not 1 <= self.lakehouse.max_snapshots <= 500:
            errors.append(
                "Lakehouse snapshot limit must be in the range 1-500"
            )
        if not 1 <= self.lakehouse.max_partitions <= 1000:
            errors.append(
                "Lakehouse partition limit must be in the range 1-1000"
            )
        if not 1 <= self.lakehouse.max_variant_sample_rows <= 500:
            errors.append(
                "Lakehouse Variant sample limit must be in the range 1-500"
            )
        if not 1 <= self.lakehouse.max_variant_paths <= 2000:
            errors.append(
                "Lakehouse Variant path limit must be in the range 1-2000"
            )
        if self.semantic.enabled and (
            not self.semantic.model_directory or not self.semantic.binding_manifest
        ):
            errors.append(
                "Enabled Ossie support requires model directory and binding manifest"
            )
        semantic_integer_limits = (
            (
                "file byte limit",
                self.semantic.max_file_bytes,
                1024,
                16 * 1024 * 1024,
            ),
            (
                "total byte limit",
                self.semantic.max_total_bytes,
                1024,
                64 * 1024 * 1024,
            ),
            ("model limit", self.semantic.max_models, 1, 256),
            ("depth limit", self.semantic.max_depth, 4, 64),
            ("alias limit", self.semantic.max_aliases, 0, 256),
            (
                "string byte limit",
                self.semantic.max_string_bytes,
                256,
                64 * 1024,
            ),
            (
                "expression byte limit",
                self.semantic.max_expression_bytes,
                64,
                16 * 1024,
            ),
            (
                "context byte limit",
                self.semantic.context_max_bytes,
                1024,
                64 * 1024,
            ),
            (
                "context hard byte limit",
                self.semantic.context_hard_max_bytes,
                1024,
                64 * 1024,
            ),
        )
        for label, value, minimum, maximum in semantic_integer_limits:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not minimum <= value <= maximum
            ):
                errors.append(
                    f"Ossie {label} must be in the range {minimum}-{maximum}"
                )
        if (
            isinstance(self.semantic.max_total_bytes, int)
            and isinstance(self.semantic.max_file_bytes, int)
            and self.semantic.max_total_bytes < self.semantic.max_file_bytes
        ):
            errors.append(
                "Ossie total byte limit must not be smaller than file byte limit"
            )
        if (
            isinstance(self.semantic.context_max_bytes, int)
            and isinstance(self.semantic.context_hard_max_bytes, int)
            and self.semantic.context_max_bytes
            > self.semantic.context_hard_max_bytes
        ):
            errors.append(
                "Ossie context byte limit must not exceed the hard byte limit"
            )

        raw_tool_providers: Any = self.mcp_tool_providers
        if not isinstance(raw_tool_providers, list):
            errors.append("MCP tool providers must be a list")
        else:
            try:
                normalize_tool_provider_names(raw_tool_providers)
            except ToolProviderError as exc:
                errors.append(str(exc))

        if len(self.mcp_state_handle_secret.encode("utf-8")) < 32:
            errors.append("MCP state handle secret must contain at least 32 bytes")

        if not 1 <= self.mcp_state_handle_ttl_seconds <= 3600:
            errors.append("MCP state handle TTL must be in the range 1-3600 seconds")

        # Validate security configuration
        if self.security.auth_type not in ["token", "basic", "oauth", "jwt"]:
            errors.append("Authentication type must be one of token, basic, oauth, or jwt")

        if self.security.token_expiry <= 0:
            errors.append("Token expiry time must be greater than 0")

        if not 0 <= self.security.token_db_validation_ttl_seconds <= 3600:
            errors.append(
                "Token database validation TTL must be in the range 0-3600 seconds"
            )

        if self.security.max_query_complexity <= 0:
            errors.append("Maximum query complexity must be greater than 0")

        if self.security.max_result_rows <= 0:
            errors.append("Maximum result rows must be greater than 0")
        elif self.security.max_result_rows > ABSOLUTE_MAX_RESULT_ROWS:
            errors.append(
                "Maximum result rows must not exceed "
                f"{ABSOLUTE_MAX_RESULT_ROWS}"
            )

        # Validate performance configuration
        if self.performance.cache_ttl <= 0:
            errors.append("Cache TTL must be greater than 0")

        if self.performance.max_concurrent_queries <= 0:
            errors.append("Maximum concurrent queries must be greater than 0")

        if self.performance.query_timeout <= 0:
            errors.append("Query timeout must be greater than 0")
        elif (
            self.performance.query_timeout
            > ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS
        ):
            errors.append(
                "Query timeout must not exceed "
                f"{ABSOLUTE_MAX_QUERY_TIMEOUT_SECONDS} seconds"
            )

        if self.performance.default_result_rows <= 0:
            errors.append("Default result rows must be greater than 0")
        elif self.performance.default_result_rows > self.security.max_result_rows:
            errors.append(
                "Default result rows must not exceed the configured "
                f"maximum result rows ({self.security.max_result_rows})"
            )

        if not (
            MIN_RESULT_BYTES
            <= self.performance.max_result_bytes
            <= ABSOLUTE_MAX_RESULT_BYTES
        ):
            errors.append(
                "Maximum result bytes must be in the range "
                f"{MIN_RESULT_BYTES}-{ABSOLUTE_MAX_RESULT_BYTES}"
            )

        # Validate data quality configuration
        if self.data_quality.max_columns_per_batch <= 0:
            errors.append("Max columns per batch must be greater than 0")

        if self.data_quality.default_sample_size <= 0:
            errors.append("Default sample size must be greater than 0")

        if self.data_quality.small_table_threshold <= 0:
            errors.append("Small table threshold must be greater than 0")

        if self.data_quality.medium_table_threshold <= 0:
            errors.append("Medium table threshold must be greater than 0")

        if self.data_quality.small_table_threshold >= self.data_quality.medium_table_threshold:
            errors.append("Small table threshold must be less than medium table threshold")

        if self.data_quality.batch_timeout <= 0:
            errors.append("Batch timeout must be greater than 0")

        if self.data_quality.fast_mode_sample_size <= 0:
            errors.append("Fast mode sample size must be greater than 0")

        if self.data_quality.histogram_bins <= 0:
            errors.append("Histogram bins must be greater than 0")

        # Validate logging configuration
        if self.logging.level not in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
            errors.append("Log level must be one of DEBUG, INFO, WARNING, ERROR, or CRITICAL")

        if self.logging.max_file_size <= 0:
            errors.append("Maximum log file size must be greater than 0")

        if self.logging.backup_count < 0:
            errors.append("Log backup count cannot be negative")

        if self.logging.max_age_days <= 0:
            errors.append("Log max age days must be greater than 0")

        if self.logging.cleanup_interval_hours <= 0:
            errors.append("Log cleanup interval hours must be greater than 0")

        # Validate monitoring configuration
        if not (1 <= self.monitoring.metrics_port <= 65535):
            errors.append("Monitoring port must be in the range 1-65535")

        if not (1 <= self.monitoring.health_check_port <= 65535):
            errors.append("Health check port must be in the range 1-65535")

        # Validate ADBC configuration
        if self.adbc.default_max_rows <= 0:
            errors.append("ADBC default max rows must be greater than 0")
        elif self.adbc.default_max_rows > self.security.max_result_rows:
            errors.append(
                "ADBC default max rows must not exceed the configured "
                f"maximum result rows ({self.security.max_result_rows})"
            )

        if self.adbc.default_timeout <= 0:
            errors.append("ADBC default timeout must be greater than 0")
        elif self.adbc.default_timeout > self.performance.query_timeout:
            errors.append(
                "ADBC default timeout must not exceed the configured query "
                f"timeout ({self.performance.query_timeout} seconds)"
            )

        if self.adbc.default_return_format not in ["arrow", "pandas", "dict"]:
            errors.append("ADBC default return format must be one of arrow, pandas, or dict")

        if self.adbc.connection_timeout <= 0:
            errors.append("ADBC connection timeout must be greater than 0")

        return errors

    def get_connection_string(self) -> str:
        """Get database connection string (hide password)"""
        return f"mysql://{self.database.user}:***@{self.database.host}:{self.database.port}/{self.database.database}"

    def get_config_summary(self) -> dict[str, Any]:
        """Get configuration summary information"""
        return {
            "server": f"{self.server_name} v{self.server_version}",
            "database": f"{self.database.host}:{self.database.port}/{self.database.database}",
            "connection_pool": f"0-{self.database.max_connections} (min fixed at 0 for stability)",
            "security": {
                "auth_type": self.security.auth_type,
                "masking_enabled": self.security.enable_masking,
                "blocked_keywords_count": len(self.security.blocked_keywords),
            },
            "performance": {
                "cache_enabled": self.performance.enable_query_cache,
                "max_concurrent": self.performance.max_concurrent_queries,
                "query_timeout": self.performance.query_timeout,
            },
            "monitoring": {
                "metrics_enabled": self.monitoring.enable_metrics,
                "alerts_enabled": self.monitoring.enable_alerts,
            },
            "tool_exposure": {
                "mode": self.tool_exposure.mode,
            },
            "administration": {
                "enabled": self.administration.enabled,
                "require_confirmation": (
                    self.administration.require_confirmation
                ),
                "status": "reserved",
            },
            "capability": {
                "snapshot_ttl_seconds": (
                    self.capability.snapshot_ttl_seconds
                ),
                "probe_timeout_seconds": (
                    self.capability.probe_timeout_seconds
                ),
                "stale_grace_seconds": (
                    self.capability.stale_grace_seconds
                ),
            },
            "semantic": {
                "enabled": self.semantic.enabled,
                "context_max_bytes": self.semantic.context_max_bytes,
                "oauth_tools_enabled": self.semantic.oauth_tools_enabled,
                "oauth_resources_enabled": (
                    self.semantic.oauth_resources_enabled
                ),
            },
        }


def build_auth_config_inputs(config: DorisConfig, requested_workers: int | None = None) -> AuthConfigInputs:
    """Build source-aware auth inputs from a DorisConfig."""
    workers_value = requested_workers
    if workers_value is None:
        workers_value = getattr(config, "workers", 1)
    explicit_sources = getattr(config, "_explicit_sources", {})
    workers_source = explicit_sources.get("workers", "default")
    transport_source = explicit_sources.get("transport", "default")

    return AuthConfigInputs(
        enable_token_auth=_config_value(config, "enable_token_auth", config.security.enable_token_auth),
        enable_jwt_auth=_config_value(config, "enable_jwt_auth", config.security.enable_jwt_auth),
        enable_external_oauth_auth=_config_value(config, "enable_oauth_auth", config.security.enable_oauth_auth),
        oauth_enabled=_config_value(config, "oauth_enabled", config.security.oauth_enabled),
        enable_doris_oauth_auth=_config_value(
            config, "enable_doris_oauth_auth", config.security.enable_doris_oauth_auth
        ),
        legacy_auth_type=_config_value(config, "auth_type", config.security.auth_type),
        transport=ConfigValue(config.transport, transport_source, transport_source != "default"),
        workers=ConfigValue(workers_value, workers_source, workers_source != "default"),
    )


def _configured_static_tokens(
    security_config: SecurityConfig,
) -> list[tuple[str, Any, bool, bool]]:
    """Load source labels, credentials, active flags, and digest markers."""
    configured: list[tuple[str, Any, bool, bool]] = []
    for name, value in os.environ.items():
        if is_static_token_environment_variable(name):
            configured.append((name, value, True, False))

    token_file = Path(security_config.token_file_path)
    if not token_file.exists():
        return configured

    try:
        token_data = json.loads(token_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuthConfigError(f"Unable to load static token file {token_file}: {exc}") from exc

    if isinstance(token_data, dict) and "tokens" in token_data:
        token_entries = token_data["tokens"]
    elif isinstance(token_data, list):
        token_entries = token_data
    else:
        raise AuthConfigError(
            f"Static token file {token_file} must contain a tokens array"
        )
    if not isinstance(token_entries, list):
        raise AuthConfigError(
            f"Static token file {token_file} must contain a tokens array"
        )

    for index, token_entry in enumerate(token_entries):
        if not isinstance(token_entry, dict):
            raise AuthConfigError(
                f"Static token file {token_file} entry {index} must be an object"
            )
        token_id = str(token_entry.get("token_id") or "").strip()
        if not token_id:
            raise AuthConfigError(
                f"Static token file {token_file} entry {index} requires token_id"
            )
        has_raw_token = "token" in token_entry
        has_token_digest = "token_digest" in token_entry
        if has_raw_token == has_token_digest:
            raise AuthConfigError(
                f"Static token file {token_file} entry {token_id} must contain "
                "exactly one of token or token_digest"
            )
        credential = (
            token_entry.get("token_digest")
            if has_token_digest
            else token_entry.get("token")
        )
        configured.append(
            (
                f"{token_file}:{token_id}",
                credential,
                _str_to_bool(token_entry.get("is_active", True)),
                has_token_digest,
            )
        )
    return configured


def _validate_static_token_bootstrap(config: DorisConfig) -> None:
    """Require at least one active high-entropy token when static auth is enabled."""
    configured = _configured_static_tokens(config.security)
    for setting, credential, _active, is_digest in configured:
        try:
            if is_digest:
                normalize_token_digest(
                    credential,
                    setting=f"{setting} token_digest",
                )
            else:
                validate_high_entropy_secret(credential, setting=setting)
        except ValueError as exc:
            raise AuthConfigError(str(exc)) from exc
    if not any(active for _setting, _credential, active, _is_digest in configured):
        raise AuthConfigError(
            "Token authentication requires at least one active high-entropy credential. "
            "Set TOKEN_<ID> or populate TOKEN_FILE_PATH before enabling it."
        )


def normalize_effective_auth_config(
    config: DorisConfig,
    requested_workers: int | None = None,
) -> EffectiveAuthConfig:
    """Normalize authentication configuration and attach it to the config."""
    inputs = build_auth_config_inputs(config, requested_workers=requested_workers)
    warnings: list[str] = []

    auth_type = str(inputs.legacy_auth_type.value or "").strip().lower()
    if auth_type and auth_type not in {"token", "basic", "oauth", "jwt"}:
        raise AuthConfigError(f"Unsupported AUTH_TYPE: {auth_type}")
    try:
        config.security.token_hash_algorithm = normalize_token_hash_algorithm(
            config.security.token_hash_algorithm
        )
    except ValueError as exc:
        raise AuthConfigError(str(exc)) from exc
    if not 0 <= config.security.token_db_validation_ttl_seconds <= 3600:
        raise AuthConfigError(
            "TOKEN_DB_VALIDATION_TTL_SECONDS must be in the range 0-3600"
        )

    modern_auth_explicit = any(
        [
            inputs.enable_token_auth.explicit,
            inputs.enable_jwt_auth.explicit,
            inputs.enable_external_oauth_auth.explicit,
            inputs.oauth_enabled.explicit,
            inputs.enable_doris_oauth_auth.explicit,
        ]
    )

    enable_token_auth = _str_to_bool(inputs.enable_token_auth.value)
    enable_jwt_auth = _str_to_bool(inputs.enable_jwt_auth.value)
    enable_external_oauth_auth = _str_to_bool(inputs.enable_external_oauth_auth.value)
    enable_doris_oauth_auth = _str_to_bool(inputs.enable_doris_oauth_auth.value)

    explicit_sources = getattr(config, "_explicit_sources", {})
    legacy_doris_oauth_fields = (
        "doris_oauth_db_tools_enabled",
        "doris_oauth_db_tool_allowlist",
        "doris_oauth_query_tools_enabled",
        "doris_oauth_query_tool_allowlist",
        "doris_oauth_explain_tools_enabled",
        "doris_oauth_explain_tool_allowlist",
    )
    configured_legacy_fields = [
        field_name
        for field_name in legacy_doris_oauth_fields
        if explicit_sources.get(field_name, "default") != "default"
    ]
    if configured_legacy_fields:
        raise AuthConfigError(
            "Legacy Doris OAuth tool-bucket settings are not supported. "
            "Use DORIS_OAUTH_CHILD_TOOLS_ENABLED and "
            "DORIS_OAUTH_CHILD_TOOL_ALLOWLIST with formal domain.child "
            "feature IDs."
        )

    config.security.doris_oauth_db_tool_allowlist = _validate_doris_oauth_metadata_tool_allowlist(
        config.security.doris_oauth_db_tool_allowlist
    )
    child_allowlist = _coerce_csv_config(
        config.security.doris_oauth_child_tool_allowlist
    )
    from ..tools.domain_catalog import FORMAL_CHILD_FEATURE_IDS

    invalid_child_features = set(child_allowlist) - set(
        FORMAL_CHILD_FEATURE_IDS
    )
    if invalid_child_features:
        invalid_list = ", ".join(sorted(invalid_child_features))
        raise AuthConfigError(
            "DORIS_OAUTH_CHILD_TOOL_ALLOWLIST can only contain formal "
            f"domain.child feature IDs; invalid entries: {invalid_list}"
        )
    config.security.doris_oauth_child_tool_allowlist = list(
        dict.fromkeys(child_allowlist)
    )
    query_allowlist = _coerce_csv_config(config.security.doris_oauth_query_tool_allowlist)
    invalid_query_tools = set(query_allowlist) - DORIS_OAUTH_QUERY_TOOL_SET
    if invalid_query_tools:
        invalid_list = ", ".join(sorted(invalid_query_tools))
        raise AuthConfigError(
            "DORIS_OAUTH_QUERY_TOOL_ALLOWLIST can only contain exec_query; "
            f"invalid entries: {invalid_list}"
        )
    config.security.doris_oauth_query_tool_allowlist = list(dict.fromkeys(query_allowlist))

    explain_allowlist = _coerce_csv_config(config.security.doris_oauth_explain_tool_allowlist)
    invalid_explain_tools = set(explain_allowlist) - DORIS_OAUTH_EXPLAIN_TOOL_SET
    if invalid_explain_tools:
        invalid_list = ", ".join(sorted(invalid_explain_tools))
        raise AuthConfigError(
            "DORIS_OAUTH_EXPLAIN_TOOL_ALLOWLIST can only contain get_sql_explain; "
            f"invalid entries: {invalid_list}"
        )
    config.security.doris_oauth_explain_tool_allowlist = list(dict.fromkeys(explain_allowlist))

    if inputs.enable_external_oauth_auth.explicit and inputs.oauth_enabled.explicit:
        if _str_to_bool(inputs.enable_external_oauth_auth.value) != _str_to_bool(inputs.oauth_enabled.value):
            raise AuthConfigError("ENABLE_OAUTH_AUTH and oauth_enabled/OAUTH_ENABLED explicitly conflict")

    if inputs.oauth_enabled.explicit:
        enable_external_oauth_auth = _str_to_bool(inputs.oauth_enabled.value)

    if not modern_auth_explicit and inputs.legacy_auth_type.explicit:
        if auth_type == "token":
            enable_token_auth = True
            warnings.append("AUTH_TYPE=token is deprecated; use ENABLE_TOKEN_AUTH=true")
        elif auth_type == "jwt":
            enable_jwt_auth = True
            warnings.append("AUTH_TYPE=jwt is deprecated; use ENABLE_JWT_AUTH=true")
        elif auth_type == "oauth":
            enable_external_oauth_auth = True
            warnings.append("AUTH_TYPE=oauth is deprecated; use ENABLE_OAUTH_AUTH=true")
        elif auth_type == "basic":
            warnings.append("AUTH_TYPE=basic is legacy; no HTTP basic verifier is enabled by default")
    elif inputs.legacy_auth_type.explicit:
        if auth_type == "oauth" and enable_doris_oauth_auth:
            raise AuthConfigError("AUTH_TYPE=oauth conflicts with ENABLE_DORIS_OAUTH_AUTH=true")
        warnings.append("AUTH_TYPE is deprecated and ignored because explicit auth switches are set")

    if enable_doris_oauth_auth and enable_external_oauth_auth:
        raise AuthConfigError("Doris OAuth and external OAuth cannot be enabled together")

    if enable_token_auth:
        _validate_static_token_bootstrap(config)

    if (
        config.security.enable_http_token_management
        and config.security.require_admin_auth
    ):
        try:
            validate_high_entropy_secret(
                config.security.token_management_admin_token,
                setting="TOKEN_MANAGEMENT_ADMIN_TOKEN",
            )
        except ValueError as exc:
            raise AuthConfigError(str(exc)) from exc

    if enable_external_oauth_auth:
        _normalize_external_oauth_authorization_config(config.security)
        config.security.oauth_issuer = _validate_external_oauth_url(
            config.security.oauth_issuer,
            setting="OAUTH_ISSUER",
        )
        config.security.oauth_resource = _validate_external_oauth_url(
            config.security.oauth_resource,
            setting="OAUTH_RESOURCE",
            allow_query=True,
        )
        config.security.oauth_audience = str(
            config.security.oauth_audience
            or config.security.oauth_resource
        ).strip()
        if not config.security.oauth_audience:
            raise AuthConfigError("OAUTH_AUDIENCE is required")

        config.security.oauth_scopes = list(
            dict.fromkeys(
                _coerce_scope_config(config.security.oauth_scopes)
            )
        )
        if not config.security.oauth_scopes:
            raise AuthConfigError(
                "OAUTH_SCOPE must contain at least one allowed scope"
            )
        required_scopes = _coerce_scope_config(
            config.security.oauth_required_scopes
        )
        if not required_scopes:
            required_scopes = list(config.security.oauth_scopes)
        if not set(required_scopes) <= set(config.security.oauth_scopes):
            raise AuthConfigError(
                "OAUTH_REQUIRED_SCOPE must be a subset of OAUTH_SCOPE"
            )
        config.security.oauth_required_scopes = list(
            dict.fromkeys(required_scopes)
        )

        discovery_url = str(config.security.oidc_discovery_url or "").strip()
        introspection_url = str(
            config.security.oauth_introspection_endpoint or ""
        ).strip()
        if not discovery_url and not introspection_url:
            raise AuthConfigError(
                "OAUTH_INTROSPECTION_URL or OAUTH_DISCOVERY_URL is required"
            )
        if discovery_url:
            config.security.oidc_discovery_url = (
                _validate_external_oauth_url(
                    discovery_url,
                    setting="OAUTH_DISCOVERY_URL",
                )
            )
        if introspection_url:
            config.security.oauth_introspection_endpoint = (
                _validate_external_oauth_url(
                    introspection_url,
                    setting="OAUTH_INTROSPECTION_URL",
                )
            )
        if config.security.oauth_userinfo_endpoint:
            config.security.oauth_userinfo_endpoint = (
                _validate_external_oauth_url(
                    config.security.oauth_userinfo_endpoint,
                    setting="OAUTH_USERINFO_URL",
                )
            )
        elif not discovery_url:
            raise AuthConfigError(
                "OAUTH_USERINFO_URL or OAUTH_DISCOVERY_URL is required"
            )

        config.security.oauth_introspection_client_id = str(
            config.security.oauth_introspection_client_id
            or config.security.oauth_client_id
        ).strip()
        config.security.oauth_introspection_client_secret = str(
            config.security.oauth_introspection_client_secret
            or config.security.oauth_client_secret
        )
        if (
            not config.security.oauth_introspection_client_id
            or not config.security.oauth_introspection_client_secret
        ):
            raise AuthConfigError(
                "OAuth introspection client credentials are required"
            )

    transport = str(inputs.transport.value or "stdio")
    requested = int(inputs.workers.value if inputs.workers.value is not None else 1)
    effective_workers = multiprocessing.cpu_count() if requested == 0 else requested

    if enable_doris_oauth_auth and transport == "stdio":
        raise AuthConfigError("Doris OAuth requires HTTP transport")
    if enable_doris_oauth_auth and effective_workers > 1:
        raise AuthConfigError("Doris OAuth initial implementation requires a single worker")
    if enable_doris_oauth_auth and not config.database.host:
        raise AuthConfigError("DORIS_HOST is required when Doris OAuth is enabled")
    if enable_doris_oauth_auth and not config.database.user:
        raise AuthConfigError("DORIS_USER service account is required when Doris OAuth is enabled")
    if enable_doris_oauth_auth:
        base_url = config.security.doris_oauth_base_url.rstrip("/")
        if not base_url:
            raise AuthConfigError("DORIS_OAUTH_BASE_URL is required when Doris OAuth is enabled")
        parsed_base_url = urlparse(base_url)
        if not parsed_base_url.scheme or not parsed_base_url.netloc:
            raise AuthConfigError("DORIS_OAUTH_BASE_URL must be an absolute URL")
        if parsed_base_url.scheme == "http" and not _is_loopback_url(base_url):
            if not config.security.doris_oauth_allow_insecure_http:
                raise AuthConfigError("Non-loopback Doris OAuth base URL must use HTTPS")
        elif parsed_base_url.scheme not in {"http", "https"}:
            raise AuthConfigError("DORIS_OAUTH_BASE_URL must use HTTP or HTTPS")

        mode = config.security.doris_oauth_dynamic_client_registration_mode
        if mode not in {"auto", "disabled", "enabled"}:
            raise AuthConfigError("DORIS_OAUTH_DYNAMIC_CLIENT_REGISTRATION_MODE must be auto, disabled, or enabled")
        if mode == "enabled" and not _is_loopback_url(base_url):
            if not config.security.enable_doris_oauth_production_dcr:
                raise AuthConfigError("Production Doris OAuth DCR requires ENABLE_DORIS_OAUTH_PRODUCTION_DCR=true")
        if not 1 <= int(config.security.doris_oauth_cimd_fetch_timeout_seconds) <= 30:
            raise AuthConfigError(
                "doris_oauth_cimd_fetch_timeout_seconds must be between 1 and 30"
            )
        if not 1024 <= int(config.security.doris_oauth_cimd_max_document_bytes) <= 65536:
            raise AuthConfigError(
                "doris_oauth_cimd_max_document_bytes must be between 1024 and 65536"
            )
        default_cache = int(config.security.doris_oauth_cimd_default_cache_seconds)
        max_cache = int(config.security.doris_oauth_cimd_max_cache_seconds)
        if not 0 <= default_cache <= max_cache:
            raise AuthConfigError(
                "doris_oauth_cimd_default_cache_seconds must be between 0 and "
                "doris_oauth_cimd_max_cache_seconds"
            )
        if not 1 <= max_cache <= 86400:
            raise AuthConfigError(
                "doris_oauth_cimd_max_cache_seconds must be between 1 and 86400"
            )
        if int(config.security.doris_oauth_cimd_max_clients) <= 0:
            raise AuthConfigError(
                "doris_oauth_cimd_max_clients must be greater than zero"
            )
        if config.security.doris_oauth_trust_proxy_headers and not config.security.doris_oauth_trusted_proxy_cidrs:
            raise AuthConfigError("Trusted proxy CIDRs are required when Doris OAuth proxy headers are trusted")

        ttl_limits = {
            "doris_oauth_access_token_expire_seconds": 86400,
            "doris_oauth_refresh_token_expire_seconds": 30 * 86400,
            "doris_oauth_auth_code_expire_seconds": 1800,
            "doris_oauth_gc_interval_seconds": 3600,
            "doris_oauth_dcr_client_ttl_seconds": 30 * 86400,
        }
        for field_name, upper_bound in ttl_limits.items():
            value = getattr(config.security, field_name)
            if int(value) <= 0 or int(value) > upper_bound:
                raise AuthConfigError(f"{field_name} must be between 1 and {upper_bound}")
        idle_timeout = config.security.doris_oauth_idle_timeout_seconds
        if idle_timeout is not None and (int(idle_timeout) <= 0 or int(idle_timeout) > 7 * 86400):
            raise AuthConfigError("doris_oauth_idle_timeout_seconds must be between 1 and 604800")
        for field_name in (
            "doris_oauth_rate_limit_window_seconds",
            "doris_oauth_login_rate_limit_per_ip",
            "doris_oauth_login_rate_limit_per_user",
            "doris_oauth_login_rate_limit_per_client",
            "doris_oauth_login_rate_limit_per_txn",
            "doris_oauth_dcr_rate_limit_per_ip",
            "doris_oauth_authorize_rate_limit_per_ip",
            "doris_oauth_token_rate_limit_per_ip",
            "doris_oauth_token_rate_limit_per_client",
            "doris_oauth_revoke_rate_limit_per_ip",
            "doris_oauth_revoke_rate_limit_per_client",
            "doris_oauth_api_auth_token_rate_limit_per_ip",
            "doris_oauth_api_auth_token_rate_limit_per_user",
            "doris_oauth_api_auth_refresh_rate_limit_per_ip",
            "doris_oauth_api_auth_refresh_rate_limit_per_client",
            "doris_oauth_dcr_max_clients",
        ):
            if int(getattr(config.security, field_name)) <= 0:
                raise AuthConfigError(f"{field_name} must be greater than 0")

    methods: list[str] = []
    if enable_doris_oauth_auth:
        methods.append("doris_oauth")
    if enable_token_auth:
        methods.append("token")
    if enable_jwt_auth:
        methods.append("jwt")
    if enable_external_oauth_auth:
        methods.append("external_oauth")

    bind_warning = validate_http_bind_auth_policy(
        transport=transport,
        host=config.server_host,
        auth_methods=tuple(methods),
        allow_unauthenticated_non_loopback=(
            config.security.allow_unauthenticated_non_loopback
        ),
    )
    if bind_warning:
        warnings.append(bind_warning)

    if enable_doris_oauth_auth:
        discovery_mode = "doris_oauth"
    elif enable_external_oauth_auth:
        discovery_mode = "external_oauth"
    else:
        discovery_mode = "none"

    source_summary = {
        "enable_token_auth": inputs.enable_token_auth.source,
        "enable_jwt_auth": inputs.enable_jwt_auth.source,
        "enable_oauth_auth": inputs.enable_external_oauth_auth.source,
        "oauth_enabled": inputs.oauth_enabled.source,
        "enable_doris_oauth_auth": inputs.enable_doris_oauth_auth.source,
        "auth_type": inputs.legacy_auth_type.source,
        "transport": inputs.transport.source,
        "workers": inputs.workers.source,
    }

    effective = EffectiveAuthConfig(
        enable_token_auth=enable_token_auth,
        enable_jwt_auth=enable_jwt_auth,
        enable_external_oauth_auth=enable_external_oauth_auth,
        enable_doris_oauth_auth=enable_doris_oauth_auth,
        auth_methods=tuple(methods),
        oauth_discovery_mode=discovery_mode,
        doris_oauth_base_url=config.security.doris_oauth_base_url.rstrip("/"),
        external_oauth_issuer=(
            config.security.oauth_issuer if enable_external_oauth_auth else ""
        ),
        external_oauth_resource=(
            config.security.oauth_resource if enable_external_oauth_auth else ""
        ),
        external_oauth_scopes=(
            tuple(config.security.oauth_scopes)
            if enable_external_oauth_auth
            else ()
        ),
        external_oauth_required_scopes=(
            tuple(config.security.oauth_required_scopes)
            if enable_external_oauth_auth
            else ()
        ),
        transport=transport,
        requested_workers=requested,
        effective_workers=effective_workers,
        legacy_auth_type=auth_type,
        auth_config_warnings=tuple(warnings),
        source_summary=source_summary,
    )
    config.effective_auth = effective
    config._auth_inputs = inputs
    return effective


def get_effective_auth_config(config: DorisConfig) -> EffectiveAuthConfig:
    """Return previously normalized auth config."""
    effective = config.effective_auth
    if effective is None:
        raise AuthConfigError("Effective auth config has not been normalized")
    return effective


class ConfigManager:
    """Configuration manager class"""

    def __init__(self, config: DorisConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def setup_logging(self) -> None:
        """Setup logging configuration using enhanced logger"""
        import sys

        from .logger import setup_logging

        # Determine log directory
        log_dir = "logs"
        if self.config.logging.file_path:
            # Extract directory from file path if provided
            from pathlib import Path
            log_dir = str(Path(self.config.logging.file_path).parent)

        # Detect if we're in stdio mode by checking if this is likely MCP stdio communication
        # In stdio mode, we shouldn't output to console as it interferes with JSON protocol
        is_stdio_mode = (
            self.config.transport == "stdio" or
            "--transport" in sys.argv and "stdio" in sys.argv or
            not sys.stdout.isatty()  # Not a terminal (likely piped/redirected)
        )

        # Setup enhanced logging with cleanup functionality
        setup_logging(
            level=self.config.logging.level,
            log_dir=log_dir,
            enable_console=not is_stdio_mode,  # Disable console logging in stdio mode
            enable_file=True,
            enable_audit=self.config.logging.enable_audit,
            audit_file=self.config.logging.audit_file_path,
            max_file_size=self.config.logging.max_file_size,
            backup_count=self.config.logging.backup_count,
            enable_cleanup=self.config.logging.enable_cleanup,
            max_age_days=self.config.logging.max_age_days,
            cleanup_interval_hours=self.config.logging.cleanup_interval_hours
        )

        # Update logger to use new system
        self.logger = get_logger(__name__)

        self.logger.info("Enhanced logging system with cleanup initialized successfully")
        self.logger.info(f"Log directory: {log_dir}")
        self.logger.info(f"Log level: {self.config.logging.level}")
        self.logger.info(f"Audit logging: {'Enabled' if self.config.logging.enable_audit else 'Disabled'}")
        self.logger.info(f"Log cleanup: {'Enabled' if self.config.logging.enable_cleanup else 'Disabled'}")
        if self.config.logging.enable_cleanup:
            self.logger.info(f"Cleanup config: Max age {self.config.logging.max_age_days} days, interval {self.config.logging.cleanup_interval_hours}h")

    def validate_config(self) -> bool:
        """Validate configuration"""
        errors = self.config.validate()
        if errors:
            self.logger.error("Configuration validation failed:")
            for error in errors:
                self.logger.error(f"  - {error}")
            return False

        self.logger.info("Configuration validation passed")
        return True

    def log_config_summary(self) -> None:
        """Log configuration summary"""
        summary = self.config.get_config_summary()
        self.logger.info("Configuration Summary:")
        self.logger.info(f"  Server: {summary['server']}")
        self.logger.info(f"  Database: {summary['database']}")
        self.logger.info(f"  Connection Pool: {summary['connection_pool']}")
        self.logger.info(f"  Security: {summary['security']}")
        self.logger.info(f"  Performance: {summary['performance']}")
        self.logger.info(f"  Monitoring: {summary['monitoring']}")


def create_default_config_file(config_path: str) -> None:
    """Create default configuration file"""
    config = DorisConfig()
    config.save_to_file(config_path)
    print(f"Default configuration file created: {config_path}")


# Example usage
if __name__ == "__main__":
    # Create default configuration
    config = DorisConfig()

    # Load from environment variables
    # config = DorisConfig.from_env()

    # Load from file
    # config = DorisConfig.from_file("config.json")

    # Validate configuration
    config_manager = ConfigManager(config)
    if config_manager.validate_config():
        config_manager.setup_logging()
        config_manager.log_config_summary()

        # Save configuration
        config.save_to_file("example_config.json")
        print("Configuration saved to example_config.json")
    else:
        print("Configuration validation failed")

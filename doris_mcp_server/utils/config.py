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
import os
import multiprocessing
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

from .logger import get_logger


class AuthConfigError(ValueError):
    """Raised when authentication configuration is inconsistent."""


DORIS_OAUTH_METADATA_TOOL_ALLOWLIST_DEFAULT = [
    "get_db_list",
    "get_db_table_list",
    "get_table_schema",
    "get_table_comment",
    "get_table_column_comments",
    "get_table_indexes",
    "get_catalog_list",
]
DORIS_OAUTH_METADATA_TOOL_SET = frozenset(DORIS_OAUTH_METADATA_TOOL_ALLOWLIST_DEFAULT)
DORIS_OAUTH_QUERY_TOOL_SET = frozenset({"exec_query"})
DORIS_OAUTH_EXPLAIN_TOOL_SET = frozenset({"get_sql_explain"})


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


def _coerce_csv_config(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
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
    port: int = 9030
    user: str = "root"
    password: str = ""
    database: str = "information_schema"
    charset: str = "UTF8"

    # FE HTTP API port for profile and other HTTP APIs
    fe_http_port: int = 8030
    
    # BE nodes configuration for external access
    # If be_hosts is empty, will use "show backends" to get BE nodes
    be_hosts: list[str] = field(default_factory=list)
    be_webserver_port: int = 8040

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
    doris_oauth_base_url: str = ""  # Public base URL for future Doris OAuth metadata
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
    token_secret: str = "default_secret"  # Legacy token secret for backward compatibility
    token_expiry: int = 3600
    
    # Enhanced Token Authentication Configuration
    token_file_path: str = "tokens.json"  # Path to token configuration file
    enable_token_expiry: bool = True  # Enable token expiration
    default_token_expiry_hours: int = 24 * 30  # Default expiry: 30 days
    token_hash_algorithm: str = "sha256"  # Token hashing algorithm: sha256, sha512
    
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
    oauth_userinfo_endpoint: str = ""
    oauth_jwks_uri: str = ""
    
    # OAuth Scopes and Settings
    oauth_scopes: list[str] = field(default_factory=list)
    oauth_state_expiry: int = 600  # State parameter expiry in seconds (10 minutes)
    oauth_pkce_enabled: bool = True  # Enable PKCE for better security
    oauth_nonce_enabled: bool = True  # Enable nonce for OIDC
    
    # User Mapping Configuration
    oauth_user_id_claim: str = "sub"  # JWT claim for user ID
    oauth_email_claim: str = "email"
    oauth_name_claim: str = "name"
    oauth_roles_claim: str = "roles"  # Custom claim for roles
    oauth_default_roles: list[str] = field(default_factory=lambda: ["oauth_user"])
    
    def __post_init__(self):
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
    default_max_rows: int = 100000
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
class DorisConfig:
    """Doris MCP Server complete configuration"""

    # Basic configuration
    server_name: str = "doris-mcp-server"
    server_version: str = "0.4.1"
    server_host: str = "localhost"
    server_port: int = 3000
    transport: str = "stdio"
    
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

    # Custom configuration
    custom_config: dict[str, Any] = field(default_factory=dict)

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
        if load_dotenv is not None:
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
        else:
            logging.getLogger(__name__).warning("python-dotenv not installed, cannot load .env files")

        config = cls()

        # Database configuration - handle empty strings properly
        doris_host = os.getenv("DORIS_HOST", "").strip()
        config.database.host = doris_host if doris_host else config.database.host
        
        doris_port = os.getenv("DORIS_PORT", "").strip()
        if doris_port and doris_port.isdigit():
            config.database.port = int(doris_port)
        
        doris_user = os.getenv("DORIS_USER", "").strip()
        config.database.user = doris_user if doris_user else config.database.user
        
        doris_password = os.getenv("DORIS_PASSWORD", "")
        config.database.password = doris_password if doris_password else config.database.password
        
        doris_database = os.getenv("DORIS_DATABASE", "").strip()
        config.database.database = doris_database if doris_database else config.database.database
        
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
        if "ENABLE_DORIS_OAUTH_AUTH" in os.environ:
            config.security.enable_doris_oauth_auth = _str_to_bool(os.getenv("ENABLE_DORIS_OAUTH_AUTH"))
            _mark_source(config, "enable_doris_oauth_auth", "env")
        if "DORIS_OAUTH_BASE_URL" in os.environ:
            config.security.doris_oauth_base_url = os.getenv("DORIS_OAUTH_BASE_URL", "").strip()
            _mark_source(config, "doris_oauth_base_url", "env")
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
        config.server_version = os.getenv("SERVER_VERSION", config.server_version)
        if "TRANSPORT" in os.environ:
            config.transport = os.getenv("TRANSPORT", config.transport)
            _mark_source(config, "transport", "env")
        if "WORKERS" in os.environ:
            config.workers = int(os.getenv("WORKERS", "1"))
            _mark_source(config, "workers", "env")
        server_port = os.getenv("SERVER_PORT", "").strip()
        if server_port and server_port.isdigit():
            config.server_port = int(server_port)
        config.temp_files_dir = os.getenv("TEMP_FILES_DIR", config.temp_files_dir)

        return config

    @classmethod
    def _from_dict(cls, config_data: dict[str, Any]) -> "DorisConfig":
        """Create configuration object from dictionary"""
        config = cls()

        # Update basic configuration
        for key in ["server_name", "server_version", "server_port", "temp_files_dir", "transport", "workers"]:
            if key in config_data:
                setattr(config, key, config_data[key])
                _mark_source(config, key, "config_file")

        # Update database configuration
        if "database" in config_data:
            db_config = config_data["database"]
            for key, value in db_config.items():
                if hasattr(config.database, key):
                    setattr(config.database, key, value)

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

        # Custom configuration
        config.custom_config = config_data.get("custom", {})

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "server_name": self.server_name,
            "server_version": self.server_version,
            "server_port": self.server_port,
            "temp_files_dir": self.temp_files_dir,
            "database": {
                "host": self.database.host,
                "port": self.database.port,
                "user": self.database.user,
                "password": "***",  # Hide password
                "database": self.database.database,
                "charset": self.database.charset,
                "fe_http_port": self.database.fe_http_port,
                "be_hosts": self.database.be_hosts,
                "be_webserver_port": self.database.be_webserver_port,
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
                "enable_doris_oauth_auth": self.security.enable_doris_oauth_auth,
                "doris_oauth_base_url": self.security.doris_oauth_base_url,
                "doris_oauth_db_tools_enabled": self.security.doris_oauth_db_tools_enabled,
                "doris_oauth_db_tool_allowlist": self.security.doris_oauth_db_tool_allowlist,
                "doris_oauth_query_tools_enabled": self.security.doris_oauth_query_tools_enabled,
                "doris_oauth_query_tool_allowlist": self.security.doris_oauth_query_tool_allowlist,
                "doris_oauth_explain_tools_enabled": self.security.doris_oauth_explain_tools_enabled,
                "doris_oauth_explain_tool_allowlist": self.security.doris_oauth_explain_tool_allowlist,
                "doris_oauth_access_token_expire_seconds": self.security.doris_oauth_access_token_expire_seconds,
                "doris_oauth_refresh_token_expire_seconds": self.security.doris_oauth_refresh_token_expire_seconds,
                "doris_oauth_auth_code_expire_seconds": self.security.doris_oauth_auth_code_expire_seconds,
                "doris_oauth_gc_interval_seconds": self.security.doris_oauth_gc_interval_seconds,
                "doris_oauth_idle_timeout_seconds": self.security.doris_oauth_idle_timeout_seconds,
                "doris_oauth_login_page_title": self.security.doris_oauth_login_page_title,
                "doris_oauth_allowed_redirect_uris": self.security.doris_oauth_allowed_redirect_uris,
                "doris_oauth_clients_file": self.security.doris_oauth_clients_file,
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

    def save_to_file(self, config_path: str):
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

        if not (1 <= self.database.port <= 65535):
            errors.append("Database port must be in the range 1-65535")

        if not self.database.user:
            errors.append("Database username cannot be empty")

        if self.database.max_connections <= 0:
            errors.append("Maximum connections must be greater than 0")

        # Validate security configuration
        if self.security.auth_type not in ["token", "basic", "oauth", "jwt"]:
            errors.append("Authentication type must be one of token, basic, oauth, or jwt")

        if self.security.token_expiry <= 0:
            errors.append("Token expiry time must be greater than 0")

        if self.security.max_query_complexity <= 0:
            errors.append("Maximum query complexity must be greater than 0")

        if self.security.max_result_rows <= 0:
            errors.append("Maximum result rows must be greater than 0")

        # Validate performance configuration
        if self.performance.cache_ttl <= 0:
            errors.append("Cache TTL must be greater than 0")

        if self.performance.max_concurrent_queries <= 0:
            errors.append("Maximum concurrent queries must be greater than 0")

        if self.performance.query_timeout <= 0:
            errors.append("Query timeout must be greater than 0")

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

        if self.adbc.default_timeout <= 0:
            errors.append("ADBC default timeout must be greater than 0")

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

    config.security.doris_oauth_db_tool_allowlist = _validate_doris_oauth_metadata_tool_allowlist(
        config.security.doris_oauth_db_tool_allowlist
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
    effective = getattr(config, "effective_auth", None)
    if effective is None:
        raise AuthConfigError("Effective auth config has not been normalized")
    return effective


class ConfigManager:
    """Configuration manager class"""

    def __init__(self, config: DorisConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)

    def setup_logging(self):
        """Setup logging configuration using enhanced logger"""
        from .logger import setup_logging, get_logger
        import sys
        
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

    def log_config_summary(self):
        """Log configuration summary"""
        summary = self.config.get_config_summary()
        self.logger.info("Configuration Summary:")
        self.logger.info(f"  Server: {summary['server']}")
        self.logger.info(f"  Database: {summary['database']}")
        self.logger.info(f"  Connection Pool: {summary['connection_pool']}")
        self.logger.info(f"  Security: {summary['security']}")
        self.logger.info(f"  Performance: {summary['performance']}")
        self.logger.info(f"  Monitoring: {summary['monitoring']}")


def create_default_config_file(config_path: str):
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

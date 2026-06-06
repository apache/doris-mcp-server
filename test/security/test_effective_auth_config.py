import pytest

from doris_mcp_server.auth.doris_oauth_scope_policy import DorisOAuthScopePolicy
from doris_mcp_server.utils.config import (
    AuthConfigError,
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)
from doris_mcp_server.utils.security import AuthenticationProvider


def test_default_auth_methods_remain_disabled():
    config = DorisConfig()

    effective = normalize_effective_auth_config(config)

    assert effective.auth_methods == ()
    assert effective.oauth_discovery_mode == "none"


def test_runtime_auth_provider_requires_normalized_effective_config():
    with pytest.raises(AuthConfigError, match="has not been normalized"):
        AuthenticationProvider(DorisConfig())


def test_explicit_oauth_false_conflicts_with_oauth_enabled_true():
    config = DorisConfig()
    config.security.oauth_enabled = True
    _mark_source(config, "oauth_enabled", "config_file")
    config.security.enable_oauth_auth = False
    _mark_source(config, "enable_oauth_auth", "env")

    with pytest.raises(AuthConfigError, match="explicitly conflict"):
        normalize_effective_auth_config(config)


def test_legacy_auth_type_only_applies_when_explicit():
    config = DorisConfig()
    config.security.auth_type = "token"
    _mark_source(config, "auth_type", "env")

    effective = normalize_effective_auth_config(config)

    assert effective.enable_token_auth is True
    assert effective.auth_methods == ("token",)


def test_doris_oauth_conflicts_with_external_oauth():
    config = DorisConfig()
    config.transport = "http"
    _mark_source(config, "transport", "env")
    config.security.enable_doris_oauth_auth = True
    _mark_source(config, "enable_doris_oauth_auth", "env")
    config.security.enable_oauth_auth = True
    _mark_source(config, "enable_oauth_auth", "env")

    with pytest.raises(AuthConfigError, match="cannot be enabled together"):
        normalize_effective_auth_config(config)


def test_doris_oauth_rejects_stdio_transport():
    config = DorisConfig()
    config.security.enable_doris_oauth_auth = True
    _mark_source(config, "enable_doris_oauth_auth", "env")

    with pytest.raises(AuthConfigError, match="requires HTTP transport"):
        normalize_effective_auth_config(config)


def _doris_oauth_http_config(base_url="http://localhost:3000"):
    config = DorisConfig()
    config.transport = "http"
    _mark_source(config, "transport", "env")
    config.security.enable_doris_oauth_auth = True
    _mark_source(config, "enable_doris_oauth_auth", "env")
    config.security.doris_oauth_base_url = base_url
    return config


def test_doris_oauth_requires_base_url():
    config = _doris_oauth_http_config("")

    with pytest.raises(AuthConfigError, match="DORIS_OAUTH_BASE_URL is required"):
        normalize_effective_auth_config(config)


def test_doris_oauth_rejects_non_loopback_http_base_url_by_default():
    config = _doris_oauth_http_config("http://mcp.example.test")

    with pytest.raises(AuthConfigError, match="must use HTTPS"):
        normalize_effective_auth_config(config)


def test_doris_oauth_accepts_loopback_http_base_url():
    config = _doris_oauth_http_config("http://localhost:3000")

    effective = normalize_effective_auth_config(config)

    assert effective.oauth_discovery_mode == "doris_oauth"
    assert effective.doris_oauth_base_url == "http://localhost:3000"


@pytest.mark.parametrize("tool_name", ["exec_query", "get_sql_explain", "get_sql_profile", "not_real"])
def test_doris_oauth_metadata_tool_allowlist_rejects_non_metadata_tools(tool_name):
    config = _doris_oauth_http_config("http://localhost:3000")
    config.security.doris_oauth_db_tool_allowlist = ["get_db_list", tool_name]

    with pytest.raises(AuthConfigError, match="DORIS_OAUTH_DB_TOOL_ALLOWLIST"):
        normalize_effective_auth_config(config)


@pytest.mark.parametrize(
    "field_name",
    [
        "doris_oauth_query_tools_enabled",
        "doris_oauth_explain_tools_enabled",
    ],
)
def test_doris_oauth_query_and_explain_flags_are_supported(field_name):
    config = _doris_oauth_http_config("http://localhost:3000")
    setattr(config.security, field_name, True)

    normalize_effective_auth_config(config)


def _doris_oauth_smoke_env_values():
    return {
        "TRANSPORT": "http",
        "SERVER_HOST": "127.0.0.1",
        "SERVER_PORT": "3000",
        "WORKERS": "1",
        "DORIS_HOST": "127.0.0.1",
        "DORIS_PORT": "9030",
        "DORIS_USER": "root",
        "DORIS_PASSWORD": "",
        "DORIS_DATABASE": "doris",
        "ENABLE_DORIS_OAUTH_AUTH": "true",
        "DORIS_OAUTH_BASE_URL": "http://127.0.0.1:3000",
        "ENABLE_TOKEN_AUTH": "false",
        "ENABLE_JWT_AUTH": "false",
        "ENABLE_OAUTH_AUTH": "false",
        "OAUTH_ENABLED": "false",
        "DORIS_OAUTH_DB_TOOLS_ENABLED": "true",
        "DORIS_OAUTH_DB_TOOL_ALLOWLIST": (
            "get_db_list,get_db_table_list,get_table_schema,get_table_comment,"
            "get_table_column_comments,get_table_indexes,get_catalog_list"
        ),
        "DORIS_OAUTH_QUERY_TOOLS_ENABLED": "true",
        "DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED": "true",
        "ENABLE_SECURITY_CHECK": "false",
        "DORIS_OAUTH_DYNAMIC_CLIENT_REGISTRATION_MODE": "auto",
    }


def test_runtime_doris_oauth_smoke_env_matches_rbac_default_scope_model(monkeypatch):
    env_values = _doris_oauth_smoke_env_values()
    for key in (
        "TRANSPORT",
        "SERVER_HOST",
        "SERVER_PORT",
        "WORKERS",
        "DORIS_HOST",
        "DORIS_PORT",
        "DORIS_USER",
        "DORIS_PASSWORD",
        "DORIS_DATABASE",
        "ENABLE_DORIS_OAUTH_AUTH",
        "DORIS_OAUTH_BASE_URL",
        "ENABLE_TOKEN_AUTH",
        "ENABLE_JWT_AUTH",
        "ENABLE_OAUTH_AUTH",
        "OAUTH_ENABLED",
        "DORIS_OAUTH_DB_TOOLS_ENABLED",
        "DORIS_OAUTH_DB_TOOL_ALLOWLIST",
        "DORIS_OAUTH_QUERY_TOOLS_ENABLED",
        "DORIS_OAUTH_EXPLAIN_TOOLS_ENABLED",
        "ENABLE_SECURITY_CHECK",
        "DORIS_OAUTH_DYNAMIC_CLIENT_REGISTRATION_MODE",
    ):
        monkeypatch.setenv(key, env_values.get(key, ""))
    monkeypatch.delenv("AUTH_TYPE", raising=False)

    config = DorisConfig.from_env()
    effective = normalize_effective_auth_config(config, requested_workers=int(env_values["WORKERS"]))
    policy = DorisOAuthScopePolicy(config.security)

    assert effective.auth_methods == ("doris_oauth",)
    assert effective.oauth_discovery_mode == "doris_oauth"
    assert effective.transport == "http"
    assert effective.effective_workers == 1
    assert config.security.enable_security_check is False
    assert config.security.enable_token_auth is False
    assert config.security.enable_jwt_auth is False
    assert config.security.enable_oauth_auth is False
    assert config.security.oauth_enabled is False

    assert {
        "tool:list",
        "resource:list",
        "resource:read",
        "tool:call:get_db_list",
        "tool:call:get_db_table_list",
        "tool:call:get_table_schema",
        "tool:call:get_table_comment",
        "tool:call:get_table_column_comments",
        "tool:call:get_table_indexes",
        "tool:call:get_catalog_list",
        "tool:call:exec_query",
        "tool:call:get_sql_explain",
    } <= policy.server_allowed_scopes
    assert {
        "*",
        "scope:admin",
        "scope:service_account",
        "scope:profile:read",
        "scope:monitoring:read",
        "scope:adbc:execute",
    }.isdisjoint(policy.server_allowed_scopes)


def test_doris_oauth_production_dcr_requires_explicit_flag():
    config = _doris_oauth_http_config("https://mcp.example.test")
    config.security.doris_oauth_dynamic_client_registration_mode = "enabled"

    with pytest.raises(AuthConfigError, match="Production Doris OAuth DCR requires"):
        normalize_effective_auth_config(config)


def test_doris_oauth_rejects_invalid_ttl():
    config = _doris_oauth_http_config("http://localhost:3000")
    config.security.doris_oauth_access_token_expire_seconds = 86401

    with pytest.raises(AuthConfigError, match="doris_oauth_access_token_expire_seconds"):
        normalize_effective_auth_config(config)


def test_doris_oauth_workers_zero_expands_before_fail_fast(monkeypatch):
    config = DorisConfig()
    config.transport = "http"
    _mark_source(config, "transport", "cli")
    config.security.enable_doris_oauth_auth = True
    _mark_source(config, "enable_doris_oauth_auth", "env")
    config.workers = 0
    _mark_source(config, "workers", "cli")

    import doris_mcp_server.utils.config as config_module

    monkeypatch.setattr(config_module.multiprocessing, "cpu_count", lambda: 4)

    with pytest.raises(AuthConfigError, match="single worker"):
        normalize_effective_auth_config(config, requested_workers=0)

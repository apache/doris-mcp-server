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

import pytest

from doris_mcp_server.utils.config import (
    AuthConfigError,
    DorisConfig,
    _mark_source,
    normalize_effective_auth_config,
)

ISSUER = "https://issuer.example.test"
RESOURCE = "https://mcp.example.test/mcp"


def _external_oauth_config() -> DorisConfig:
    config = DorisConfig()
    config.security.enable_oauth_auth = True
    _mark_source(config, "enable_oauth_auth", "test")
    config.security.oauth_client_id = "oauth-client"
    config.security.oauth_client_secret = "oauth-secret"
    config.security.oauth_issuer = ISSUER
    config.security.oauth_resource = RESOURCE
    config.security.oauth_audience = ""
    config.security.oauth_scopes = [
        "tool:list",
        "resource:read",
        "tool:list",
    ]
    config.security.oauth_required_scopes = ["resource:read"]
    config.security.oauth_introspection_endpoint = f"{ISSUER}/introspect"
    config.security.oauth_userinfo_endpoint = f"{ISSUER}/userinfo"
    return config


def test_external_oauth_context_configuration_is_normalized_fail_closed():
    config = _external_oauth_config()

    effective = normalize_effective_auth_config(config)

    assert effective.auth_methods == ("external_oauth",)
    assert effective.oauth_discovery_mode == "external_oauth"
    assert config.security.oauth_issuer == ISSUER
    assert config.security.oauth_resource == RESOURCE
    assert config.security.oauth_audience == RESOURCE
    assert config.security.oauth_scopes == ["tool:list", "resource:read"]
    assert config.security.oauth_required_scopes == ["resource:read"]
    assert config.security.oauth_introspection_client_id == "oauth-client"
    assert config.security.oauth_introspection_client_secret == "oauth-secret"
    serialized = config.to_dict()["security"]
    assert "oauth_introspection_client_secret" not in serialized
    assert "oauth_client_secret" not in serialized


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    [
        ("oauth_issuer", "", "OAUTH_ISSUER"),
        ("oauth_resource", "", "OAUTH_RESOURCE"),
        ("oauth_scopes", [], "OAUTH_SCOPE"),
        (
            "oauth_introspection_endpoint",
            "",
            "OAUTH_INTROSPECTION_URL or OAUTH_DISCOVERY_URL",
        ),
        (
            "oauth_userinfo_endpoint",
            "",
            "OAUTH_USERINFO_URL or OAUTH_DISCOVERY_URL",
        ),
        ("oauth_client_secret", "", "introspection client credentials"),
    ],
)
def test_external_oauth_missing_trust_inputs_are_rejected(
    field_name,
    value,
    message,
):
    config = _external_oauth_config()
    setattr(config.security, field_name, value)

    with pytest.raises(AuthConfigError, match=message):
        normalize_effective_auth_config(config)


def test_external_oauth_required_scopes_must_be_allowed():
    config = _external_oauth_config()
    config.security.oauth_required_scopes = ["unconfigured:admin"]

    with pytest.raises(AuthConfigError, match="must be a subset"):
        normalize_effective_auth_config(config)


def test_external_oauth_rejects_insecure_remote_introspection():
    config = _external_oauth_config()
    config.security.oauth_introspection_endpoint = (
        "http://issuer.example.test/introspect"
    )

    with pytest.raises(AuthConfigError, match="must use HTTPS"):
        normalize_effective_auth_config(config)


def test_external_oauth_environment_maps_token_context_settings(monkeypatch):
    values = {
        "ENABLE_OAUTH_AUTH": "true",
        "ENABLE_DORIS_OAUTH_AUTH": "false",
        "OAUTH_PROVIDER_TYPE": "custom",
        "OAUTH_CLIENT_ID": "oauth-client",
        "OAUTH_CLIENT_SECRET": "oauth-secret",
        "OAUTH_REDIRECT_URI": "http://localhost:3000/auth/callback",
        "OAUTH_ISSUER": ISSUER,
        "OAUTH_RESOURCE": RESOURCE,
        "OAUTH_AUDIENCE": "mcp-api",
        "OAUTH_AUTHORIZATION_URL": f"{ISSUER}/authorize",
        "OAUTH_TOKEN_URL": f"{ISSUER}/token",
        "OAUTH_INTROSPECTION_URL": f"{ISSUER}/introspect",
        "OAUTH_INTROSPECTION_CLIENT_ID": "introspection-client",
        "OAUTH_INTROSPECTION_CLIENT_SECRET": "introspection-secret",
        "OAUTH_USERINFO_URL": f"{ISSUER}/userinfo",
        "OAUTH_SCOPE": "tool:list, resource:list resource:read",
        "OAUTH_REQUIRED_SCOPE": "tool:list resource:read",
        "OAUTH_DEFAULT_ROLES": "member, auditor",
        "OAUTH_DEFAULT_SECURITY_LEVEL": "public",
        "OAUTH_TRUSTED_DOMAINS": "Example.COM, internal.example.test",
        "OAUTH_TRUSTED_DOMAIN_SECURITY_LEVEL": "confidential",
        "OAUTH_ROLE_SECURITY_LEVELS_JSON": (
            '{"member":"internal","executive":"secret"}'
        ),
        "OAUTH_ROLE_PERMISSIONS_JSON": (
            '{"member":["read_data"],"auditor":["read_data","audit"]}'
        ),
        "OAUTH_DEFAULT_PERMISSIONS": "",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    for name in ("AUTH_TYPE", "OAUTH_ENABLED"):
        monkeypatch.delenv(name, raising=False)

    config = DorisConfig.from_env()
    normalize_effective_auth_config(config)

    assert config.security.oauth_provider == "custom"
    assert config.security.oauth_issuer == ISSUER
    assert config.security.oauth_resource == RESOURCE
    assert config.security.oauth_audience == "mcp-api"
    assert config.security.oauth_scopes == [
        "tool:list",
        "resource:list",
        "resource:read",
    ]
    assert config.security.oauth_required_scopes == [
        "tool:list",
        "resource:read",
    ]
    assert config.security.oauth_introspection_client_id == ("introspection-client")
    assert config.security.oauth_introspection_client_secret == ("introspection-secret")
    assert config.security.oauth_default_roles == ["member", "auditor"]
    assert config.security.oauth_default_security_level == "public"
    assert config.security.oauth_trusted_domains == [
        "example.com",
        "internal.example.test",
    ]
    assert config.security.oauth_trusted_domain_security_level == "confidential"
    assert config.security.oauth_role_security_levels == {
        "member": "internal",
        "executive": "secret",
    }
    assert config.security.oauth_role_permissions == {
        "member": ["read_data"],
        "auditor": ["read_data", "audit"],
    }
    assert config.security.oauth_default_permissions == []


@pytest.mark.parametrize(
    ("name", "value", "message"),
    [
        (
            "OAUTH_ROLE_SECURITY_LEVELS_JSON",
            '["admin"]',
            "must map strings to strings",
        ),
        (
            "OAUTH_ROLE_PERMISSIONS_JSON",
            '{"admin":"read_data"}',
            "must map strings to arrays of strings",
        ),
    ],
)
def test_external_oauth_environment_rejects_invalid_authorization_json(
    monkeypatch,
    tmp_path,
    name,
    value,
    message,
):
    monkeypatch.setenv(name, value)

    with pytest.raises(AuthConfigError, match=message):
        DorisConfig.from_env(str(tmp_path / "missing.env"))


def test_external_oauth_rejects_invalid_authorization_security_level():
    config = _external_oauth_config()
    config.security.oauth_default_security_level = "top-secret"

    with pytest.raises(AuthConfigError, match="OAUTH_DEFAULT_SECURITY_LEVEL"):
        normalize_effective_auth_config(config)

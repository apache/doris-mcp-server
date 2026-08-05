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

import re
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMPOSE_PATH = REPOSITORY_ROOT / "docker-compose.yml"
DOCKERFILE_PATH = REPOSITORY_ROOT / "Dockerfile"
DOCKERIGNORE_PATH = REPOSITORY_ROOT / ".dockerignore"
START_SCRIPT_PATH = REPOSITORY_ROOT / "start_server.sh"
REQUIREMENTS_PATH = REPOSITORY_ROOT / "requirements.txt"
RUNTIME_SECURITY_PATH = REPOSITORY_ROOT / "doris_mcp_server" / "utils" / "security.py"
DEFAULT_VARIABLE = re.compile(r"^\$\{[^}:]+:-([^}]+)\}$")
PINNED_IMAGES = {
    "doris-fe": (
        "apache/doris:fe-3.0.8@"
        "sha256:749afa2be75cd58d54a0bdb3edaa805d5974646f67500f094912f8dbc4a96b8f"
    ),
    "doris-be": (
        "apache/doris:be-3.0.8@"
        "sha256:a337e2b17a65c86c22a1205467a825d46dc3380c94ba8024e53eea033641f12e"
    ),
    "redis": (
        "redis:7.4.10-alpine@"
        "sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2"
    ),
    "prometheus": (
        "prom/prometheus:v3.13.0@"
        "sha256:c6b27ea434f8389bfe233fbc7be381cf50587c286e871bc842008f5a1b1908a7"
    ),
    "grafana": (
        "grafana/grafana:13.1.0@"
        "sha256:121a7a9ece6dc10b969f1f96eed64b4f07dfac0d0b8abc070f7cb83bbde86f63"
    ),
    "nginx": (
        "nginx:1.30.4-alpine@"
        "sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46"
    ),
}


def _compose() -> dict:
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def _default_published_port(port: str | dict) -> int:
    published = str(
        port["published"] if isinstance(port, dict) else port.rsplit(":", 1)[0]
    )
    match = DEFAULT_VARIABLE.fullmatch(published)
    return int(match.group(1) if match else published)


def test_default_compose_host_ports_are_unique() -> None:
    compose = _compose()
    published: list[int] = []
    for service in compose["services"].values():
        published.extend(
            _default_published_port(port) for port in service.get("ports", [])
        )

    assert len(published) == len(set(published))


def test_compose_does_not_reserve_a_fixed_bridge_subnet() -> None:
    network = _compose()["networks"]["doris-network"]

    assert network == {"driver": "bridge"}


def test_mcp_service_uses_one_real_listener_and_readiness_probe() -> None:
    service = _compose()["services"]["doris-mcp-server"]

    assert service["ports"] == [
        {
            "target": 3000,
            "published": "${MCP_HTTP_PORT:-3000}",
            "host_ip": "127.0.0.1",
            "protocol": "tcp",
        }
    ]
    assert "SERVER_HOST=0.0.0.0" in service["environment"]
    assert "SERVER_PORT=3000" in service["environment"]
    assert (
        "MCP_ALLOWED_HOSTS=${MCP_ALLOWED_HOSTS:-127.0.0.1:*,localhost:*}"
        in service["environment"]
    )
    assert service["healthcheck"]["test"] == [
        "CMD",
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--max-time",
        "3",
        "http://127.0.0.1:3000/ready",
    ]
    assert service["depends_on"]["doris-fe"]["condition"] == "service_healthy"
    assert service["depends_on"]["doris-be"]["condition"] == "service_healthy"


def test_grafana_default_port_does_not_conflict_with_mcp() -> None:
    grafana = _compose()["services"]["grafana"]

    assert grafana["ports"] == [
        {
            "target": 3000,
            "published": "${GRAFANA_HTTP_PORT:-3003}",
            "host_ip": "127.0.0.1",
            "protocol": "tcp",
        }
    ]


def test_direct_service_ports_are_loopback_only() -> None:
    services = _compose()["services"]

    for service_name in (
        "doris-mcp-server",
        "doris-fe",
        "doris-be",
        "redis",
        "prometheus",
        "grafana",
    ):
        assert all(
            port["host_ip"] == "127.0.0.1" for port in services[service_name]["ports"]
        )


def test_compose_defaults_to_a_dedicated_doris_account() -> None:
    environment = _compose()["services"]["doris-mcp-server"]["environment"]

    assert "DORIS_USER=${DORIS_USER:-mcp_reader}" in environment
    assert "DORIS_USER=root" not in environment


def test_external_images_are_versioned_and_digest_pinned() -> None:
    services = _compose()["services"]

    assert {
        service: services[service]["image"] for service in PINNED_IMAGES
    } == PINNED_IMAGES
    assert all(":latest" not in image for image in PINNED_IMAGES.values())


def test_compose_credentials_are_file_backed_secrets() -> None:
    compose = _compose()
    services = compose["services"]
    secret_files = {
        name: value["file"] for name, value in compose["secrets"].items()
    }

    assert secret_files == {
        "doris_password": (
            "${COMPOSE_DORIS_PASSWORD_FILE:-./.secrets/doris_password}"
        ),
        "doris_fe_custom_config": (
            "${COMPOSE_DORIS_FE_CUSTOM_CONFIG_FILE:"
            "-./.secrets/doris_fe_custom.conf}"
        ),
        "mcp_static_token": (
            "${COMPOSE_MCP_STATIC_TOKEN_FILE:-./.secrets/mcp_static_token}"
        ),
        "redis_password": (
            "${COMPOSE_REDIS_PASSWORD_FILE:-./.secrets/redis_password}"
        ),
        "grafana_admin_password": (
            "${COMPOSE_GRAFANA_ADMIN_PASSWORD_FILE:"
            "-./.secrets/grafana_admin_password}"
        ),
    }
    assert services["doris-mcp-server"]["secrets"] == [
        "doris_password",
        "mcp_static_token",
    ]
    assert "DORIS_PASSWORD_FILE=/run/secrets/doris_password" in (
        services["doris-mcp-server"]["environment"]
    )
    assert "TOKEN_ADMIN_FILE=/run/secrets/mcp_static_token" in (
        services["doris-mcp-server"]["environment"]
    )
    assert services["redis"]["secrets"] == ["redis_password"]
    assert services["grafana"]["secrets"] == ["grafana_admin_password"]
    assert (
        "GF_SECURITY_ADMIN_PASSWORD__FILE=/run/secrets/grafana_admin_password"
        in services["grafana"]["environment"]
    )

    compose_text = COMPOSE_PATH.read_text(encoding="utf-8")
    for weak_value in ("doris123", "redis123", "admin123", "analyst123"):
        assert weak_value not in compose_text


def test_doris_nodes_mount_password_and_initial_root_config_secrets() -> None:
    services = _compose()["services"]

    assert services["doris-fe"]["secrets"] == [
        {
            "source": "doris_password",
            "target": "/etc/basic_auth/password",
        },
        {
            "source": "doris_fe_custom_config",
            "target": "/opt/apache-doris/fe/conf/fe_custom.conf",
        },
    ]
    assert services["doris-be"]["secrets"] == [
        {
            "source": "doris_password",
            "target": "/etc/basic_auth/password",
        }
    ]


def test_redis_password_is_not_exposed_in_command_or_healthcheck() -> None:
    redis = _compose()["services"]["redis"]

    assert redis["command"][-1] == (
        'exec redis-server --appendonly yes --requirepass '
        '"$$(cat /run/secrets/redis_password)"'
    )
    assert redis["healthcheck"]["test"] == [
        "CMD-SHELL",
        (
            'REDISCLI_AUTH="$$(cat /run/secrets/redis_password)" '
            "redis-cli --no-auth-warning ping | grep -qx PONG"
        ),
    ]


def test_image_healthcheck_uses_liveness_on_the_real_listener() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

    assert (
        "FROM python:3.12.11-slim-bookworm@"
        "sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7"
        in dockerfile
    )
    assert "http://127.0.0.1:3000/live" in dockerfile
    assert "EXPOSE 3000\n" in dockerfile
    assert "EXPOSE 3000 3001 3002" not in dockerfile
    assert "COPY . ." not in dockerfile
    assert "COPY doris_mcp_server ./doris_mcp_server" in dockerfile
    assert "COPY start_server.sh ." in dockerfile


def test_container_dependency_manifest_uses_mcp_sdk_v2() -> None:
    requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8").splitlines()

    assert "mcp>=2.0.0,<2.1.0" in requirements
    assert "mcp>=1.8.0,<2.0.0" not in requirements


def test_docker_build_context_is_an_explicit_runtime_allowlist() -> None:
    dockerignore = DOCKERIGNORE_PATH.read_text(encoding="utf-8").splitlines()

    assert "**" in dockerignore
    assert "!doris_mcp_server/**" in dockerignore
    assert "!requirements.txt" in dockerignore
    assert "!start_server.sh" in dockerignore
    assert "!LICENSE.txt" in dockerignore


def test_start_script_uses_canonical_server_host_and_documents_both_probes() -> None:
    script = START_SCRIPT_PATH.read_text(encoding="utf-8")

    assert 'SERVER_HOST="${SERVER_HOST:-${MCP_HOST:-127.0.0.1}}"' in script
    assert '--host "${SERVER_HOST}" --port "${SERVER_PORT}"' in script
    assert "load_secret_file DORIS_PASSWORD" in script
    assert "load_secret_file TOKEN_ADMIN" in script
    assert "Both ${variable_name} and ${file_variable_name} are set" in script
    assert 'unset "${file_variable_name}"' in script
    assert "/live" in script
    assert "/ready" in script


def test_runtime_has_no_fixed_legacy_credentials() -> None:
    security = RUNTIME_SECURITY_PATH.read_text(encoding="utf-8")

    for fixed_credential in (
        "valid_token_123",
        "admin_token_456",
        '"password": "admin123"',
        '"password": "analyst123"',
    ):
        assert fixed_credential not in security
    assert "_authenticate_legacy_token" not in security
    assert "Basic authentication is not supported" in security

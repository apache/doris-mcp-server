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
DEFAULT_VARIABLE = re.compile(r"^\$\{[^}:]+:-([^}]+)\}$")


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


def test_mcp_service_uses_one_real_listener_and_readiness_probe() -> None:
    service = _compose()["services"]["doris-mcp-server"]

    assert service["ports"] == ["${MCP_HTTP_PORT:-3000}:3000"]
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

    assert grafana["ports"] == ["${GRAFANA_HTTP_PORT:-3003}:3000"]


def test_image_healthcheck_uses_liveness_on_the_real_listener() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")

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
    assert "/live" in script
    assert "/ready" in script

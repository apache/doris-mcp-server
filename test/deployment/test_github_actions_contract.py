# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import re
import tomllib
from pathlib import Path

import yaml

from test.deployment.check_coverage_domains import DOMAINS

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
FULL_COMMIT_ACTION = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
CHECKOUT_ACTION = "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
CONFORMANCE_COMMIT = "49103de6ed70804e940637bf3e9e29e4a3f54e64"


def _workflow() -> dict:
    return yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


def _commands(job: dict) -> str:
    return "\n".join(step.get("run", "") for step in job["steps"])


def test_ci_runs_on_pull_requests_and_master_pushes_with_read_only_permissions():
    workflow = _workflow()

    assert set(workflow["on"]) == {"pull_request", "push", "workflow_dispatch"}
    assert workflow["on"]["push"]["branches"] == ["master"]
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"]["cancel-in-progress"] == "true"


def test_ci_jobs_are_bounded_and_external_actions_are_commit_pinned():
    jobs = _workflow()["jobs"]

    assert set(jobs) == {"quality", "test", "package", "conformance"}
    for job in jobs.values():
        assert job["runs-on"] == "ubuntu-latest"
        assert int(job["timeout-minutes"]) <= 30
        assert "continue-on-error" not in job
        for step in job["steps"]:
            assert "continue-on-error" not in step
            if action := step.get("uses"):
                assert FULL_COMMIT_ACTION.fullmatch(action), action
                assert action.startswith("actions/"), action
                if action.startswith("actions/checkout@"):
                    assert action == CHECKOUT_ACTION
        assert (
            "python -m pip install --disable-pip-version-check --no-deps uv==0.9.0"
            in " ".join(_commands(job).split())
        )


def test_quality_test_and_package_gates_cover_the_release_contract():
    jobs = _workflow()["jobs"]
    quality = _commands(jobs["quality"])
    tests = _commands(jobs["test"])
    package = _commands(jobs["package"])

    assert "uv lock --check" in quality
    assert "uv sync --frozen --group dev" in quality
    assert "uv run ruff check ." in quality
    assert "uv run mypy doris_mcp_server" in quality
    assert (
        "uv run bandit -q -c pyproject.toml -r "
        "doris_mcp_server doris_mcp_client generate_requirements.py"
    ) in " ".join(quality.split())

    assert "uv sync --frozen --group dev" in tests
    assert "uv run pytest -q -W error" in tests
    assert "uv run coverage json" in tests
    assert "test/deployment/check_coverage_domains.py" in tests

    assert "uv sync --frozen --group dev" in package
    assert "uv build" in package
    assert 'test "$wheel_count" = "1"' in package
    assert 'cd "$smoke_root"' in package
    assert 'doris-mcp-server" --version' in package
    assert 'doris-mcp-client" --help' in package
    assert "import doris_mcp_client, doris_mcp_server" in package
    assert "test/deployment/check_runtime_dependencies.py" in package


def test_conformance_gate_is_official_pinned_and_has_no_failure_baseline():
    job = _workflow()["jobs"]["conformance"]
    commands = _commands(job)
    checkout = next(
        step
        for step in job["steps"]
        if step.get("with", {}).get("repository") == "modelcontextprotocol/conformance"
    )

    assert checkout["with"]["ref"] == CONFORMANCE_COMMIT
    assert "uv sync --frozen --group dev" in commands
    assert "npm ci" in commands
    assert "npm run build" in commands
    assert "test/protocol/conformance_server.py" in commands
    assert "--transport http" in commands
    assert "--scenario server-stateless" in commands
    assert "--url http://127.0.0.1:39124/mcp" in commands
    assert "expected-failures" not in commands


def test_coverage_contract_has_full_repository_and_domain_floors() -> None:
    pyproject = tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))

    assert pyproject["tool"]["coverage"]["report"]["fail_under"] == 55
    assert set(DOMAINS) == {"protocol", "authentication", "core_managers"}
    assert {domain.minimum for domain in DOMAINS.values()} == {80.0}

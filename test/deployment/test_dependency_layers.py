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
"""Contracts for production and development dependency separation."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import generate_requirements
from test.deployment import check_runtime_dependencies

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PYPROJECT_PATH = REPOSITORY_ROOT / "pyproject.toml"
RUNTIME_REQUIREMENTS_PATH = REPOSITORY_ROOT / "requirements.txt"
DEV_REQUIREMENTS_PATH = REPOSITORY_ROOT / "requirements-dev.txt"
DEVELOPMENT_ONLY = {
    *check_runtime_dependencies.DEVELOPMENT_ONLY_DISTRIBUTIONS,
    "pandas-stubs",
    "pytest-mock",
    "pytest-xdist",
    "toml",
    "types-jsonschema",
}
REQUIRED_CI_TOOLS = {
    "bandit",
    "mypy",
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "ruff",
}


def _dependency_name(requirement: str) -> str:
    return re.split(r"[<>=!~;\[]", requirement, maxsplit=1)[0].strip().lower()


def _manifest_requirements(path: Path) -> list[str]:
    return [
        line
        for raw_line in path.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip())
        and not line.startswith("#")
        and not line.startswith("-r ")
    ]


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))


def test_runtime_metadata_excludes_development_and_build_tools() -> None:
    pyproject = _pyproject()
    runtime = {
        _dependency_name(requirement)
        for requirement in pyproject["project"]["dependencies"]
    }

    assert runtime.isdisjoint(DEVELOPMENT_ONLY)
    assert pyproject["build-system"]["requires"] == ["hatchling"]


def test_ci_development_group_owns_test_and_quality_dependencies() -> None:
    pyproject = _pyproject()
    development = {
        _dependency_name(requirement)
        for requirement in pyproject["dependency-groups"]["dev"]
    }

    assert REQUIRED_CI_TOOLS <= development
    assert development.isdisjoint(
        {
            _dependency_name(requirement)
            for requirement in pyproject["project"]["dependencies"]
        }
    )


def test_generated_manifests_match_their_independent_dependency_layers() -> None:
    pyproject = _pyproject()

    assert (
        _manifest_requirements(RUNTIME_REQUIREMENTS_PATH)
        == pyproject["project"]["dependencies"]
    )
    assert (
        _manifest_requirements(DEV_REQUIREMENTS_PATH)
        == pyproject["dependency-groups"]["dev"]
    )
    assert "-r requirements.txt" in DEV_REQUIREMENTS_PATH.read_text(encoding="utf-8")
    assert generate_requirements.verify_consistency(
        PYPROJECT_PATH,
        RUNTIME_REQUIREMENTS_PATH,
        DEV_REQUIREMENTS_PATH,
    )


def test_requirement_generator_is_reproducible(tmp_path: Path) -> None:
    runtime_path = tmp_path / "requirements.txt"
    dev_path = tmp_path / "requirements-dev.txt"

    generate_requirements.generate_requirements(PYPROJECT_PATH, runtime_path)
    generate_requirements.generate_requirements_dev(PYPROJECT_PATH, dev_path)

    assert runtime_path.read_bytes() == RUNTIME_REQUIREMENTS_PATH.read_bytes()
    assert dev_path.read_bytes() == DEV_REQUIREMENTS_PATH.read_bytes()


def test_consistency_rejects_cross_layer_package_with_different_specifiers(
    tmp_path: Path,
    capsys,
) -> None:
    project_path = tmp_path / "pyproject.toml"
    runtime_path = tmp_path / "requirements.txt"
    dev_path = tmp_path / "requirements-dev.txt"
    project_path.write_text(
        '[project]\ndependencies = ["shared>=1"]\n'
        '[dependency-groups]\ndev = ["shared>=2"]\n',
        encoding="utf-8",
    )
    runtime_path.write_text("shared>=1\n", encoding="utf-8")
    dev_path.write_text("-r requirements.txt\nshared>=2\n", encoding="utf-8")

    assert not generate_requirements.verify_consistency(
        project_path,
        runtime_path,
        dev_path,
    )
    assert "runtime/development overlap: ['shared']" in capsys.readouterr().out


def test_runtime_checker_reports_only_installed_development_packages(
    monkeypatch,
) -> None:
    def fake_version(distribution_name: str) -> str:
        if distribution_name == "pytest":
            return "9.0.0"
        raise check_runtime_dependencies.PackageNotFoundError

    monkeypatch.setattr(check_runtime_dependencies, "version", fake_version)

    assert check_runtime_dependencies.installed_development_packages() == {
        "pytest": "9.0.0"
    }

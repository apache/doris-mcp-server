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
Generate separated runtime and development requirement manifests.

``pyproject.toml`` remains the source of truth:

* ``project.dependencies`` feeds the production ``requirements.txt``.
* ``dependency-groups.dev`` feeds ``requirements-dev.txt``.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

PROJECT_PATH = Path("pyproject.toml")
RUNTIME_REQUIREMENTS_PATH = Path("requirements.txt")
DEV_REQUIREMENTS_PATH = Path("requirements-dev.txt")


def load_pyproject(project_path: Path = PROJECT_PATH) -> dict[str, Any]:
    """Load project metadata from a PEP 518 TOML document."""

    try:
        with project_path.open("rb") as project_file:
            return tomllib.load(project_file)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"{project_path} not found") from exc


def runtime_dependencies(pyproject: dict[str, Any]) -> list[str]:
    """Return dependencies installed for every package consumer."""

    return list(pyproject.get("project", {}).get("dependencies", []))


def development_dependencies(pyproject: dict[str, Any]) -> list[str]:
    """Return the lean development group used by CI and local contributors."""

    return list(pyproject.get("dependency-groups", {}).get("dev", []))


def generate_requirements(
    project_path: Path = PROJECT_PATH,
    output_path: Path = RUNTIME_REQUIREMENTS_PATH,
) -> int:
    """Generate the production-only requirements manifest."""

    dependencies = runtime_dependencies(load_pyproject(project_path))
    content = [
        "# Runtime dependencies - auto-generated from pyproject.toml",
        "# Do not edit manually; run `python generate_requirements.py`.",
        "",
        *dependencies,
        "",
    ]
    output_path.write_text("\n".join(content), encoding="utf-8")
    return len(dependencies)


def generate_requirements_dev(
    project_path: Path = PROJECT_PATH,
    output_path: Path = DEV_REQUIREMENTS_PATH,
) -> int:
    """Generate the development manifest on top of runtime requirements."""

    dependencies = development_dependencies(load_pyproject(project_path))
    content = [
        "# Development dependencies - auto-generated from pyproject.toml",
        "# Install with `pip install -r requirements-dev.txt`.",
        "",
        "-r requirements.txt",
        "",
        *dependencies,
        "",
    ]
    output_path.write_text("\n".join(content), encoding="utf-8")
    return len(dependencies)


def _manifest_dependencies(path: Path) -> set[str]:
    return {
        line
        for raw_line in path.read_text(encoding="utf-8").splitlines()
        if (line := raw_line.strip())
        and not line.startswith("#")
        and not line.startswith("-r ")
    }


def _dependency_names(dependencies: set[str]) -> set[str]:
    return {
        re.split(r"[<>=!~;\[]", dependency, maxsplit=1)[0].strip().lower()
        for dependency in dependencies
    }


def verify_consistency(
    project_path: Path = PROJECT_PATH,
    runtime_path: Path = RUNTIME_REQUIREMENTS_PATH,
    dev_path: Path = DEV_REQUIREMENTS_PATH,
) -> bool:
    """Verify both generated manifests against their independent source layers."""

    pyproject = load_pyproject(project_path)
    expected_runtime = set(runtime_dependencies(pyproject))
    expected_dev = set(development_dependencies(pyproject))
    actual_runtime = _manifest_dependencies(runtime_path)
    actual_dev = _manifest_dependencies(dev_path)

    problems = {
        "runtime only in manifest": actual_runtime - expected_runtime,
        "runtime only in pyproject": expected_runtime - actual_runtime,
        "development only in manifest": actual_dev - expected_dev,
        "development only in pyproject": expected_dev - actual_dev,
        "runtime/development overlap": _dependency_names(expected_runtime)
        & _dependency_names(expected_dev),
    }
    active_problems = {name: values for name, values in problems.items() if values}
    if not active_problems:
        print("✅ Dependency layer consistency verification passed!")
        return True

    print("❌ Found dependency layer inconsistencies:")
    for name, values in active_problems.items():
        print(f"   {name}: {sorted(values)}")
    return False


def main() -> int:
    print("🔄 Generating separated requirement manifests...")
    runtime_count = generate_requirements()
    dev_count = generate_requirements_dev()
    print(f"   Runtime dependencies: {runtime_count} items")
    print(f"   Development dependencies: {dev_count} items")
    print()
    print("🔍 Verifying dependency layer consistency...")
    if not verify_consistency():
        return 1
    print("✨ Completed!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

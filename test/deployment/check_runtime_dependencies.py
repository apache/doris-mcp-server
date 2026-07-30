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
"""Fail when a clean runtime environment contains development-only packages."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

DEVELOPMENT_ONLY_DISTRIBUTIONS = (
    "bandit",
    "black",
    "build",
    "flake8",
    "hatchling",
    "isort",
    "mypy",
    "pre-commit",
    "pytest",
    "pytest-asyncio",
    "pytest-cov",
    "ruff",
    "safety",
    "sphinx",
    "tox",
)


def installed_development_packages() -> dict[str, str]:
    """Return forbidden development distributions installed in this interpreter."""

    installed: dict[str, str] = {}
    for distribution_name in DEVELOPMENT_ONLY_DISTRIBUTIONS:
        try:
            installed[distribution_name] = version(distribution_name)
        except PackageNotFoundError:
            continue
    return installed


def main() -> int:
    installed = installed_development_packages()
    if installed:
        details = ", ".join(
            f"{distribution_name}=={distribution_version}"
            for distribution_name, distribution_version in sorted(installed.items())
        )
        print(f"Runtime environment contains development-only packages: {details}")
        return 1

    print("Runtime dependency boundary: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

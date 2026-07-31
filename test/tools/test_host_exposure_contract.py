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

"""Process-independent contracts for stable progressive tool exposure."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from doris_mcp_server.tools.domain_manifest import (
    MAX_TOP_LEVEL_TOOL_LIST_BYTES,
    DomainManifestService,
)
from doris_mcp_server.tools.doris_feature_matrix import (
    EXPECTED_DOMAIN_CHILDREN,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

_WORKER_CONTRACT_SCRIPT = """
import asyncio
import json

from doris_mcp_server.tools.domain_manifest import DomainManifestService


async def main():
    service = DomainManifestService()
    manifests = {}
    for name in sorted(service.domain_names):
        result = await service.call(name, {}, None)
        manifests[name] = result.manifest_version
    payload = {
        "manifest_versions": manifests,
        "tool_list_bytes": service.top_level_tool_list_bytes,
        "tools": [
            tool.model_dump(
                mode="json",
                by_alias=True,
                exclude_none=True,
            )
            for tool in service.list_tools()
        ],
    }
    print(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )


asyncio.run(main())
"""


def _tool_wire(service: DomainManifestService) -> list[dict[str, Any]]:
    return [
        tool.model_dump(
            mode="json",
            by_alias=True,
            exclude_none=True,
        )
        for tool in service.list_tools()
    ]


def _worker_contract(hash_seed: str) -> dict[str, Any]:
    environment = {**os.environ, "PYTHONHASHSEED": hash_seed}
    completed = subprocess.run(
        [sys.executable, "-c", _WORKER_CONTRACT_SCRIPT],
        cwd=REPO_ROOT,
        env=environment,
        capture_output=True,
        check=True,
        text=True,
        timeout=30,
    )
    return json.loads(completed.stdout)


@pytest.mark.asyncio
async def test_host_registration_stays_stable_across_domain_switches() -> None:
    service = DomainManifestService()
    before = _tool_wire(service)

    catalog = await service.call("doris_catalog", {}, None)
    cluster_first = await service.call("doris_cluster", {}, None)
    cluster_second = await service.call("doris_cluster", {}, None)
    after = _tool_wire(service)

    assert before == after
    assert [tool["name"] for tool in before] == list(
        EXPECTED_DOMAIN_CHILDREN
    )
    assert [child.name for child in catalog.children] == list(
        EXPECTED_DOMAIN_CHILDREN["doris_catalog"]
    )
    assert [child.name for child in cluster_first.children] == list(
        EXPECTED_DOMAIN_CHILDREN["doris_cluster"]
    )
    assert cluster_first.manifest_version == cluster_second.manifest_version
    assert service.top_level_tool_list_bytes <= MAX_TOP_LEVEL_TOOL_LIST_BYTES


def test_worker_processes_produce_identical_exposure_contracts() -> None:
    first = _worker_contract("1")
    second = _worker_contract("8675309")

    assert first == second
    assert first["tool_list_bytes"] <= MAX_TOP_LEVEL_TOOL_LIST_BYTES
    assert len(first["tools"]) == 8
    assert len(first["manifest_versions"]) == 8

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
"""Real-process MetricFlow sidecar cancellation, deadline, and exit races."""

from __future__ import annotations

import asyncio
import sys
from collections.abc import AsyncIterator
from contextlib import suppress
from pathlib import Path
from typing import Any

import pytest

from doris_mcp_server.semantic.metricflow import (
    MetricFlowProviderFailure,
    MetricFlowSidecarProvider,
)


@pytest.fixture
async def children(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[dict[str, Any]]:
    captured: dict[str, Any] = {
        "processes": [],
        "waited": set(),
        "waiters": {},
        "hold_after_exit": False,
        "communicated": asyncio.Event(),
    }
    original_create = asyncio.create_subprocess_exec

    async def create(*args: Any, **kwargs: Any) -> asyncio.subprocess.Process:
        process = await original_create(*args, **kwargs)
        captured["processes"].append(process)
        original_wait = process.wait
        captured["waiters"][process.pid] = original_wait

        async def wait() -> int:
            code = await original_wait()
            captured["waited"].add(process.pid)
            return code

        original_communicate = process.communicate

        async def communicate(input: bytes | None = None) -> tuple[bytes, bytes]:
            result = await original_communicate(input)
            captured["communicated"].set()
            if captured["hold_after_exit"]:
                # Hold delivery after the real process has exited and been reaped.
                await asyncio.Event().wait()
            return result

        monkeypatch.setattr(process, "wait", wait)
        monkeypatch.setattr(process, "communicate", communicate)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    try:
        yield captured
    finally:
        for process in captured["processes"]:
            if process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
            # Do not credit the test's fallback cleanup to provider.wait().
            await asyncio.wait_for(captured["waiters"][process.pid](), 5)


def provider(
    tmp_path: Path, *, reply: bool = False
) -> tuple[MetricFlowSidecarProvider, Path]:
    script = tmp_path / "sidecar.py"
    ready = tmp_path / "ready"
    script.write_text(
        "import json, sys, time\n"
        "from pathlib import Path\n"
        "request = json.loads(sys.stdin.read())\n"
        "Path(sys.argv[1]).write_text('ready', encoding='utf-8')\n"
        + (
            "sys.stdout.write(json.dumps({\n"
            "    'protocol_version': request['protocol_version'],\n"
            "    'request_id': request['request_id'],\n"
            "    'ok': True, 'data': {'items': []},\n"
            "}))\n"
            if reply
            else "time.sleep(60)\n"
        ),
        encoding="utf-8",
    )
    return (
        MetricFlowSidecarProvider(
            [sys.executable, str(script), str(ready)], timeout_seconds=2
        ),
        ready,
    )


async def await_ready(ready: Path) -> None:
    async def signalled() -> None:
        while not ready.exists():
            await asyncio.sleep(0.01)

    await asyncio.wait_for(signalled(), 5)


async def finish_task(task: asyncio.Task[Any]) -> None:
    if not task.done():
        task.cancel()
    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 5)


async def test_cancelled_request_kills_and_reaps_ready_sidecar(tmp_path, children):
    sidecar, ready = provider(tmp_path)
    task = asyncio.create_task(sidecar.request("list_models", {}))
    try:
        await await_ready(ready)
        process = children["processes"][0]
        assert process.returncode is None
        task.cancel("caller cancelled")
        with pytest.raises(asyncio.CancelledError) as error:
            await asyncio.wait_for(task, 5)
        assert error.value.args == ("caller cancelled",)
        assert task.cancelled()
        assert process.returncode is not None
        assert process.pid in children["waited"]
    finally:
        await finish_task(task)


async def test_provider_deadline_kills_and_reaps_ready_sidecar(tmp_path, children):
    sidecar, ready = provider(tmp_path)
    task = asyncio.create_task(sidecar.request("list_models", {}))
    try:
        await await_ready(ready)
        with pytest.raises(MetricFlowProviderFailure) as error:
            await asyncio.wait_for(task, 5)
        assert error.value.reason_code == "METRICFLOW_PROVIDER_TIMEOUT"
        process = children["processes"][0]
        assert process.returncode is not None
        assert process.pid in children["waited"]
    finally:
        await finish_task(task)


async def test_successful_request_reaps_sidecar(tmp_path, children):
    sidecar, _ = provider(tmp_path, reply=True)
    assert await asyncio.wait_for(sidecar.request("list_models", {}), 5) == {
        "items": []
    }
    process = children["processes"][0]
    assert process.returncode == 0
    assert process.pid in children["waited"]


@pytest.mark.parametrize("interruption", ["cancel", "timeout"])
async def test_interruption_after_real_process_exit_preserves_error(
    tmp_path, children, interruption
):
    sidecar, _ = provider(tmp_path, reply=True)
    children["hold_after_exit"] = True
    task = asyncio.create_task(sidecar.request("list_models", {}))
    try:
        await asyncio.wait_for(children["communicated"].wait(), 5)
        process = children["processes"][0]
        assert process.returncode == 0
        if interruption == "cancel":
            task.cancel("caller cancelled after exit")
            with pytest.raises(asyncio.CancelledError) as error:
                await asyncio.wait_for(task, 5)
            assert error.value.args == ("caller cancelled after exit",)
        else:
            with pytest.raises(MetricFlowProviderFailure) as error:
                await asyncio.wait_for(task, 5)
            assert error.value.reason_code == "METRICFLOW_PROVIDER_TIMEOUT"
        assert process.returncode == 0
        assert process.pid in children["waited"]
    finally:
        await finish_task(task)

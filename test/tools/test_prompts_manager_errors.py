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

import asyncio
from contextlib import asynccontextmanager

import pytest

from doris_mcp_server.tools.prompts_manager import DorisPromptsManager


class FailingConnection:
    async def execute(self, sql, params=None, auth_context=None):
        raise RuntimeError("database context backend failed")


class FailingConnectionManager:
    def __init__(self):
        self.acquires = 0
        self.releases = 0
        self.connection = FailingConnection()

    async def get_connection(self, session_id):
        self.acquires += 1
        return self.connection

    async def release_connection(self, session_id, connection):
        assert connection is self.connection
        self.releases += 1


class ContextFailingConnectionManager:
    def __init__(self):
        self.acquires = 0
        self.releases = 0
        self.connection = FailingConnection()

    @asynccontextmanager
    async def get_connection_context(self, session_id):
        self.acquires += 1
        try:
            yield self.connection
        finally:
            self.releases += 1


class HangingConnectionManager:
    async def get_connection(self, session_id):
        await asyncio.Event().wait()


@pytest.mark.asyncio
async def test_unknown_prompt_has_stable_request_error_code():
    manager = DorisPromptsManager(FailingConnectionManager())

    with pytest.raises(ValueError) as error:
        await manager.get_prompt("missing", {})

    assert error.value.error_code == "UNKNOWN_PROMPT"


@pytest.mark.asyncio
async def test_missing_required_argument_names_the_argument():
    manager = DorisPromptsManager(FailingConnectionManager())

    with pytest.raises(ValueError) as error:
        await manager.get_prompt("sales_analysis", {})

    assert error.value.error_code == "MISSING_REQUIRED_ARGUMENT"
    assert error.value.argument == "date_range"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "connection_manager",
    [
        FailingConnectionManager,
        ContextFailingConnectionManager,
    ],
)
async def test_database_context_failure_is_typed_and_releases_connection(
    connection_manager,
):
    connections = connection_manager()
    manager = DorisPromptsManager(connections)

    with pytest.raises(RuntimeError) as error:
        await manager.get_prompt(
            "sales_analysis",
            {"date_range": "last 30 days"},
        )

    assert error.value.error_code == "DATABASE_CONTEXT_UNAVAILABLE"
    assert isinstance(error.value.__cause__, RuntimeError)
    assert connections.acquires == 1
    assert connections.releases == 1


@pytest.mark.asyncio
async def test_database_context_timeout_becomes_typed_failure():
    manager = DorisPromptsManager(
        HangingConnectionManager(),
        database_context_timeout_seconds=0.01,
    )

    with pytest.raises(RuntimeError) as error:
        await manager.get_prompt(
            "sales_analysis",
            {"date_range": "last 30 days"},
        )

    assert error.value.error_code == "DATABASE_CONTEXT_UNAVAILABLE"
    assert isinstance(error.value.__cause__, TimeoutError)

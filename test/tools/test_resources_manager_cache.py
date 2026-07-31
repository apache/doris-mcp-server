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

import json
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.semantic.runtime import SemanticRuntimeFailure
from doris_mcp_server.tools.resources_manager import (
    DorisOAuthResourceError,
    DorisResourcesManager,
    MetadataCache,
    ResourceMetadataError,
)
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)


class FakeConnection:
    def __init__(self):
        self.table_metadata_queries = 0
        self.column_metadata_queries = 0

    async def execute(self, sql, params=None, auth_context=None):
        if "FROM information_schema.tables" in sql and "AND table_type = 'BASE TABLE'" in sql:
            self.table_metadata_queries += 1
            return SimpleNamespace(
                data=[
                    {
                        "table_name": f"orders_{self.table_metadata_queries}",
                        "table_comment": "orders",
                        "row_count": 1,
                        "create_time": None,
                    }
                ]
            )
        if "FROM information_schema.columns" in sql:
            self.column_metadata_queries += 1
            return SimpleNamespace(data=[])
        return SimpleNamespace(data=[])


class FakeConnectionManager:
    def __init__(self):
        self.connection = FakeConnection()
        self.acquires = 0
        self.releases = 0

    @asynccontextmanager
    async def get_connection_context(self, session_id):
        self.acquires += 1
        try:
            yield self.connection
        finally:
            self.releases += 1


class RaisingConnection:
    async def execute(self, sql, params=None, auth_context=None):
        raise RuntimeError("metadata backend failed")


class RaisingConnectionManager:
    def __init__(self):
        self.connection = RaisingConnection()
        self.acquires = 0
        self.releases = 0

    @asynccontextmanager
    async def get_connection_context(self, session_id):
        self.acquires += 1
        try:
            yield self.connection
        finally:
            self.releases += 1


class ClassifiedErrorConnection:
    def __init__(self, error):
        self.error = error

    async def execute(self, sql, params=None, auth_context=None):
        raise self.error


class ClassifiedErrorConnectionManager:
    def __init__(self, error):
        self.connection = ClassifiedErrorConnection(error)
        self.acquires = 0
        self.releases = 0

    @asynccontextmanager
    async def get_connection_context(self, session_id):
        self.acquires += 1
        try:
            yield self.connection
        finally:
            self.releases += 1


class DorisOAuthResourceConnection:
    def __init__(self):
        self.calls = []

    async def execute(self, sql, params=None, auth_context=None):
        self.calls.append((sql, params, auth_context))
        if sql.strip().upper().startswith("SHOW DATABASES"):
            return SimpleNamespace(
                data=[
                    {"Database": "information_schema"},
                    {"Database": "db1"},
                    {"Database": "db2"},
                    {"Database": "db/slash"},
                    {"Database": "database"},
                ]
            )
        if "FROM information_schema.tables" in sql and "AND table_type = 'BASE TABLE'" in sql:
            db_name = params[0]
            return SimpleNamespace(
                data=[
                    {
                        "table_name": f"{db_name}_orders",
                        "table_comment": "orders",
                        "row_count": 1,
                        "create_time": None,
                    }
                ]
            )
        if "FROM information_schema.views" in sql and "view_definition" in sql and "AND table_name" not in sql:
            db_name = params[0]
            return SimpleNamespace(
                data=[
                    {
                        "table_name": f"{db_name}_view",
                        "table_comment": "view",
                        "view_definition": "select 1",
                    }
                ]
            )
        if "FROM information_schema.columns" in sql:
            return SimpleNamespace(data=[])
        if "FROM information_schema.statistics" in sql:
            return SimpleNamespace(data=[])
        return SimpleNamespace(data=[])


class DorisOAuthResourceConnectionManager:
    def __init__(self):
        self.connection = DorisOAuthResourceConnection()
        self.acquires = 0
        self.releases = 0

    @asynccontextmanager
    async def get_connection_context(self, session_id):
        self.acquires += 1
        try:
            yield self.connection
        finally:
            self.releases += 1


class DorisOAuthReadConnection:
    def __init__(self):
        self.calls = []

    async def execute(self, sql, params=None, auth_context=None):
        self.calls.append((sql, params, auth_context))
        if "FROM information_schema.views" in sql and "AND table_name" in sql:
            assert params == ("db1", "orders_view")
            return SimpleNamespace(
                data=[
                    {
                        "table_name": "orders_view",
                        "view_definition": "SELECT * FROM orders",
                    }
                ]
            )
        if "FROM information_schema.tables" in sql and "AND table_name" in sql:
            assert params in {("db1", "orders"), ("db/slash", "orders/slash")}
            _db_name, table_name = params
            return SimpleNamespace(
                data=[
                    {
                        "table_name": table_name,
                        "table_comment": "orders",
                        "table_rows": 10,
                        "create_time": None,
                        "engine": "Doris",
                    }
                ]
            )
        if "FROM information_schema.columns" in sql:
            assert params in {("db1", "orders"), ("db/slash", "orders/slash")}
            return SimpleNamespace(data=[{"column_name": "id"}])
        if "FROM information_schema.statistics" in sql:
            assert params in {("db1", "orders"), ("db/slash", "orders/slash")}
            return SimpleNamespace(data=[])
        return SimpleNamespace(data=[])


class DorisOAuthReadConnectionManager:
    def __init__(self):
        self.connection = DorisOAuthReadConnection()
        self.acquires = 0
        self.releases = 0

    @asynccontextmanager
    async def get_connection_context(self, session_id):
        self.acquires += 1
        try:
            yield self.connection
        finally:
            self.releases += 1


def doris_context(scopes):
    return AuthContext(
        user_id="doris_user",
        auth_method="doris_oauth",
        oauth_scopes=list(scopes),
        pool_key="doris_user:doris_user",
    )


@pytest.mark.asyncio
async def test_semantic_resources_are_listed_and_read_through_exact_runtime() -> None:
    manager = DorisResourcesManager(FakeConnectionManager())  # type: ignore[arg-type]
    semantic_uri = "doris://semantic/models/retail%2Fmain/0123456789abcdef"
    manager.semantic_runtime.list_resource_descriptors = AsyncMock(
        return_value=[
            {
                "uri": semantic_uri,
                "name": "Semantic Model: retail",
                "description": "Validated Ossie summary for retail",
            }
        ]
    )
    manager.semantic_runtime.read_resource = AsyncMock(
        return_value='{"model_ref":"retail/main"}'
    )

    resources = await manager.list_resources()
    semantic = [resource for resource in resources if str(resource.uri) == semantic_uri]

    assert len(semantic) == 1
    assert semantic[0].mime_type == "application/json"
    assert await manager.read_resource(semantic_uri) == (
        '{"model_ref":"retail/main"}'
    )
    manager.semantic_runtime.read_resource.assert_awaited_once_with(semantic_uri)


@pytest.mark.asyncio
async def test_hidden_semantic_resource_uses_generic_not_found_payload() -> None:
    manager = DorisResourcesManager(FakeConnectionManager())  # type: ignore[arg-type]
    uri = "doris://semantic/models/hidden%2Fmodel/0123456789abcdef"
    manager.semantic_runtime.read_resource = AsyncMock(
        side_effect=SemanticRuntimeFailure(
            "SEMANTIC_MODEL_NOT_FOUND",
            "Semantic model was not found.",
            status_code=404,
        )
    )

    payload = json.loads(await manager.read_resource(uri))

    assert payload == {
        "error": "Resource not found",
        "uri": uri,
        "error_code": "RESOURCE_NOT_FOUND",
    }


@pytest.mark.asyncio
async def test_metadata_cache_disabled_by_default():
    cache = MetadataCache(enabled=False)
    await cache.set("table_metadata", ["cached"])

    assert await cache.get("table_metadata") is None


@pytest.mark.asyncio
async def test_resources_manager_reuses_identity_scoped_metadata_cache():
    connection_manager = FakeConnectionManager()
    manager = DorisResourcesManager(connection_manager)

    first = await manager._get_table_metadata()
    second = await manager._get_table_metadata()

    assert manager.metadata_cache.enabled is True
    assert [table.name for table in first] == ["orders_1"]
    assert [table.name for table in second] == ["orders_1"]
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1
    assert connection_manager.connection.column_metadata_queries == 0


@pytest.mark.asyncio
async def test_resources_manager_does_not_share_metadata_across_identities():
    connection_manager = FakeConnectionManager()
    manager = DorisResourcesManager(connection_manager)

    first_token = set_current_auth_context(
        AuthContext(
            token_id="token-a",
            user_id="user-a",
            roles=["reader"],
            permissions=["resource:list"],
            auth_method="token",
        )
    )
    try:
        first = await manager._get_table_metadata()
    finally:
        reset_auth_context(first_token)

    second_token = set_current_auth_context(
        AuthContext(
            token_id="token-b",
            user_id="user-b",
            roles=["reader"],
            permissions=["resource:list"],
            auth_method="token",
        )
    )
    try:
        second = await manager._get_table_metadata()
    finally:
        reset_auth_context(second_token)

    assert [table.name for table in first] == ["orders_1"]
    assert [table.name for table in second] == ["orders_2"]
    assert connection_manager.acquires == 2
    assert connection_manager.releases == 2


@pytest.mark.asyncio
async def test_doris_oauth_list_resources_backend_error_is_structured_failure():
    connection_manager = RaisingConnectionManager()
    manager = DorisResourcesManager(connection_manager)
    token = set_current_auth_context(doris_context(["resource:list"]))

    try:
        with pytest.raises(DorisOAuthResourceError) as exc:
            await manager.list_resources()
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_METADATA_BACKEND_ERROR"
    assert exc.value.status_code == 502
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1


@pytest.mark.asyncio
async def test_list_resources_backend_error_is_not_a_successful_partial_list():
    connection_manager = ClassifiedErrorConnectionManager(
        OSError("metadata backend unavailable")
    )
    manager = DorisResourcesManager(connection_manager)

    with pytest.raises(ResourceMetadataError) as exc:
        await manager.list_resources()

    assert exc.value.error_code == "DORIS_METADATA_BACKEND_ERROR"
    assert exc.value.status_code == 502
    assert exc.value.list_error_category == "backend_unavailable"
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1


@pytest.mark.asyncio
async def test_list_resources_permission_error_is_not_a_successful_empty_list():
    connection_manager = ClassifiedErrorConnectionManager(
        RuntimeError(1142, "SELECT command denied")
    )
    manager = DorisResourcesManager(connection_manager)

    with pytest.raises(ResourceMetadataError) as exc:
        await manager.list_resources()

    assert exc.value.error_code == "DORIS_METADATA_PERMISSION_DENIED"
    assert exc.value.status_code == 403
    assert exc.value.list_error_category == "permission_denied"
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1


@pytest.mark.asyncio
async def test_list_resources_internal_error_is_not_a_successful_empty_list():
    connection_manager = RaisingConnectionManager()
    manager = DorisResourcesManager(connection_manager)

    with pytest.raises(ResourceMetadataError) as exc:
        await manager.list_resources()

    assert exc.value.error_code == "DORIS_METADATA_INTERNAL_ERROR"
    assert exc.value.status_code == 500
    assert exc.value.list_error_category == "internal_error"
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1


@pytest.mark.asyncio
async def test_doris_oauth_list_resources_uses_database_qualified_uris_without_database_function():
    connection_manager = DorisOAuthResourceConnectionManager()
    manager = DorisResourcesManager(connection_manager)
    token = set_current_auth_context(doris_context(["resource:list"]))

    try:
        resources = await manager.list_resources()
    finally:
        reset_auth_context(token)

    uris = {str(resource.uri) for resource in resources}
    assert "doris://table/db1/db1_orders" in uris
    assert "doris://view/db1/db1_view" in uris
    assert "doris://stats/db1" in uris
    assert "doris://table/db%2Fslash/db%2Fslash_orders" in uris
    assert "doris://view/db%2Fslash/db%2Fslash_view" in uris
    assert "doris://stats/database/database" in uris
    assert "doris://table/information_schema/information_schema_orders" not in uris
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1
    assert all(
        "DATABASE()" not in sql
        for sql, _params, _auth in connection_manager.connection.calls
    )
    assert all(
        "table_comment" not in sql
        for sql, _params, _auth in connection_manager.connection.calls
        if "FROM information_schema.views" in sql
    )


@pytest.mark.asyncio
async def test_doris_oauth_read_resource_backend_error_is_structured_failure():
    connection_manager = RaisingConnectionManager()
    manager = DorisResourcesManager(connection_manager)
    token = set_current_auth_context(doris_context(["resource:read"]))

    try:
        with pytest.raises(DorisOAuthResourceError) as exc:
            await manager.read_resource("doris://table/orders")
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_METADATA_BACKEND_ERROR"
    assert exc.value.status_code == 502
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1


@pytest.mark.asyncio
async def test_doris_oauth_read_database_qualified_table_resource_uses_uri_database():
    connection_manager = DorisOAuthReadConnectionManager()
    manager = DorisResourcesManager(connection_manager)
    token = set_current_auth_context(doris_context(["resource:read"]))

    try:
        result = await manager.read_resource("doris://table/db1/orders")
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["database_name"] == "db1"
    assert payload["table_name"] == "orders"
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1
    assert all(
        "DATABASE()" not in sql
        for sql, _params, _auth in connection_manager.connection.calls
    )


@pytest.mark.asyncio
async def test_doris_oauth_read_view_uses_doris_information_schema_columns():
    connection_manager = DorisOAuthReadConnectionManager()
    manager = DorisResourcesManager(connection_manager)
    token = set_current_auth_context(doris_context(["resource:read"]))

    try:
        result = await manager.read_resource("doris://view/db1/orders_view")
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload == {
        "database_name": "db1",
        "view_name": "orders_view",
        "comment": None,
        "definition": "SELECT * FROM orders",
    }
    view_queries = [
        sql
        for sql, _params, _auth in connection_manager.connection.calls
        if "FROM information_schema.views" in sql
    ]
    assert len(view_queries) == 1
    assert "table_comment" not in view_queries[0]


@pytest.mark.asyncio
async def test_doris_oauth_read_percent_encoded_table_resource_uses_decoded_identifiers():
    connection_manager = DorisOAuthReadConnectionManager()
    manager = DorisResourcesManager(connection_manager)
    token = set_current_auth_context(doris_context(["resource:read"]))

    try:
        result = await manager.read_resource("doris://table/db%2Fslash/orders%2Fslash")
    finally:
        reset_auth_context(token)

    payload = json.loads(result)
    assert payload["database_name"] == "db/slash"
    assert payload["table_name"] == "orders/slash"
    assert connection_manager.acquires == 1
    assert connection_manager.releases == 1
    assert all("DATABASE()" not in sql for sql, _params, _auth in connection_manager.connection.calls)


def test_parse_stats_resource_distinguishes_legacy_current_database_from_literal_database_name():
    manager = DorisResourcesManager(DorisOAuthResourceConnectionManager())

    assert manager._parse_resource_uri("doris://stats/database") == ("stats", "database", None)
    assert manager._parse_resource_uri("doris://stats/database/database") == (
        "stats",
        "database",
        "database",
    )


@pytest.mark.asyncio
async def test_legacy_read_resource_hides_backend_error_details():
    manager = DorisResourcesManager(RaisingConnectionManager())

    result = await manager.read_resource("doris://table/orders")

    payload = json.loads(result)
    assert payload["uri"] == "doris://table/orders"
    assert payload["error"] == "Resource read failed"
    assert "metadata backend failed" not in payload["error"]
    assert "error_code" not in payload


@pytest.mark.asyncio
async def test_read_resource_marks_invalid_uri_for_protocol_boundary():
    manager = DorisResourcesManager(FakeConnectionManager())

    result = await manager.read_resource("https://example.com/orders")

    payload = json.loads(result)
    assert payload == {
        "error": "Invalid resource URI",
        "error_code": "INVALID_RESOURCE_URI",
        "uri": "https://example.com/orders",
    }


@pytest.mark.asyncio
async def test_read_resource_marks_missing_table_for_protocol_boundary():
    class EmptyConnection:
        async def execute(self, sql, params=None, auth_context=None):
            return SimpleNamespace(data=[])

    class EmptyConnectionManager:
        @asynccontextmanager
        async def get_connection_context(self, session_id):
            yield EmptyConnection()

    manager = DorisResourcesManager(EmptyConnectionManager())

    result = await manager.read_resource("doris://table/missing")

    payload = json.loads(result)
    assert payload == {
        "error": "Resource not found",
        "error_code": "RESOURCE_NOT_FOUND",
        "uri": "doris://table/missing",
    }

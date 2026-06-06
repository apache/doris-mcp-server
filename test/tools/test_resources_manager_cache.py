from contextlib import asynccontextmanager
import json
from types import SimpleNamespace

import pytest

from doris_mcp_server.tools.resources_manager import (
    DorisOAuthResourceError,
    DorisResourcesManager,
    MetadataCache,
)
from doris_mcp_server.utils.security import AuthContext, reset_auth_context, set_current_auth_context


class FakeConnection:
    def __init__(self):
        self.table_metadata_queries = 0

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
async def test_metadata_cache_disabled_by_default():
    cache = MetadataCache(enabled=False)
    await cache.set("table_metadata", ["cached"])

    assert await cache.get("table_metadata") is None


@pytest.mark.asyncio
async def test_resources_manager_does_not_reuse_global_metadata_cache():
    connection_manager = FakeConnectionManager()
    manager = DorisResourcesManager(connection_manager)

    first = await manager._get_table_metadata()
    second = await manager._get_table_metadata()

    assert manager.metadata_cache.enabled is False
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
    assert all("DATABASE()" not in sql for sql, _params, _auth in connection_manager.connection.calls)


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
    assert all("DATABASE()" not in sql for sql, _params, _auth in connection_manager.connection.calls)


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
async def test_legacy_read_resource_keeps_json_error_body_compatibility():
    manager = DorisResourcesManager(RaisingConnectionManager())

    result = await manager.read_resource("doris://table/orders")

    payload = json.loads(result)
    assert payload["uri"] == "doris://table/orders"
    assert "metadata backend failed" in payload["error"]

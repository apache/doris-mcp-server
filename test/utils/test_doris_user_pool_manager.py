from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from doris_mcp_server.utils import db as db_module
from doris_mcp_server.utils.db import (
    DorisConnection,
    DorisConnectionManager,
    DorisUserAuthenticationError,
    DorisUserPoolMissingError,
    QueryResult,
)
from doris_mcp_server.utils.security import (
    AuthContext,
    reset_auth_context,
    set_current_auth_context,
)


class FakeAuthConnection:
    def __init__(self):
        self.closed = False
        self.close_calls = 0

    def close(self):
        self.close_calls += 1
        self.closed = True


class FakeRawConnection:
    def __init__(self, label):
        self.label = label
        self.closed = False
        self.ensure_closed_calls = 0

    async def ensure_closed(self):
        self.ensure_closed_calls += 1
        self.closed = True


class FakePool:
    def __init__(self, name):
        self.name = name
        self.closed = False
        self.size = 0
        self.freesize = 0
        self.minsize = 0
        self.maxsize = 5
        self.acquire_calls = 0
        self.release_calls = []
        self.close_calls = 0
        self.wait_closed_calls = 0

    async def acquire(self):
        self.acquire_calls += 1
        return FakeRawConnection(f"{self.name}:{self.acquire_calls}")

    def release(self, connection):
        self.release_calls.append(connection)

    def close(self):
        self.close_calls += 1
        self.closed = True

    async def wait_closed(self):
        self.wait_closed_calls += 1


def manager_config():
    return SimpleNamespace(
        database=SimpleNamespace(
            host="127.0.0.1",
            port=9030,
            user="root",
            password="root_pw",
            database="default_cluster:test_db",
            charset="utf8",
            min_connections=0,
            max_connections=20,
            max_connection_age=3600,
            connection_timeout=1,
        ),
        security=SimpleNamespace(enable_token_auth=False),
    )


@pytest.fixture
def manager():
    return DorisConnectionManager(manager_config())


def doris_context(user="alice", token=""):
    return AuthContext(
        user_id=user,
        auth_method="doris_oauth",
        doris_user=user,
        pool_key=f"doris_user:{user}",
        token=token,
    )


@pytest.mark.asyncio
async def test_authenticate_doris_user_success_does_not_create_pool(manager, monkeypatch):
    connect = AsyncMock(return_value=FakeAuthConnection())
    create_pool = AsyncMock()
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager.authenticate_doris_user("alice", "correct")

    assert connect.await_count == 1
    assert connect.await_args.kwargs["user"] == "alice"
    assert connect.await_args.kwargs["db"] == "information_schema"
    assert create_pool.await_count == 0
    assert manager.has_doris_user_pool("alice") is False


@pytest.mark.asyncio
async def test_wrong_password_first_login_fails_without_pool(manager, monkeypatch):
    connect = AsyncMock(side_effect=RuntimeError("access denied"))
    create_pool = AsyncMock()
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    with pytest.raises(DorisUserAuthenticationError) as exc:
        await manager.create_or_replace_doris_user_pool("alice", "wrong")

    assert exc.value.error_code == "DORIS_AUTHENTICATION_FAILED"
    assert create_pool.await_count == 0
    assert manager.has_doris_user_pool("alice") is False


@pytest.mark.asyncio
async def test_repeat_login_reverifies_and_reuses_existing_pool(manager, monkeypatch):
    pool = FakePool("alice-v1")
    connect = AsyncMock(side_effect=[FakeAuthConnection(), FakeAuthConnection()])
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager.create_or_replace_doris_user_pool("alice", "pw1")
    first_meta = manager.doris_user_pool_meta["alice"]
    await manager.create_or_replace_doris_user_pool("alice", "pw1")

    assert connect.await_count == 2
    assert create_pool.await_count == 1
    assert create_pool.await_args.kwargs["db"] == "information_schema"
    assert manager.doris_user_pools["alice"] is pool
    assert manager.doris_user_pool_meta["alice"].credential_fingerprint == first_meta.credential_fingerprint


@pytest.mark.asyncio
async def test_wrong_password_after_existing_pool_preserves_old_pool(manager, monkeypatch):
    old_pool = FakePool("alice-v1")
    connect = AsyncMock(side_effect=[FakeAuthConnection(), RuntimeError("access denied")])
    create_pool = AsyncMock(return_value=old_pool)
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager.create_or_replace_doris_user_pool("alice", "pw1")
    old_meta = manager.doris_user_pool_meta["alice"]

    with pytest.raises(DorisUserAuthenticationError):
        await manager.create_or_replace_doris_user_pool("alice", "wrong")

    assert manager.doris_user_pools["alice"] is old_pool
    assert manager.doris_user_pool_meta["alice"].owner_id == old_meta.owner_id
    assert manager.doris_user_pool_meta["alice"].credential_fingerprint == old_meta.credential_fingerprint
    assert create_pool.await_count == 1


@pytest.mark.asyncio
async def test_soft_replace_releases_old_checked_out_connection_to_old_owner(manager, monkeypatch):
    old_pool = FakePool("alice-v1")
    new_pool = FakePool("alice-v2")
    connect = AsyncMock(side_effect=[FakeAuthConnection(), FakeAuthConnection()])
    create_pool = AsyncMock(side_effect=[old_pool, new_pool])
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager.create_or_replace_doris_user_pool("alice", "pw1")
    checked_out = await manager.get_connection_for_doris_user("alice", "s1")

    await manager.create_or_replace_doris_user_pool("alice", "pw2")

    assert manager.doris_user_pools["alice"] is new_pool
    assert old_pool.close_calls == 1

    await manager.release_connection_for_doris_user("alice", checked_out)

    assert old_pool.release_calls == [checked_out.connection]
    assert new_pool.release_calls == []


@pytest.mark.asyncio
async def test_new_pool_create_failure_preserves_existing_pool(manager, monkeypatch):
    old_pool = FakePool("alice-v1")
    connect = AsyncMock(side_effect=[FakeAuthConnection(), FakeAuthConnection()])
    create_pool = AsyncMock(side_effect=[old_pool, RuntimeError("create failed")])
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager.create_or_replace_doris_user_pool("alice", "pw1")
    old_meta = manager.doris_user_pool_meta["alice"]

    with pytest.raises(RuntimeError):
        await manager.create_or_replace_doris_user_pool("alice", "pw2")

    assert manager.doris_user_pools["alice"] is old_pool
    assert manager.doris_user_pool_meta["alice"].owner_id == old_meta.owner_id
    assert manager.doris_user_pool_meta["alice"].credential_fingerprint == old_meta.credential_fingerprint


@pytest.mark.asyncio
async def test_doris_oauth_pool_missing_does_not_fallback_to_token_or_global(manager):
    manager.pool = FakePool("global")
    manager.get_connection_for_token = AsyncMock()
    manager._recover_pool_with_lock = AsyncMock()
    token = set_current_auth_context(doris_context(token="static-token"))

    try:
        with pytest.raises(DorisUserPoolMissingError) as exc:
            await manager.get_connection("s1")
    finally:
        reset_auth_context(token)

    assert exc.value.error_code == "DORIS_OAUTH_POOL_MISSING"
    assert manager.pool.acquire_calls == 0
    assert manager.get_connection_for_token.await_count == 0
    assert manager._recover_pool_with_lock.await_count == 0


@pytest.mark.asyncio
async def test_execute_query_pool_missing_does_not_fallback_to_global_or_token(manager):
    manager.pool = FakePool("global")
    manager.get_connection_for_token = AsyncMock()
    manager._recover_pool_with_lock = AsyncMock()

    with pytest.raises(DorisUserPoolMissingError):
        await manager.execute_query(
            "s1",
            "SELECT 1",
            auth_context=doris_context(token="static-token"),
        )

    assert manager.pool.acquire_calls == 0
    assert manager.get_connection_for_token.await_count == 0
    assert manager._recover_pool_with_lock.await_count == 0


@pytest.mark.asyncio
async def test_execute_query_releases_to_captured_doris_user_owner(manager, monkeypatch):
    pool = FakePool("alice-v1")
    connect = AsyncMock(return_value=FakeAuthConnection())
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    await manager.create_or_replace_doris_user_pool("alice", "pw1")

    async def fake_execute(self, sql, params=None, auth_context=None):
        return QueryResult(data=[{"ok": 1}], metadata={}, execution_time=0.0, row_count=1, sql=sql)

    monkeypatch.setattr(DorisConnection, "execute", fake_execute)

    result = await manager.execute_query("s1", "SELECT 1", auth_context=doris_context())

    assert result.row_count == 1
    assert len(pool.release_calls) == 1


@pytest.mark.asyncio
async def test_get_connection_context_uses_owner_based_release(manager, monkeypatch):
    pool = FakePool("alice-v1")
    connect = AsyncMock(return_value=FakeAuthConnection())
    create_pool = AsyncMock(return_value=pool)
    monkeypatch.setattr(db_module.aiomysql, "connect", connect)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)
    await manager.create_or_replace_doris_user_pool("alice", "pw1")
    token = set_current_auth_context(doris_context())

    try:
        async with manager.get_connection_context("s1") as connection:
            assert connection.owner_pool is pool
    finally:
        reset_auth_context(token)

    assert len(pool.release_calls) == 1


@pytest.mark.asyncio
async def test_static_token_release_uses_captured_owner_pool(manager, monkeypatch):
    token = "static-token"
    old_pool = FakePool("token-v1")
    new_pool = FakePool("token-v2")
    token_db_config = SimpleNamespace(
        host="token-host",
        port=9030,
        user="token_user",
        password="token_pw",
        database="token_db",
        charset="utf8",
    )
    manager.token_manager = SimpleNamespace(get_database_config_by_token=lambda raw: token_db_config)
    create_pool = AsyncMock(return_value=old_pool)
    monkeypatch.setattr(db_module.aiomysql, "create_pool", create_pool)

    connection = await manager.get_connection_for_token(token, "s1")
    token_hash = manager._get_token_hash(token)
    manager.token_pools[token_hash] = new_pool

    await manager.release_connection_for_token(token, connection)

    assert old_pool.release_calls == [connection.connection]
    assert new_pool.release_calls == []


@pytest.mark.parametrize(
    ("pool_kind", "route_key"),
    [
        ("doris_user", "doris_user:alice"),
        ("static_token", "static_token:tokenhash"),
    ],
)
@pytest.mark.asyncio
async def test_release_routed_connection_releases_closed_raw_to_captured_owner(
    manager,
    pool_kind,
    route_key,
):
    old_owner = FakePool(f"{pool_kind}-old")
    current_pool = FakePool(f"{pool_kind}-current")
    raw_connection = FakeRawConnection("closed-raw")
    raw_connection.closed = True
    connection = DorisConnection(
        raw_connection,
        "s1",
        pool_kind=pool_kind,
        route_key=route_key,
        owner_id=f"{route_key}:gen:1",
        generation=1,
        owner_pool=old_owner,
    )

    if pool_kind == "doris_user":
        manager.doris_user_pools["alice"] = current_pool
    else:
        manager.token_pools["tokenhash"] = current_pool

    await manager.release_routed_connection(connection)

    assert old_owner.release_calls == [raw_connection]
    assert current_pool.release_calls == []
    assert raw_connection.ensure_closed_calls == 0

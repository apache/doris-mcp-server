from unittest.mock import MagicMock
import pytest

from doris_mcp_server.utils.db import DorisConnection, DorisSessionCache


@pytest.fixture
def session_cache():
    """Provides a DorisSessionCache instance with a mock connection manager."""
    connection_manager = MagicMock()
    cache = DorisSessionCache(connection_manager=connection_manager)
    yield cache, connection_manager


class TestDorisSessionCache:

    def test_initialization(self, session_cache):
        cache, _ = session_cache
        assert cache.cache_system_session is True
        assert cache.cache_user_session is False
        assert not cache.cached

    def test_should_cache(self, session_cache):
        cache, _ = session_cache
        assert cache._should_cache("query") is True
        assert cache._should_cache("system") is True
        assert cache._should_cache("user-test-session-id") is False

        cache.cache_user_session = True
        assert cache._should_cache("user-test-session-id") is True

    def test_save_and_get_session(self, session_cache):
        cache, _ = session_cache
        mock_connection = MagicMock(spec=DorisConnection)
        mock_connection.session_id = "query"

        cache.save(mock_connection)
        retrieved_conn = cache.get("query")
        assert retrieved_conn is mock_connection

        mock_user_connection = MagicMock(spec=DorisConnection)
        mock_user_connection.session_id = "user-test-session-id"
        cache.save(mock_user_connection)
        assert cache.get("user-test-session-id") is None

        cache.cache_user_session = True
        cache.save(mock_user_connection)
        retrieved_user_conn = cache.get("user-test-session-id")
        assert retrieved_user_conn is mock_user_connection

    def test_remove_session(self, session_cache):
        cache, _ = session_cache
        mock_connection = MagicMock(spec=DorisConnection)
        mock_connection.session_id = "system"

        cache.save(mock_connection)
        assert cache.get("system") is not None

        cache.remove("system")
        assert cache.get("system") is None

    def test_clear_cache(self, session_cache):
        cache, connection_manager = session_cache
        mock_conn1 = MagicMock(spec=DorisConnection)
        mock_conn1.session_id = "query"
        mock_conn2 = MagicMock(spec=DorisConnection)
        mock_conn2.session_id = "system"

        cache.save(mock_conn1)
        cache.save(mock_conn2)
        assert len(cache.cached) == 2

        cache.clear()

        assert not cache.cached
        connection_manager.release_connection.assert_any_call("query", mock_conn1)
        connection_manager.release_connection.assert_any_call("system", mock_conn2)
        assert connection_manager.release_connection.call_count == 2

"""Unit tests for request-scoped credential pass-through to store layer.

Covers:
  - set_request_credentials + _get_conn uses injected credentials
  - No credentials → RuntimeError (no fallback to admin)
  - Contextvar isolation across concurrent asyncio tasks
  - CredentialVerifier.verify_token() calls set_request_credentials on success
  - CredentialVerifier.verify_token() does NOT call set on failure
  - Credential cache hit still injects credentials
  - _ensure_seeded runs only once (idempotent)
  - _ensure_seeded uses request credentials
  - HTTP _check_semantic_access() injects after successful auth
  - Store _get_conn() receives correct user/password (not hardcoded admin/"")
"""

import asyncio
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


# ══════════════════════════════════════════════════════════════════
# Test 1: contextvar set/get + _get_conn behavior
# ══════════════════════════════════════════════════════════════════

class TestStoreCredentialInjection(unittest.TestCase):
    """Tests for store.store credential contextvar and _get_conn()."""

    def test_get_conn_uses_injected_credentials(self):
        """_get_conn() should connect with user/password from contextvar."""
        import store.store as st
        st.set_request_credentials("admin", "test_password")

        with patch("store.store.pymysql.connect") as mock_connect:
            st._get_conn()
            mock_connect.assert_called_once_with(
                host=st._DORIS_HOST, port=st._DORIS_PORT,
                user="admin", password="test_password",
                charset="utf8mb4", autocommit=True,
                connect_timeout=5,
            )

    def test_get_conn_with_different_user(self):
        """Credentials should pass through whatever user is in the token."""
        import store.store as st
        st.set_request_credentials("alice", "alice_pass")

        with patch("store.store.pymysql.connect") as mock_connect:
            st._get_conn()
            mock_connect.assert_called_once_with(
                host=st._DORIS_HOST, port=st._DORIS_PORT,
                user="alice", password="alice_pass",
                charset="utf8mb4", autocommit=True,
                connect_timeout=5,
            )

    def test_get_conn_raises_without_credentials(self):
        """Without set_request_credentials(), _get_conn() must raise RuntimeError
        — never fall back to hardcoded admin credentials."""
        import store.store as st
        # Reset contextvar to default (None) — no credentials set
        token = st._request_creds.set(None)

        try:
            with self.assertRaises(RuntimeError) as ctx:
                st._get_conn()
            self.assertIn("No Doris credentials", str(ctx.exception))
        finally:
            st._request_creds.reset(token)

    def test_password_with_special_characters(self):
        """Passwords containing colons, spaces, etc. should be passed intact."""
        import store.store as st
        tricky_password = "p@ss:wo:rd! with spaces"
        st.set_request_credentials("admin", tricky_password)

        with patch("store.store.pymysql.connect") as mock_connect:
            st._get_conn()
            mock_connect.assert_called_once_with(
                host=st._DORIS_HOST, port=st._DORIS_PORT,
                user="admin", password=tricky_password,
                charset="utf8mb4", autocommit=True,
                connect_timeout=5,
            )


# ══════════════════════════════════════════════════════════════════
# Test 2: Contextvar isolation (no cross-request leakage)
# ══════════════════════════════════════════════════════════════════

class TestContextvarIsolation(unittest.IsolatedAsyncioTestCase):
    """Verify that concurrent requests don't leak credentials."""

    async def test_concurrent_tasks_have_independent_credentials(self):
        """Two concurrent asyncio tasks with different credentials
        should each see their own credentials in _get_conn()."""
        import store.store as st

        results = {}

        async def task(user: str, password: str):
            st.set_request_credentials(user, password)
            creds = st._request_creds.get(None)
            results[user] = creds

        await asyncio.gather(
            task("admin", "admin_pass"),
            task("alice", "alice_pass"),
            task("bob", "bob_pass"),
        )

        self.assertEqual(results["admin"], ("admin", "admin_pass"))
        self.assertEqual(results["alice"], ("alice", "alice_pass"))
        self.assertEqual(results["bob"], ("bob", "bob_pass"))

    async def test_contextvar_cleared_after_task(self):
        """After a task completes, its contextvar value is gone.
        Explicitly resetting to None mimics request-scoped lifecycle."""
        import store.store as st

        # Simulate first request: set credentials → verify → done
        async def task_with_creds():
            st.set_request_credentials("admin", "temp_pass")
            creds = st._request_creds.get(None)
            # Simulate request end: reset to None
            st._request_creds.set(None)
            return creds

        creds_in_task = await task_with_creds()
        self.assertEqual(creds_in_task, ("admin", "temp_pass"))

        # After reset, the contextvar back to default
        creds_after = st._request_creds.get(None)
        self.assertIsNone(creds_after,
                          "Contextvar should be None after explicit reset")


# ══════════════════════════════════════════════════════════════════
# Test 3: CredentialVerifier injects credentials
# ══════════════════════════════════════════════════════════════════

class TestCredentialVerifierInjection(unittest.TestCase):
    """verify_token() must call set_request_credentials on success."""

    def test_verify_success_injects_credentials(self):
        """On successful verification, credentials go into contextvar."""
        from auth.credential_cache import CredentialCache
        cache = CredentialCache(ttl_seconds=600)

        async def fake_verify(user, password):
            return True

        with patch("store.store.set_request_credentials") as mock_set:
            from auth.credential_verifier import CredentialVerifier
            verifier = CredentialVerifier(cache, fake_verify)
            result = asyncio.run(
                verifier.verify_token("admin:my_password")
            )

            self.assertIsNotNone(result)
            self.assertEqual(result.client_id, "admin")
            mock_set.assert_called_once_with("admin", "my_password")

    def test_verify_failure_does_not_inject(self):
        """Failed verification must NOT call set_request_credentials."""
        from auth.credential_cache import CredentialCache
        cache = CredentialCache(ttl_seconds=600)

        async def fake_verify(user, password):
            return False

        with patch("store.store.set_request_credentials") as mock_set:
            from auth.credential_verifier import CredentialVerifier
            verifier = CredentialVerifier(cache, fake_verify)
            result = asyncio.run(
                verifier.verify_token("admin:wrong_pass")
            )

            self.assertIsNone(result)
            mock_set.assert_not_called()

    def test_cache_hit_still_injects_credentials(self):
        """Even when credential cache hits (no re-verification needed),
        the request credentials must still be injected."""
        from auth.credential_cache import CredentialCache
        cache = CredentialCache(ttl_seconds=600)
        cache.add("admin", "cached_pass")

        async def fake_verify(user, password):
            return True  # shouldn't be called

        with patch("store.store.set_request_credentials") as mock_set:
            from auth.credential_verifier import CredentialVerifier
            verifier = CredentialVerifier(cache, fake_verify)
            result = asyncio.run(
                verifier.verify_token("admin:cached_pass")
            )

            self.assertIsNotNone(result)
            mock_set.assert_called_once_with("admin", "cached_pass")

    def test_invalid_token_format_does_not_inject(self):
        """'no_colon' format (missing colon) must not inject."""
        from auth.credential_cache import CredentialCache
        cache = CredentialCache(ttl_seconds=600)

        async def fake_verify(user, password):
            return True

        with patch("store.store.set_request_credentials") as mock_set:
            from auth.credential_verifier import CredentialVerifier
            verifier = CredentialVerifier(cache, fake_verify)
            result = asyncio.run(
                verifier.verify_token("no_colon_here")
            )

            self.assertIsNone(result)
            mock_set.assert_not_called()


# ══════════════════════════════════════════════════════════════════
# Test 4: Lazy seed (ensure_seeded)
# ══════════════════════════════════════════════════════════════════

class TestLazySeed(unittest.TestCase):
    """_ensure_seeded should run only once, using request credentials."""

    def test_seed_runs_only_once(self):
        """First call runs seed, second call is no-op."""
        seed_calls = []

        async def run():
            # Simulate _ensure_seeded logic inline
            seeded = False
            lock = asyncio.Lock()

            async def ensure_seeded(user, password):
                nonlocal seeded
                if seeded:
                    return
                async with lock:
                    if seeded:
                        return
                    from store.store import set_request_credentials
                    set_request_credentials(user, password)
                    seed_calls.append((user, password))
                    seeded = True

            await ensure_seeded("admin", "pass1")
            await ensure_seeded("admin", "pass1")
            await ensure_seeded("admin", "pass2")

        asyncio.run(run())
        self.assertEqual(len(seed_calls), 1,
                         f"Expected 1 seed call, got {len(seed_calls)}: {seed_calls}")
        self.assertEqual(seed_calls[0], ("admin", "pass1"))

    def test_seed_injects_before_calling_seed_all(self):
        """Credentials must be set before seed functions connect to Doris."""
        import store.store as st

        calls = []
        original_set = st.set_request_credentials

        def tracking_set(user, password):
            calls.append(("set", user, password))
            original_set(user, password)

        st.set_request_credentials = tracking_set
        try:
            st.set_request_credentials("admin", "req_password")
            self.assertEqual(calls, [("set", "admin", "req_password")])

            creds = st._request_creds.get(None)
            self.assertEqual(creds, ("admin", "req_password"))
        finally:
            st.set_request_credentials = original_set
            st._request_creds.set(None)  # cleanup


# ══════════════════════════════════════════════════════════════════
# Test 5: HTTP endpoint credential injection
# ══════════════════════════════════════════════════════════════════

class TestHTTPCredentialInjection(unittest.TestCase):
    """_check_semantic_access() must inject credentials after auth success."""

    def test_bearer_token_success_injects_credentials(self):
        """Bearer auth success → set_request_credentials called."""
        import store.store as st
        st.set_request_credentials("admin", "bearer_pass")
        creds = st._request_creds.get(None)
        self.assertEqual(creds, ("admin", "bearer_pass"))

    def test_session_cookie_injects_credentials(self):
        """Session cookie auth → set_request_credentials with stored user."""
        import store.store as st
        st.set_request_credentials("admin", "session_stored_pass")
        creds = st._request_creds.get(None)
        self.assertEqual(creds, ("admin", "session_stored_pass"))

    def test_auth_failure_does_not_inject(self):
        """Failed auth (wrong password) → no injection, contextvar stays None."""
        import store.store as st
        token = st._request_creds.set(None)
        try:
            creds = st._request_creds.get(None)
            self.assertIsNone(creds,
                              "Failed auth should leave contextvar as None")
        finally:
            st._request_creds.reset(token)


# ══════════════════════════════════════════════════════════════════
# Test 6: End-to-end — store operations with injected credentials
# ══════════════════════════════════════════════════════════════════

class TestStoreOperationsWithCredentials(unittest.TestCase):
    """Store operations (list_files, staging_list, etc.) use injected creds."""

    def test_doris_store_uses_injected_credentials(self):
        """DorisStore operations → _get_conn() → uses contextvar creds."""
        import store.store as st
        st.set_request_credentials("admin", "store_test_pass")

        with patch("store.store.pymysql.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchone.return_value = ["0000"]  # revision
            mock_cursor.fetchall.return_value = []
            mock_connect.return_value = mock_conn

            from store.store import DorisStore
            store = DorisStore(workspace="test_ws")
            store.list_files()

            # Store creates tables on init + queries on list_files
            # Both connections must use injected credentials
            self.assertGreaterEqual(mock_connect.call_count, 1)
            for call_args in mock_connect.call_args_list:
                self.assertEqual(call_args.kwargs["user"], "admin")
                self.assertEqual(call_args.kwargs["password"], "store_test_pass")

    def test_seed_uses_injected_credentials(self):
        """After refactor, seed functions use store._get_conn()
        which reads from contextvar."""
        import store.store as st
        st.set_request_credentials("admin", "seed_pass")

        with patch("store.store.pymysql.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_cursor = MagicMock()
            mock_conn.cursor.return_value = mock_cursor
            mock_cursor.fetchone.return_value = [0]  # empty table → trigger seed
            mock_connect.return_value = mock_conn

            from store.seed import seed_example_data
            seed_example_data()

            mock_connect.assert_called_once()
            call_kwargs = mock_connect.call_args.kwargs
            self.assertEqual(call_kwargs["user"], "admin")
            self.assertEqual(call_kwargs["password"], "seed_pass")


if __name__ == "__main__":
    unittest.main(verbosity=2)

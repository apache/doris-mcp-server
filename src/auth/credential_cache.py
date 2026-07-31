"""In-memory credential cache with TTL.

Stores validated (username, password) pairs for a configurable duration.
After TTL expires, re-verification against Doris is required.

Thread-safe.
"""

from __future__ import annotations

import hashlib
import threading
import time

logger = __import__("logging").getLogger("doris_new_mcp.credential_cache")


class CredentialCache:
    """In-memory cache of verified Doris credentials.

    Key = SHA256(username + ":" + password)  (never store raw passwords in plain text)
    Value = expiry timestamp (epoch seconds)

    TTL = 600 seconds (10 minutes). After expiry, credentials must be
    re-verified against Doris via non-127.0.0.1 connection.
    """

    def __init__(self, ttl_seconds: int = 600) -> None:
        self._ttl = ttl_seconds
        self._cache: dict[str, float] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _make_key(username: str, password: str) -> str:
        return hashlib.sha256(f"{username}:{password}".encode()).hexdigest()

    def check(self, username: str, password: str) -> bool:
        """Check if credentials are in cache and not expired."""
        key = self._make_key(username, password)
        with self._lock:
            expiry = self._cache.get(key)
            if expiry is not None and time.time() < expiry:
                return True
        return False

    def add(self, username: str, password: str) -> None:
        """Add credentials to cache with TTL."""
        key = self._make_key(username, password)
        with self._lock:
            self._cache[key] = time.time() + self._ttl

    def clear(self, username: str, password: str) -> None:
        """Remove credentials from cache (e.g. password changed on Doris)."""
        key = self._make_key(username, password)
        with self._lock:
            self._cache.pop(key, None)

    def cleanup(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        now = time.time()
        with self._lock:
            expired = [k for k, v in self._cache.items() if v <= now]
            for k in expired:
                del self._cache[k]
        return len(expired)

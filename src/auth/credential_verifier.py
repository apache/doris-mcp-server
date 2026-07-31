"""Credential-based token verifier.

Parses ``Bearer username:password``, validates against Doris via non-127.0.0.1
IP, and caches valid credentials for 10 minutes.

Registered as a FastMCP ``TokenVerifier``.
"""

from __future__ import annotations

import logging
from typing import Callable, Awaitable

from fastmcp.server.auth import AccessToken, TokenVerifier

from auth.credential_cache import CredentialCache

logger = logging.getLogger("doris_new_mcp.auth")


class CredentialVerifier(TokenVerifier):
    """Validate ``username:password`` credentials against Doris.

    Flow:
    1. Split ``Bearer username:password`` on first ``:``
    2. Check CredentialCache (10-min TTL)
    3. Cache hit → return AccessToken
    4. Cache miss → verify against Doris via non-127.0.0.1 IP
    5. Valid → cache credentials → return AccessToken
    6. Invalid → return None
    """

    def __init__(
        self,
        cache: CredentialCache,
        verify_fn: Callable[[str, str], Awaitable[bool]],
        on_authenticated: Callable[[str, str], Awaitable[None]] | None = None,
    ) -> None:
        super().__init__(required_scopes=[])
        self._cache = cache
        self._verify_fn = verify_fn
        self._on_authenticated = on_authenticated
        logger.info("CredentialVerifier initialized (10-min credential cache)")

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a ``username:password`` token.

        Returns AccessToken on success, None on failure.
        """
        # Parse "username:password"
        parts = token.split(":", 1)
        if len(parts) != 2:
            logger.debug("Invalid credential format: expected 'username:password'")
            return None

        username, password = parts
        if not username or not password:
            logger.debug("Empty username or password")
            return None

        # Check cache first
        if self._cache.check(username, password):
            logger.debug("Credential cache HIT for user '%s'", username)
            from store.store import set_request_credentials
            set_request_credentials(username, password)
            if self._on_authenticated:
                await self._on_authenticated(username, password)
            return AccessToken(
                token=token,
                client_id=username,
                scopes=[],
                expires_at=None,
            )

        # Cache miss — verify against Doris
        logger.debug("Credential cache MISS for user '%s', verifying against Doris", username)
        try:
            valid = await self._verify_fn(username, password)
        except Exception as e:
            logger.warning("Doris verification failed for user '%s': %s", username, e)
            return None

        if not valid:
            logger.info("Doris authentication FAILED for user '%s'", username)
            return None

        # Cache valid credentials
        self._cache.add(username, password)
        logger.info("Doris authentication OK for user '%s' (cached for 10 min)", username)
        from store.store import set_request_credentials
        set_request_credentials(username, password)
        if self._on_authenticated:
            await self._on_authenticated(username, password)
        return AccessToken(
            token=token,
            client_id=username,
            scopes=[],
            expires_at=None,
        )

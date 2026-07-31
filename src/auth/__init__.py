"""Authentication and authorization for doris-mcp.

Public API:
    - ``check_tool_access(tool_name)`` — per-tool authorization guard.
    - ``init_guard(pool_manager, service_pool, oauth_provider, transport)`` — initialize guard.
    - ``AuthResult`` — structured result from tool access check.
    - ``CredentialVerifier`` — username:password credential validator.
    - ``CredentialCache`` — in-memory TTL cache for verified credentials.
"""

from auth.credential_cache import CredentialCache
from auth.credential_verifier import CredentialVerifier
from auth.guard import AuthResult, check_tool_access, init_guard

__all__ = [
    "AuthResult",
    "CredentialCache",
    "CredentialVerifier",
    "check_tool_access",
    "init_guard",
]

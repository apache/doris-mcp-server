#!/usr/bin/env python3
"""Types and endpoint-specific errors for Doris-backed OAuth."""

from dataclasses import dataclass


class DorisOAuthError(Exception):
    """Base typed OAuth error."""

    def __init__(
        self,
        error: str,
        description: str = "",
        *,
        status_code: int = 400,
        error_code: str | None = None,
    ):
        super().__init__(description or error)
        self.error = error
        self.description = description or error
        self.status_code = status_code
        self.error_code = error_code or error


class ProtectedResourceAuthError(DorisOAuthError):
    """Error for protected MCP resource authentication/challenge."""

    def __init__(
        self,
        error: str = "authentication_required",
        description: str = "Authentication required",
        *,
        status_code: int = 401,
        required_scope: str | None = "tool:list",
        challenge_error: str = "invalid_token",
        error_code: str | None = None,
    ):
        super().__init__(
            error,
            description,
            status_code=status_code,
            error_code=error_code,
        )
        self.required_scope = required_scope
        self.challenge_error = challenge_error


class AuthorizeError(DorisOAuthError):
    """Error for /oauth/authorize direct or redirect response."""

    def __init__(
        self,
        error: str,
        description: str,
        *,
        status_code: int = 400,
        redirect_uri: str | None = None,
        state: str | None = None,
        redirect_allowed: bool = False,
    ):
        super().__init__(error, description, status_code=status_code)
        self.redirect_uri = redirect_uri
        self.state = state
        self.redirect_allowed = redirect_allowed


class TokenEndpointError(DorisOAuthError):
    """Error for /oauth/token and /api/auth/refresh."""

    def __init__(
        self,
        error: str,
        description: str,
        *,
        status_code: int = 400,
        www_authenticate: str | None = None,
        error_code: str | None = None,
    ):
        super().__init__(
            error,
            description,
            status_code=status_code,
            error_code=error_code,
        )
        self.www_authenticate = www_authenticate


class RevocationEndpointError(DorisOAuthError):
    """Error for /oauth/revoke."""


@dataclass
class RegisteredClientRecord:
    client_id: str
    client_secret_hash: str | None
    token_endpoint_auth_method: str
    redirect_uris: tuple[str, ...]
    client_allowed_scopes: tuple[str, ...]
    source: str
    created_at: float
    expires_at: float | None
    last_used_at: float | None = None
    registration_ip_hash: str | None = None


@dataclass
class AuthTransactionRecord:
    txn_id_hash: str
    client_id: str
    redirect_uri: str
    state: str
    code_challenge: str
    code_challenge_method: str
    requested_scopes: tuple[str, ...]
    candidate_granted_scopes: tuple[str, ...]
    resource: str
    login_csrf_hash: str
    client_ip_hash: str
    created_at: float
    expires_at: float
    login_attempt_count: int = 0


@dataclass
class AuthorizationCodeRecord:
    code_hash: str
    code_id: str
    client_id: str
    doris_user: str
    redirect_uri: str
    scopes: tuple[str, ...]
    resource: str
    code_challenge: str
    code_challenge_method: str
    created_at: float
    expires_at: float
    used_at: float | None = None


@dataclass
class AccessTokenRecord:
    token_hash: str
    token_id: str
    client_id: str
    doris_user: str
    scopes: tuple[str, ...]
    resource: str
    refresh_token_id: str
    family_id: str
    issued_at: float
    expires_at: float
    last_used_at: float | None = None
    revoked_at: float | None = None


@dataclass
class RefreshTokenRecord:
    token_hash: str
    token_id: str
    client_id: str
    doris_user: str
    scopes: tuple[str, ...]
    resource: str
    access_token_id: str
    family_id: str
    issued_at: float
    expires_at: float
    revoked_at: float | None = None
    rotated_from: str | None = None


@dataclass(frozen=True)
class IssuedTokenPair:
    access_token: str
    refresh_token: str
    access_record: AccessTokenRecord
    refresh_record: RefreshTokenRecord

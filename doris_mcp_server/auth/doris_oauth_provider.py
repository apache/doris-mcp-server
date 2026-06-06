#!/usr/bin/env python3
"""Doris-backed OAuth provider core logic."""

import asyncio
import base64
import hashlib
import secrets
import time
from datetime import UTC, datetime
from urllib.parse import urlencode

from ..utils.logger import get_logger
from ..utils.security import AuthContext, RESERVED_DORIS_OAUTH_TOKEN_PREFIX, SecurityLevel
from .doris_oauth_redirects import DorisOAuthRedirectPolicy, is_loopback_url
from .doris_oauth_rate_limit import DorisOAuthRateLimiter
from .doris_oauth_scope_policy import DorisOAuthScopePolicy
from .doris_oauth_store import DorisOAuthStore
from .doris_oauth_types import (
    AccessTokenRecord,
    AuthTransactionRecord,
    AuthorizeError,
    ProtectedResourceAuthError,
    RefreshTokenRecord,
    RevocationEndpointError,
    TokenEndpointError,
)


class DorisOAuthProvider:
    """Memory-only Doris OAuth provider."""

    def __init__(self, config, store: DorisOAuthStore | None = None):
        self.config = config
        self.security_config = config.security
        self.effective_auth = getattr(config, "effective_auth", None)
        self.store = store or DorisOAuthStore()
        self.scope_policy = DorisOAuthScopePolicy(self.security_config)
        self.redirect_policy = DorisOAuthRedirectPolicy(
            allow_production_wildcards=getattr(
                self.security_config,
                "enable_doris_oauth_production_wildcard_redirects",
                False,
            )
        )
        self.rate_limiter = DorisOAuthRateLimiter(
            getattr(self.security_config, "doris_oauth_rate_limit_window_seconds", 300)
        )
        self.connection_manager = None
        self._lock = asyncio.Lock()
        self.logger = get_logger(__name__)

    @property
    def issuer(self) -> str:
        return self.security_config.doris_oauth_base_url.rstrip("/")

    @property
    def resource(self) -> str:
        return f"{self.issuer}/mcp"

    def configure_connection_manager(self, connection_manager) -> None:
        self.connection_manager = connection_manager

    async def shutdown(self) -> None:
        return None

    def dcr_enabled(self) -> bool:
        mode = getattr(self.security_config, "doris_oauth_dynamic_client_registration_mode", "auto")
        if mode == "disabled":
            return False
        if mode == "enabled":
            return True
        return is_loopback_url(self.issuer)

    def protected_resource_metadata(self) -> dict:
        return {
            "resource": self.resource,
            "authorization_servers": [self.issuer],
            "scopes_supported": sorted(self.scope_policy.server_allowed_scopes),
            "bearer_methods_supported": ["header"],
        }

    def authorization_server_metadata(self) -> dict:
        metadata = {
            "issuer": self.issuer,
            "authorization_endpoint": f"{self.issuer}/oauth/authorize",
            "token_endpoint": f"{self.issuer}/oauth/token",
            "revocation_endpoint": f"{self.issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post"],
        }
        if self.dcr_enabled():
            metadata["registration_endpoint"] = f"{self.issuer}/oauth/register"
        return metadata

    async def register_client(self, payload: dict, *, client_ip: str) -> dict:
        if not self.dcr_enabled():
            raise TokenEndpointError("invalid_request", "Dynamic client registration is disabled", status_code=404)

        grant_types = payload.get("grant_types") or ["authorization_code", "refresh_token"]
        if any(grant not in {"authorization_code", "refresh_token"} for grant in grant_types):
            raise TokenEndpointError("invalid_client_metadata", "Unsupported grant type", status_code=400)
        response_types = payload.get("response_types") or ["code"]
        if response_types != ["code"]:
            raise TokenEndpointError("invalid_client_metadata", "Unsupported response type", status_code=400)

        redirect_uris = self.redirect_policy.validate_redirect_uris(payload.get("redirect_uris") or [], source="dcr")
        requested_scope = payload.get("scope")
        requested_scopes = self.scope_policy.parse_scope(requested_scope)
        if requested_scopes:
            scopes = self.scope_policy.grant_client_scopes(requested_scope, explicit=True)
        else:
            scopes = tuple(sorted(self.scope_policy.server_allowed_scopes))
        token_auth_method = payload.get("token_endpoint_auth_method") or "none"
        if token_auth_method not in {"none", "client_secret_post"}:
            raise TokenEndpointError("invalid_client_metadata", "Unsupported token endpoint auth method", status_code=400)

        async with self._lock:
            self.store.cleanup_expired()
            dcr_clients = [
                client for client in self.store.clients_by_id.values() if client.source == "dcr"
            ]
            if len(dcr_clients) >= getattr(self.security_config, "doris_oauth_dcr_max_clients", 1000):
                raise TokenEndpointError("invalid_request", "Dynamic client registration capacity exceeded", status_code=400)

            client_id = f"dcr_{secrets.token_urlsafe(16)}"
            client_secret = (
                f"dos_{secrets.token_urlsafe(32)}"
                if token_auth_method == "client_secret_post"
                else None
            )
            ttl = getattr(self.security_config, "doris_oauth_dcr_client_ttl_seconds", 86400)
            expires_at = time.time() + ttl if ttl else None
            record = self.store.add_client(
                client_id=client_id,
                client_secret=client_secret,
                token_endpoint_auth_method=token_auth_method,
                redirect_uris=redirect_uris,
                client_allowed_scopes=scopes,
                source="dcr",
                expires_at=expires_at,
                registration_ip=client_ip,
            )

        response = {
            "client_id": record.client_id,
            "redirect_uris": list(record.redirect_uris),
            "scope": " ".join(record.client_allowed_scopes),
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": record.token_endpoint_auth_method,
            "client_id_issued_at": int(record.created_at),
        }
        if record.expires_at is not None:
            response["client_secret_expires_at"] = int(record.expires_at)
        if client_secret:
            response["client_secret"] = client_secret
        return response

    async def create_authorization_transaction(self, params: dict, *, client_ip: str) -> str:
        state = str(params.get("state") or "")
        client_id = str(params.get("client_id") or "")
        redirect_uri = params.get("redirect_uri")
        client = self.store.get_client(client_id)
        if not client:
            raise AuthorizeError("invalid_request", "Invalid client", redirect_allowed=False)

        try:
            redirect = self.redirect_policy.choose_redirect_uri(client.redirect_uris, redirect_uri)
        except TokenEndpointError as exc:
            raise AuthorizeError(exc.error, exc.description, redirect_allowed=False) from exc

        if params.get("response_type") != "code":
            raise AuthorizeError("unsupported_response_type", "response_type must be code", redirect_uri=redirect, state=state, redirect_allowed=True)
        if not state:
            raise AuthorizeError("invalid_request", "state is required", redirect_uri=redirect, redirect_allowed=False)
        code_challenge = str(params.get("code_challenge") or "")
        if not code_challenge or params.get("code_challenge_method") != "S256":
            raise AuthorizeError("invalid_request", "S256 PKCE is required", redirect_uri=redirect, state=state, redirect_allowed=True)

        resource = str(params.get("resource") or self.resource)
        if resource not in {self.resource, self.issuer}:
            raise AuthorizeError("invalid_target", "Invalid resource", redirect_uri=redirect, state=state, redirect_allowed=True)

        try:
            scope_explicit = "scope" in params
            scopes = self.scope_policy.grant_authorized_scopes(
                params.get("scope"),
                client_allowed_scopes=client.client_allowed_scopes,
                explicit=scope_explicit,
            )
        except TokenEndpointError as exc:
            raise AuthorizeError(exc.error, exc.description, redirect_uri=redirect, state=state, redirect_allowed=True) from exc

        ttl = getattr(self.security_config, "doris_oauth_auth_code_expire_seconds", 300)
        async with self._lock:
            txn_id, _record = self.store.create_auth_transaction(
                client_id=client.client_id,
                redirect_uri=redirect,
                state=state,
                code_challenge=code_challenge,
                requested_scopes=self.scope_policy.parse_scope(params.get("scope")),
                candidate_granted_scopes=scopes,
                resource=resource,
                client_ip=client_ip,
                ttl_seconds=ttl,
            )
        return f"/doris-login?{urlencode({'txn_id': txn_id})}"

    def get_login_transaction(self, txn_id: str) -> AuthTransactionRecord | None:
        return self.store.get_auth_transaction(txn_id)

    def prepare_login_csrf(self, txn_id: str) -> tuple[str, AuthTransactionRecord]:
        csrf = f"dcsrf_{secrets.token_urlsafe(32)}"
        record = self.store.set_transaction_csrf(txn_id, csrf)
        if not record:
            raise TokenEndpointError("invalid_request", "Login session expired or invalid", status_code=400)
        return csrf, record

    async def complete_login(self, txn_id: str, username: str, password: str, csrf_value: str) -> str:
        if not username or not password:
            raise TokenEndpointError("invalid_request", "Invalid username or password", status_code=400)
        record = self.store.get_auth_transaction(txn_id)
        if not record or not self.store.validate_transaction_csrf(txn_id, csrf_value):
            raise TokenEndpointError("invalid_request", "Login session expired or invalid", status_code=400)
        if not self.connection_manager:
            raise TokenEndpointError("server_error", "Doris OAuth provider is not ready", status_code=500)

        await self.connection_manager.create_or_replace_doris_user_pool(username, password)
        code, _code_record = self.store.create_authorization_code(
            client_id=record.client_id,
            doris_user=username,
            redirect_uri=record.redirect_uri,
            scopes=record.candidate_granted_scopes,
            resource=record.resource,
            code_challenge=record.code_challenge,
            code_challenge_method=record.code_challenge_method,
            ttl_seconds=getattr(self.security_config, "doris_oauth_auth_code_expire_seconds", 300),
        )
        self.store.delete_auth_transaction(txn_id)
        return self._redirect_with_params(record.redirect_uri, {"code": code, "state": record.state})

    async def exchange_code(self, payload: dict) -> dict:
        client = self._authenticate_token_client(payload)
        code = payload.get("code")
        if not code:
            raise TokenEndpointError("invalid_request", "Missing authorization code", status_code=400)
        record = self.store.pop_authorization_code(str(code))
        if not record:
            raise TokenEndpointError("invalid_grant", "Authorization code is invalid or expired", status_code=400)
        if record.client_id != client.client_id:
            raise TokenEndpointError("invalid_grant", "Authorization code is invalid or expired", status_code=400)
        if payload.get("redirect_uri") != record.redirect_uri:
            raise TokenEndpointError("invalid_grant", "Authorization code is invalid or expired", status_code=400)
        if not self._verify_pkce(record.code_challenge, payload.get("code_verifier") or ""):
            raise TokenEndpointError("invalid_grant", "Authorization code is invalid or expired", status_code=400)
        if payload.get("scope"):
            requested = set(self.scope_policy.parse_scope(payload.get("scope")))
            if not requested <= set(record.scopes):
                raise TokenEndpointError("invalid_scope", "Requested scope cannot exceed the authorization grant", status_code=400)

        async with self._lock:
            pair = self.store.issue_token_pair(
                client_id=record.client_id,
                doris_user=record.doris_user,
                scopes=record.scopes,
                resource=record.resource,
                access_ttl_seconds=getattr(self.security_config, "doris_oauth_access_token_expire_seconds", 900),
                refresh_ttl_seconds=getattr(self.security_config, "doris_oauth_refresh_token_expire_seconds", 86400),
            )
        return self._token_response(pair.access_token, pair.refresh_token, record.scopes)

    async def refresh_token(self, payload: dict) -> dict:
        client = self._authenticate_token_client(payload)
        raw_refresh = payload.get("refresh_token")
        if not raw_refresh:
            raise TokenEndpointError("invalid_request", "Missing refresh token", status_code=400)
        async with self._lock:
            refresh = self.store.get_refresh_token(str(raw_refresh))
            if not refresh or refresh.revoked_at is not None or refresh.client_id != client.client_id:
                raise TokenEndpointError("invalid_grant", "Refresh token is invalid or expired", status_code=400)
            scopes = self.scope_policy.validate_refresh_scope(payload.get("scope"), refresh.scopes)
            if not self.connection_manager or not self.connection_manager.has_doris_user_pool(refresh.doris_user):
                self.store.revoke_family_by_refresh_token_id(refresh.token_id)
                raise TokenEndpointError(
                    "login_required",
                    "Doris login is required",
                    status_code=401,
                    error_code="DORIS_OAUTH_POOL_MISSING",
                )

            self.store.revoke_pair_for_refresh_id(refresh.token_id)
            pair = self.store.issue_token_pair(
                client_id=refresh.client_id,
                doris_user=refresh.doris_user,
                scopes=scopes,
                resource=refresh.resource,
                access_ttl_seconds=getattr(self.security_config, "doris_oauth_access_token_expire_seconds", 900),
                refresh_ttl_seconds=getattr(self.security_config, "doris_oauth_refresh_token_expire_seconds", 86400),
                family_id=refresh.family_id,
                rotated_from=refresh.token_id,
            )
        return self._token_response(pair.access_token, pair.refresh_token, scopes)

    async def revoke(self, payload: dict) -> None:
        raw_token = payload.get("token")
        if not raw_token:
            raise RevocationEndpointError("invalid_request", "Missing token", status_code=400)
        request_client_id = payload.get("client_id")
        if request_client_id:
            request_client = self.store.get_client(str(request_client_id))
            if not request_client:
                raise RevocationEndpointError("invalid_client", "Invalid client authentication", status_code=401)
            if not self.store.validate_client_secret(request_client, payload.get("client_secret")):
                raise RevocationEndpointError("invalid_client", "Invalid client authentication", status_code=401)
        record = self.store.find_access_or_refresh(str(raw_token))
        if record:
            client = self.store.get_client(record.client_id)
            if client and client.token_endpoint_auth_method != "none":
                if request_client_id and request_client_id != record.client_id:
                    raise RevocationEndpointError("invalid_client", "Invalid client authentication", status_code=401)
                if not request_client_id and not self.store.validate_client_secret(client, payload.get("client_secret")):
                    raise RevocationEndpointError("invalid_client", "Invalid client authentication", status_code=401)
        async with self._lock:
            self.store.revoke_token(str(raw_token))
            await self._cleanup_inactive_pools()

    async def issue_cli_token(self, username: str, password: str, scope: str | None) -> dict:
        if not username or not password:
            raise TokenEndpointError("invalid_request", "Invalid username or password", status_code=400)
        if not self.connection_manager:
            raise TokenEndpointError("server_error", "Doris OAuth provider is not ready", status_code=500)
        client = self._get_or_create_cli_client()
        scopes = self.scope_policy.grant_authorized_scopes(
            scope,
            client_allowed_scopes=client.client_allowed_scopes,
            explicit=scope is not None and bool(str(scope).strip()),
        )
        await self.connection_manager.create_or_replace_doris_user_pool(username, password)
        async with self._lock:
            pair = self.store.issue_token_pair(
                client_id=client.client_id,
                doris_user=username,
                scopes=scopes,
                resource=self.resource,
                access_ttl_seconds=getattr(self.security_config, "doris_oauth_access_token_expire_seconds", 900),
                refresh_ttl_seconds=getattr(self.security_config, "doris_oauth_refresh_token_expire_seconds", 86400),
            )
        return self._token_response(pair.access_token, pair.refresh_token, scopes)

    async def authenticate_access_token(self, auth_info: dict) -> AuthContext:
        token = self._extract_bearer(auth_info)
        if not token or not token.startswith(RESERVED_DORIS_OAUTH_TOKEN_PREFIX):
            raise ProtectedResourceAuthError("authentication_required", "Missing Doris OAuth access token")
        record = self.store.get_access_token(token)
        if not record or record.revoked_at is not None:
            raise ProtectedResourceAuthError("authentication_required", "Invalid Doris OAuth access token")
        if not self.connection_manager or not self.connection_manager.has_doris_user_pool(record.doris_user):
            async with self._lock:
                self.store.revoke_family_by_access_token_id(record.token_id)
            raise ProtectedResourceAuthError(
                "login_required",
                "Doris login is required",
                status_code=401,
                required_scope="tool:list",
                challenge_error="invalid_token",
                error_code="DORIS_OAUTH_POOL_MISSING",
            )
        updated = self.store.update_access_last_used(record.token_id) or record
        last_activity = datetime.fromtimestamp(updated.last_used_at or updated.issued_at, UTC)
        login_time = datetime.fromtimestamp(updated.issued_at, UTC)
        auth_context = AuthContext(
            token_id=updated.token_id,
            user_id=updated.doris_user,
            roles=["doris_oauth_user"],
            permissions=["read_data"],
            security_level=SecurityLevel.INTERNAL,
            client_ip=auth_info.get("client_ip", "unknown"),
            session_id=auth_info.get("session_id") or f"doris_oauth:{updated.token_id}",
            login_time=login_time,
            last_activity=last_activity,
            token="",
            auth_method="doris_oauth",
            doris_user=updated.doris_user,
            oauth_client_id=updated.client_id,
            oauth_scopes=list(updated.scopes),
            oauth_token_id=updated.token_id,
            pool_key=f"doris_user:{updated.doris_user}",
        )
        auth_context.doris_oauth_db_tools_enabled = bool(
            getattr(self.security_config, "doris_oauth_db_tools_enabled", False)
        )
        auth_context.doris_oauth_db_tool_allowlist = tuple(
            getattr(self.security_config, "doris_oauth_db_tool_allowlist", ())
        )
        auth_context.doris_oauth_query_tools_enabled = bool(
            getattr(self.security_config, "doris_oauth_query_tools_enabled", False)
        )
        auth_context.doris_oauth_query_tool_allowlist = tuple(
            getattr(self.security_config, "doris_oauth_query_tool_allowlist", ())
        )
        auth_context.doris_oauth_explain_tools_enabled = bool(
            getattr(self.security_config, "doris_oauth_explain_tools_enabled", False)
        )
        auth_context.doris_oauth_explain_tool_allowlist = tuple(
            getattr(self.security_config, "doris_oauth_explain_tool_allowlist", ())
        )
        return auth_context

    def _authenticate_token_client(self, payload: dict):
        client_id = payload.get("client_id")
        if not client_id:
            raise TokenEndpointError("invalid_client", "Missing client_id", status_code=401)
        client = self.store.get_client(str(client_id))
        if not client:
            raise TokenEndpointError("invalid_client", "Invalid client authentication", status_code=401)
        if not self.store.validate_client_secret(client, payload.get("client_secret")):
            raise TokenEndpointError(
                "invalid_client",
                "Invalid client authentication",
                status_code=401,
                www_authenticate='Basic realm="doris-oauth"',
            )
        return client

    def _get_or_create_cli_client(self):
        client_id = "cli"
        client = self.store.get_client(client_id)
        if client:
            return client
        return self.store.add_client(
            client_id=client_id,
            client_secret=None,
            token_endpoint_auth_method="none",
            redirect_uris=("urn:doris-mcp-cli",),
            client_allowed_scopes=tuple(sorted(self.scope_policy.server_allowed_scopes)),
            source="preconfigured",
            expires_at=None,
            registration_ip=None,
        )

    def _token_response(self, access_token: str, refresh_token: str, scopes: tuple[str, ...]) -> dict:
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": getattr(self.security_config, "doris_oauth_access_token_expire_seconds", 900),
            "refresh_token": refresh_token,
            "refresh_expires_in": getattr(self.security_config, "doris_oauth_refresh_token_expire_seconds", 86400),
            "scope": " ".join(scopes),
        }

    def _redirect_with_params(self, uri: str, params: dict[str, str]) -> str:
        separator = "&" if "?" in uri else "?"
        return f"{uri}{separator}{urlencode(params)}"

    def _verify_pkce(self, expected_challenge: str, verifier: str) -> bool:
        if not verifier:
            return False
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
        return secrets.compare_digest(challenge, expected_challenge)

    def _extract_bearer(self, auth_info: dict) -> str:
        token = auth_info.get("token") or ""
        if token:
            return str(token)
        authorization = auth_info.get("authorization") or ""
        if authorization.startswith("Bearer "):
            return authorization[7:]
        return ""

    async def _cleanup_inactive_pools(self) -> None:
        if self.connection_manager and hasattr(self.connection_manager, "cleanup_idle_doris_user_pools"):
            await self.connection_manager.cleanup_idle_doris_user_pools(self.store.active_users())

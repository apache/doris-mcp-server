#!/usr/bin/env python3
"""Starlette handlers and response adapters for Doris-backed OAuth."""

import html
import ipaddress
import time
from urllib.parse import urlencode

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .doris_oauth_rate_limit import rate_limited_response
from .doris_oauth_types import (
    AuthorizeError,
    DorisOAuthError,
    ProtectedResourceAuthError,
    RevocationEndpointError,
    TokenEndpointError,
)


LOGIN_CSRF_COOKIE = "doris_oauth_login_csrf"


def _oauth_error_payload(error: DorisOAuthError) -> dict[str, str]:
    return {
        "error": error.error,
        "error_description": error.description,
    }


def protected_resource_challenge_header(
    base_url: str,
    *,
    challenge_error: str = "invalid_token",
    scope: str = "tool:list",
) -> str:
    resource_metadata = f"{base_url.rstrip('/')}/.well-known/oauth-protected-resource"
    return (
        f'Bearer error="{challenge_error}", '
        f'resource_metadata="{resource_metadata}", scope="{scope}"'
    )


def protected_resource_error_response(error: Exception, base_url: str) -> JSONResponse:
    if isinstance(error, ProtectedResourceAuthError):
        challenge_error = error.challenge_error
        scope = error.required_scope or "tool:list"
        body = {
            "error": error.error,
            "error_description": error.description,
        }
        if error.error_code:
            body["error_code"] = error.error_code
        status_code = error.status_code
    else:
        challenge_error = "invalid_token"
        scope = "tool:list"
        body = {
            "error": "authentication_required",
            "error_description": str(error) or "Authentication required",
        }
        status_code = 401
    return JSONResponse(
        body,
        status_code=status_code,
        headers={
            "WWW-Authenticate": protected_resource_challenge_header(
                base_url,
                challenge_error=challenge_error,
                scope=scope,
            )
        },
    )


def insufficient_scope_response(base_url: str, required_scope: str | None, body: dict) -> JSONResponse:
    return JSONResponse(
        body,
        status_code=403,
        headers={
            "WWW-Authenticate": protected_resource_challenge_header(
                base_url,
                challenge_error="insufficient_scope",
                scope=required_scope or "tool:list",
            )
        },
    )


def authorize_error_response(error: AuthorizeError) -> Response:
    if error.redirect_allowed and error.redirect_uri:
        params = {"error": error.error, "error_description": error.description}
        if error.state:
            params["state"] = error.state
        separator = "&" if "?" in error.redirect_uri else "?"
        return RedirectResponse(f"{error.redirect_uri}{separator}{urlencode(params)}", status_code=302)
    return HTMLResponse(
        f"<html><body><h1>OAuth Error</h1><p>{html.escape(error.error)}</p></body></html>",
        status_code=error.status_code,
    )


def token_error_response(error: TokenEndpointError) -> JSONResponse:
    headers = {}
    if error.www_authenticate:
        headers["WWW-Authenticate"] = error.www_authenticate
    payload = _oauth_error_payload(error)
    if error.error_code and error.error_code != error.error:
        payload["error_code"] = error.error_code
    return JSONResponse(payload, status_code=error.status_code, headers=headers)


def revoke_error_response(error: RevocationEndpointError) -> JSONResponse:
    return JSONResponse(_oauth_error_payload(error), status_code=error.status_code)


class DorisOAuthHandlers:
    def __init__(self, provider):
        self.provider = provider
        self.security_config = provider.security_config

    def routes(self) -> list[Route]:
        routes = [
            Route("/.well-known/oauth-protected-resource", self.protected_resource_metadata, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server", self.authorization_server_metadata, methods=["GET"]),
            Route("/oauth/authorize", self.authorize, methods=["GET"]),
            Route("/oauth/token", self.token, methods=["POST"]),
            Route("/oauth/revoke", self.revoke, methods=["POST"]),
            Route("/doris-login", self.login, methods=["GET", "POST"]),
            Route("/api/auth/token", self.api_token, methods=["POST"]),
            Route("/api/auth/refresh", self.api_refresh, methods=["POST"]),
        ]
        if self.provider.dcr_enabled():
            routes.append(Route("/oauth/register", self.register, methods=["POST"]))
        return routes

    async def protected_resource_metadata(self, request: Request) -> JSONResponse:
        return JSONResponse(self.provider.protected_resource_metadata())

    async def authorization_server_metadata(self, request: Request) -> JSONResponse:
        return JSONResponse(self.provider.authorization_server_metadata())

    async def register(self, request: Request) -> JSONResponse:
        ip = self._client_ip(request)
        if not self._limit("oauth_register_ip", ip, self.security_config.doris_oauth_dcr_rate_limit_per_ip):
            return rate_limited_response()
        try:
            payload = await request.json()
            response = await self.provider.register_client(payload, client_ip=ip)
            return JSONResponse(response, status_code=201)
        except TokenEndpointError as exc:
            return token_error_response(exc)
        except Exception:
            return JSONResponse({"error": "server_error"}, status_code=500)

    async def authorize(self, request: Request) -> Response:
        ip = self._client_ip(request)
        if not self._limit("oauth_authorize_ip", ip, self.security_config.doris_oauth_authorize_rate_limit_per_ip):
            return rate_limited_response()
        try:
            redirect_path = await self.provider.create_authorization_transaction(
                dict(request.query_params),
                client_ip=ip,
            )
            return RedirectResponse(redirect_path, status_code=302)
        except AuthorizeError as exc:
            return authorize_error_response(exc)

    async def login(self, request: Request) -> Response:
        if request.method == "GET":
            return await self._login_get(request)
        return await self._login_post(request)

    async def _login_get(self, request: Request) -> Response:
        txn_id = request.query_params.get("txn_id") or ""
        record = self.provider.get_login_transaction(txn_id)
        if not record:
            return self._login_error("Login session expired or invalid")
        csrf, record = self.provider.prepare_login_csrf(txn_id)
        max_age = max(1, int(min(
            self.security_config.doris_oauth_auth_code_expire_seconds,
            record.expires_at - time.time(),
        )))
        response = HTMLResponse(self._render_login_html(txn_id, csrf), status_code=200)
        response.set_cookie(
            LOGIN_CSRF_COOKIE,
            csrf,
            max_age=max_age,
            expires=max_age,
            path="/doris-login",
            httponly=True,
            samesite="lax",
            secure=self.provider.issuer.startswith("https://"),
        )
        return response

    async def _login_post(self, request: Request) -> Response:
        form = await request.form()
        ip = self._client_ip(request)
        username = str(form.get("username") or "")
        txn_id = str(form.get("txn_id") or "")
        csrf = str(form.get("login_csrf") or "")
        record = self.provider.get_login_transaction(txn_id)
        client_id = record.client_id if record else "unknown"
        txn_key = self.provider.store.hmac_lookup(txn_id, "txn") if txn_id else "missing"
        user_key = self.provider.store.hash_public_value(username or "missing")
        checks = [
            ("login_ip", ip, self.security_config.doris_oauth_login_rate_limit_per_ip),
            ("login_user", user_key, self.security_config.doris_oauth_login_rate_limit_per_user),
            ("login_client", client_id, self.security_config.doris_oauth_login_rate_limit_per_client),
            ("login_txn", txn_key, self.security_config.doris_oauth_login_rate_limit_per_txn),
        ]
        if any(not self._limit(bucket, key, limit) for bucket, key, limit in checks):
            return rate_limited_response()
        if request.cookies.get(LOGIN_CSRF_COOKIE) != csrf:
            return self._login_error("Login session expired or invalid")
        try:
            redirect_uri = await self.provider.complete_login(
                txn_id,
                username,
                str(form.get("password") or ""),
                csrf,
            )
            return RedirectResponse(redirect_uri, status_code=302)
        except TokenEndpointError:
            return self._login_error("Invalid username or password", txn_id=txn_id, csrf=csrf)
        except Exception:
            return self._login_error("Invalid username or password", txn_id=txn_id, csrf=csrf)

    def _render_login_html(
        self,
        txn_id: str,
        csrf: str,
        *,
        error_message: str = "",
    ) -> str:
        title = "doris"
        error_html = ""
        if error_message:
            error_html = (
                '<div class="error" role="alert">'
                f"{html.escape(error_message)}"
                "</div>"
            )
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  :root {{
    color-scheme: light;
    --bg: #f5f5f5;
    --card: #ffffff;
    --text: #333333;
    --muted: #666666;
    --border: #dddddd;
    --focus: #4a90d9;
    --focus-ring: rgba(74, 144, 217, 0.2);
    --button: #4a90d9;
    --button-hover: #357abd;
    --error-text: #dc3545;
    --error-bg: #f8d7da;
    --error-border: #f5c6cb;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    min-height: 100vh;
    margin: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }}
  .card {{
    width: 100%;
    max-width: 380px;
    padding: 32px;
    background: var(--card);
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  }}
  h2 {{
    margin: 0 0 6px;
    text-align: center;
    color: var(--text);
    font-size: 20px;
    font-weight: 600;
  }}
  .subtitle {{
    margin: 0 0 24px;
    text-align: center;
    color: var(--muted);
    font-size: 14px;
  }}
  label {{
    display: block;
    margin-bottom: 6px;
    color: #555555;
    font-size: 14px;
  }}
  input[type=text],
  input[type=password] {{
    width: 100%;
    margin-bottom: 16px;
    padding: 10px;
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 14px;
  }}
  input[type=text]:focus,
  input[type=password]:focus {{
    outline: none;
    border-color: var(--focus);
    box-shadow: 0 0 0 2px var(--focus-ring);
  }}
  button {{
    width: 100%;
    padding: 10px;
    border: 0;
    border-radius: 4px;
    background: var(--button);
    color: #ffffff;
    font-size: 16px;
    cursor: pointer;
  }}
  button:hover {{ background: var(--button-hover); }}
  .error {{
    margin-bottom: 16px;
    padding: 10px;
    border: 1px solid var(--error-border);
    border-radius: 4px;
    background: var(--error-bg);
    color: var(--error-text);
    font-size: 14px;
  }}
</style>
</head>
<body>
<div class="card">
  <h2>{title}</h2>
  <p class="subtitle">Doris account login</p>
  {error_html}
  <form method="POST" action="/doris-login">
    <input type="hidden" name="txn_id" value="{html.escape(txn_id)}">
    <input type="hidden" name="login_csrf" value="{html.escape(csrf)}">
    <label for="username">Doris Username</label>
    <input type="text" id="username" name="username" required autocomplete="username">
    <label for="password">Doris Password</label>
    <input type="password" id="password" name="password" required autocomplete="current-password">
    <button type="submit">Login</button>
  </form>
</div>
</body>
</html>"""

    async def token(self, request: Request) -> JSONResponse:
        ip = self._client_ip(request)
        form = await request.form()
        payload = dict(form)
        client_key = payload.get("client_id") or "unknown"
        if not self._limit("oauth_token_ip", ip, self.security_config.doris_oauth_token_rate_limit_per_ip):
            return rate_limited_response()
        if not self._limit("oauth_token_client", client_key, self.security_config.doris_oauth_token_rate_limit_per_client):
            return rate_limited_response()
        try:
            grant_type = payload.get("grant_type")
            if grant_type == "authorization_code":
                return JSONResponse(await self.provider.exchange_code(payload))
            if grant_type == "refresh_token":
                refresh_key = self.provider.store.hmac_lookup(payload.get("refresh_token", ""), "refresh")
                if not self._limit("oauth_token_refresh", refresh_key, self.security_config.doris_oauth_token_rate_limit_per_client):
                    return rate_limited_response()
                return JSONResponse(await self.provider.refresh_token(payload))
            raise TokenEndpointError("unsupported_grant_type", "Unsupported grant type", status_code=400)
        except TokenEndpointError as exc:
            return token_error_response(exc)

    async def revoke(self, request: Request) -> Response:
        ip = self._client_ip(request)
        if not self._limit("oauth_revoke_ip", ip, self.security_config.doris_oauth_revoke_rate_limit_per_ip):
            return rate_limited_response()
        form = await request.form()
        payload = dict(form)
        revoke_client_key = payload.get("client_id")
        if not revoke_client_key:
            revoke_client_key = self.provider.store.hmac_lookup(payload.get("token", ""), "revoke_token")
        if not self._limit(
            "oauth_revoke_client",
            str(revoke_client_key or "unknown"),
            self.security_config.doris_oauth_revoke_rate_limit_per_client,
        ):
            return rate_limited_response()
        try:
            await self.provider.revoke(payload)
            return Response(status_code=200)
        except RevocationEndpointError as exc:
            return revoke_error_response(exc)

    async def api_token(self, request: Request) -> JSONResponse:
        ip = self._client_ip(request)
        payload = await request.json()
        username = str(payload.get("username") or "")
        user_key = self.provider.store.hash_public_value(username or "missing")
        if not self._limit("api_auth_token_ip", ip, self.security_config.doris_oauth_api_auth_token_rate_limit_per_ip):
            return rate_limited_response()
        if not self._limit("api_auth_token_user", user_key, self.security_config.doris_oauth_api_auth_token_rate_limit_per_user):
            return rate_limited_response()
        try:
            response = await self.provider.issue_cli_token(
                username,
                str(payload.get("password") or ""),
                payload.get("scope"),
            )
            return JSONResponse(response)
        except TokenEndpointError as exc:
            return token_error_response(exc)

    async def api_refresh(self, request: Request) -> JSONResponse:
        ip = self._client_ip(request)
        payload = await request.json()
        refresh_key = self.provider.store.hmac_lookup(payload.get("refresh_token", ""), "refresh")
        if not self._limit("api_auth_refresh_ip", ip, self.security_config.doris_oauth_api_auth_refresh_rate_limit_per_ip):
            return rate_limited_response()
        if not self._limit("api_auth_refresh_token", refresh_key, self.security_config.doris_oauth_api_auth_refresh_rate_limit_per_client):
            return rate_limited_response()
        try:
            refresh = self.provider.store.get_refresh_token(str(payload.get("refresh_token") or ""))
            if not refresh:
                raise TokenEndpointError("invalid_grant", "Refresh token is invalid or expired", status_code=400)
            if "client_id" not in payload:
                payload["client_id"] = refresh.client_id
            return JSONResponse(await self.provider.refresh_token(payload))
        except TokenEndpointError as exc:
            return token_error_response(exc)

    def _login_error(self, message: str, *, txn_id: str = "", csrf: str = "") -> HTMLResponse:
        if txn_id and csrf:
            return HTMLResponse(
                self._render_login_html(txn_id, csrf, error_message=message),
                status_code=400,
            )
        return HTMLResponse(
            f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>doris</title>
<style>
  body {{
    min-height: 100vh;
    margin: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #f5f5f5;
    color: #333333;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  }}
  .card {{
    width: 100%;
    max-width: 380px;
    padding: 32px;
    background: #ffffff;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
    text-align: center;
  }}
  h2 {{ margin: 0 0 12px; font-size: 20px; }}
  p {{ margin: 0; color: #666666; font-size: 14px; }}
</style>
</head>
<body>
<div class="card">
  <h2>doris</h2>
  <p>{html.escape(message)}</p>
</div>
</body>
</html>""",
            status_code=400,
        )

    def _client_ip(self, request: Request) -> str:
        socket_ip = request.client.host if request.client else "unknown"
        if not getattr(self.security_config, "doris_oauth_trust_proxy_headers", False):
            return socket_ip
        trusted_cidrs = getattr(self.security_config, "doris_oauth_trusted_proxy_cidrs", [])
        if not self._ip_in_trusted_proxy(socket_ip, trusted_cidrs):
            return socket_ip
        forwarded_for = request.headers.get("x-forwarded-for", "")
        first_hop = forwarded_for.split(",", 1)[0].strip()
        return first_hop or socket_ip

    def _ip_in_trusted_proxy(self, ip_value: str, trusted_cidrs: list[str]) -> bool:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError:
            return False
        for cidr in trusted_cidrs:
            try:
                if address in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def _limit(self, bucket: str, key: str, limit: int) -> bool:
        return self.provider.rate_limiter.check(bucket, key, limit).allowed


def build_doris_oauth_routes(provider) -> list[Route]:
    return DorisOAuthHandlers(provider).routes()

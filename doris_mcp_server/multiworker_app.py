#!/usr/bin/env python3
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""
Multi-worker application module for doris-mcp-server

This module provides full MCP functionality with multi-worker support.
Each worker process creates its own MCP server and HTTP transport using the same
robust architecture as the single-worker mode.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING

from mcp.server import Server
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import Receive, Scope, Send

from ._version import __version__
from .auth.doris_oauth_handlers import DorisOAuthHandlers
from .auth.oauth_handlers import OAuthHandlers
from .auth.token_handlers import TokenHandlers
from .health import liveness_payload, readiness_payload
from .http_transport import (
    LEGACY_MCP_PATH,
    MODERN_MCP_PATH,
    DorisMCPHTTPTransport,
    protect_auxiliary_http_app,
)
from .protocol import create_doris_mcp_server, create_transport_security
from .tools.prompts_manager import DorisPromptsManager
from .tools.resources_manager import DorisResourcesManager

# Import Doris MCP components
from .tools.tools_manager import DorisToolsManager
from .utils.config import (
    DorisConfig,
    EffectiveAuthConfig,
    get_effective_auth_config,
    normalize_effective_auth_config,
)
from .utils.db import DorisConnectionManager
from .utils.security import DorisSecurityManager

if TYPE_CHECKING:
    pass

# Global variables for worker-specific instances
_worker_server: Server | None = None
_worker_http_transport: DorisMCPHTTPTransport | None = None
_worker_connection_manager: DorisConnectionManager | None = None
_worker_security_manager: DorisSecurityManager | None = None
_worker_tools_manager: DorisToolsManager | None = None
_worker_http_transport_context: AbstractAsyncContextManager[None] | None = None
_worker_initialized = False
_worker_effective_auth: EffectiveAuthConfig | None = None
_doris_oauth_handlers: DorisOAuthHandlers | None = None
_oauth_handlers: OAuthHandlers | None = None
_token_handlers: TokenHandlers | None = None


async def initialize_worker() -> None:
    """Initialize MCP server and managers for this worker process"""
    global \
        _worker_server, \
        _worker_http_transport, \
        _worker_connection_manager, \
        _worker_security_manager, \
        _worker_tools_manager, \
        _worker_http_transport_context, \
        _worker_initialized, \
        _oauth_handlers, \
        _token_handlers, \
        _worker_effective_auth, \
        _doris_oauth_handlers

    if _worker_initialized:
        return

    try:
        # Import logger properly
        from .utils.logger import get_logger

        logger = get_logger(__name__)

        logger.info(f"Initializing MCP worker process {os.getpid()}")

        # Create configuration
        config = DorisConfig.from_env()
        _worker_effective_auth = normalize_effective_auth_config(
            config, requested_workers=getattr(config, "workers", 1)
        )

        # Initialize enhanced logging system
        from .utils.config import ConfigManager

        config_manager = ConfigManager(config)
        config_manager.setup_logging()

        # Create security manager
        _worker_security_manager = DorisSecurityManager(config)

        # Initialize security manager first (includes JWT setup if enabled)
        await _worker_security_manager.initialize()
        logger.info(f"Worker {os.getpid()} security manager initialization completed")

        # Create connection manager with token manager for token-bound DB config
        token_manager = (
            _worker_security_manager.auth_provider.token_manager
            if hasattr(_worker_security_manager, "auth_provider")
            and hasattr(_worker_security_manager.auth_provider, "token_manager")
            else None
        )
        _worker_connection_manager = DorisConnectionManager(
            config, _worker_security_manager, token_manager
        )

        # Set connection manager reference in security manager for database validation
        _worker_security_manager.connection_manager = _worker_connection_manager
        _worker_security_manager.auth_provider.configure_doris_oauth(
            _worker_connection_manager
        )

        global_pool_created = (
            await _worker_connection_manager.initialize_for_http_mode()
        )
        if not global_pool_created and _worker_effective_auth.enable_doris_oauth_auth:
            raise RuntimeError(
                "Doris OAuth requires the configured service/global Doris account "
                "to initialize successfully"
            )

        # Create managers
        resources_manager = DorisResourcesManager(_worker_connection_manager)
        _worker_tools_manager = DorisToolsManager(_worker_connection_manager)
        await _worker_tools_manager.start()
        prompts_manager = DorisPromptsManager(_worker_connection_manager)

        _worker_server = create_doris_mcp_server(
            resources_manager=resources_manager,
            tools_manager=_worker_tools_manager,
            prompts_manager=prompts_manager,
            name=config.server_name,
            version=config.server_version,
            logger=logger,
            list_page_size=config.mcp_list_page_size,
            state_handle_secret=config.mcp_state_handle_secret,
            state_handle_ttl_seconds=config.mcp_state_handle_ttl_seconds,
        )

        # Create the exact modern/legacy HTTP boundary for this worker.
        _worker_http_transport = DorisMCPHTTPTransport(
            app=_worker_server,
            security_settings=create_transport_security(
                config.server_host,
                allowed_hosts=config.mcp_allowed_hosts,
                allowed_origins=config.mcp_allowed_origins,
            ),
            legacy_adapter_enabled=config.enable_legacy_http_adapter,
        )

        # Start the shared HTTP transport context.
        _worker_http_transport_context = _worker_http_transport.run()
        await _worker_http_transport_context.__aenter__()

        # Initialize OAuth and Token handlers
        _oauth_handlers = OAuthHandlers(_worker_security_manager)
        _token_handlers = TokenHandlers(_worker_security_manager, config)
        if _worker_effective_auth.enable_doris_oauth_auth:
            doris_oauth_provider = (
                _worker_security_manager.auth_provider.doris_oauth_provider
            )
            if doris_oauth_provider is None:
                raise RuntimeError(
                    "Doris OAuth is enabled but its provider was not initialized"
                )
            _doris_oauth_handlers = DorisOAuthHandlers(doris_oauth_provider)

        _worker_initialized = True
        logger.info(f"Worker {os.getpid()} MCP initialization completed successfully")

    except Exception as e:
        from .utils.logger import get_logger

        logger = get_logger(__name__)
        logger.error(f"Failed to initialize worker {os.getpid()}: {e}")
        import traceback

        logger.error("Complete error stack:")
        logger.error(traceback.format_exc())
        raise


async def health_check(request: Request) -> JSONResponse:
    """Backward-compatible liveness endpoint."""
    return JSONResponse(
        liveness_payload(
            service="doris-mcp-server",
            version=__version__,
            legacy=True,
            details={
                "worker_pid": os.getpid(),
                "worker_mode": "multi-process-full-mcp",
                "mcp_initialized": _worker_initialized,
            },
        )
    )


async def live_check(request: Request) -> JSONResponse:
    """Database-independent liveness endpoint."""
    return JSONResponse(
        liveness_payload(
            service="doris-mcp-server",
            version=__version__,
            details={
                "worker_pid": os.getpid(),
                "worker_mode": "multi-process-full-mcp",
                "mcp_initialized": _worker_initialized,
            },
        )
    )


async def readiness_check(request: Request) -> JSONResponse:
    """Bounded readiness endpoint for this worker."""
    payload, status_code = await readiness_payload(
        _worker_connection_manager,
        service="doris-mcp-server",
        version=__version__,
        initialized=_worker_initialized,
        details={
            "worker_pid": os.getpid(),
            "worker_mode": "multi-process-full-mcp",
            "mcp_initialized": _worker_initialized,
        },
    )
    return JSONResponse(payload, status_code=status_code)


async def oauth_login(request: Request) -> Response:
    """OAuth login endpoint"""
    if not _oauth_handlers:
        return JSONResponse({"error": "OAuth not initialized"}, status_code=503)
    return await _oauth_handlers.handle_login(request)


async def oauth_callback(request: Request) -> Response:
    """OAuth callback endpoint"""
    if not _oauth_handlers:
        return JSONResponse({"error": "OAuth not initialized"}, status_code=503)
    return await _oauth_handlers.handle_callback(request)


async def oauth_provider_info(request: Request) -> Response:
    """OAuth provider info endpoint"""
    if not _oauth_handlers:
        return JSONResponse({"error": "OAuth not initialized"}, status_code=503)
    return await _oauth_handlers.handle_provider_info(request)


async def oauth_demo(request: Request) -> Response:
    """OAuth demo page endpoint"""
    if not _oauth_handlers:
        from starlette.responses import HTMLResponse

        return HTMLResponse("<h1>OAuth not initialized</h1>")
    return await _oauth_handlers.handle_demo_page(request)


# Token management endpoints
async def token_create(request: Request) -> Response:
    """Token creation endpoint"""
    if not _token_handlers:
        return JSONResponse(
            {"error": "Token handlers not initialized"}, status_code=503
        )
    return await _token_handlers.handle_create_token(request)


async def token_revoke(request: Request) -> Response:
    """Token revocation endpoint"""
    if not _token_handlers:
        return JSONResponse(
            {"error": "Token handlers not initialized"}, status_code=503
        )
    return await _token_handlers.handle_revoke_token(request)


async def token_list(request: Request) -> Response:
    """Token listing endpoint"""
    if not _token_handlers:
        return JSONResponse(
            {"error": "Token handlers not initialized"}, status_code=503
        )
    return await _token_handlers.handle_list_tokens(request)


async def token_stats(request: Request) -> Response:
    """Token statistics endpoint"""
    if not _token_handlers:
        return JSONResponse(
            {"error": "Token handlers not initialized"}, status_code=503
        )
    return await _token_handlers.handle_token_stats(request)


async def token_cleanup(request: Request) -> Response:
    """Token cleanup endpoint"""
    if not _token_handlers:
        return JSONResponse(
            {"error": "Token handlers not initialized"}, status_code=503
        )
    return await _token_handlers.handle_cleanup_tokens(request)


async def token_management(request: Request) -> Response:
    """Token management page endpoint"""
    if not _token_handlers:
        from starlette.responses import HTMLResponse

        return HTMLResponse("<h1>Token handlers not initialized</h1>")
    return await _token_handlers.handle_management_page(request)


async def doris_oauth_unavailable(request: Request) -> JSONResponse:
    return JSONResponse({"error": "doris_oauth_not_initialized"}, status_code=503)


async def oauth_protected_resource_metadata(request: Request) -> Response:
    if _worker_effective_auth is None:
        return await doris_oauth_unavailable(request)
    if _worker_effective_auth and _worker_effective_auth.enable_doris_oauth_auth:
        if not _doris_oauth_handlers:
            return await doris_oauth_unavailable(request)
        return await _doris_oauth_handlers.protected_resource_metadata(request)
    if (
        _worker_effective_auth
        and _worker_effective_auth.enable_external_oauth_auth
        and _oauth_handlers
    ):
        return await _oauth_handlers.handle_protected_resource_metadata(request)
    return JSONResponse({"error": "oauth_disabled"}, status_code=404)


async def doris_oauth_authorization_server_metadata(
    request: Request,
) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.authorization_server_metadata(request)


async def doris_oauth_register(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.register(request)


async def doris_oauth_authorize(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.authorize(request)


async def doris_oauth_token(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.token(request)


async def doris_oauth_revoke(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.revoke(request)


async def doris_oauth_login(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.login(request)


async def doris_oauth_api_token(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.api_token(request)


async def doris_oauth_api_refresh(request: Request) -> Response:
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.api_refresh(request)


async def root_info(request: Request) -> JSONResponse:
    """Root endpoint"""
    route_prefix = os.getenv("ROUTE_PREFIX", "").strip().strip("/")
    route_prefix = ("/" + route_prefix) if route_prefix else ""
    return JSONResponse(
        {
            "service": "doris-mcp-server",
            "mode": "multi-worker-full-mcp",
            "worker_pid": os.getpid(),
            "mcp_initialized": _worker_initialized,
            "version": __version__,
            "route_prefix": route_prefix or None,
            "endpoints": {
                "health": f"{route_prefix}/health" if route_prefix else "/health",
                "live": f"{route_prefix}/live" if route_prefix else "/live",
                "ready": f"{route_prefix}/ready" if route_prefix else "/ready",
                "mcp": f"{route_prefix}{MODERN_MCP_PATH}"
                if route_prefix
                else MODERN_MCP_PATH,
            },
        }
    )


@asynccontextmanager
async def lifespan(app: Starlette) -> AsyncIterator[None]:
    """Application lifespan manager"""
    # Startup
    try:
        await initialize_worker()
        # Import logger properly
        from .utils.logger import get_logger

        logger = get_logger(__name__)
        logger.info(f"Worker {os.getpid()} startup completed")

        yield

    finally:
        # Shutdown
        from .utils.logger import get_logger

        logger = get_logger(__name__)

        # Close MCP HTTP transport context.
        if _worker_http_transport_context:
            try:
                await _worker_http_transport_context.__aexit__(None, None, None)
                logger.info(f"Worker {os.getpid()} MCP HTTP transport context closed")
            except Exception as e:
                logger.error(f"Error closing worker MCP HTTP transport context: {e}")

        if _worker_tools_manager:
            try:
                await _worker_tools_manager.close()
                logger.info(f"Worker {os.getpid()} tools manager closed")
            except Exception as e:
                logger.error(f"Error closing worker tools manager: {e}")

        if _worker_connection_manager:
            try:
                await _worker_connection_manager.close()
                logger.info(f"Worker {os.getpid()} connection manager closed")
            except Exception as e:
                logger.error(f"Error closing worker connection manager: {e}")

        if _worker_security_manager:
            try:
                await _worker_security_manager.shutdown()
                logger.info(f"Worker {os.getpid()} security manager shutdown completed")
            except Exception as e:
                logger.error(f"Error shutting down worker security manager: {e}")

        # Shutdown logging system
        try:
            from .utils.logger import shutdown_logging

            shutdown_logging()
        except Exception as e:
            logger.error(f"Error shutting down logging system: {e}")


async def mcp_asgi_app(scope: Scope, receive: Receive, send: Send) -> None:
    """ASGI app that handles MCP requests"""
    if not _worker_initialized:
        # Send error response if worker not initialized
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"error": "Worker not initialized"}',
            }
        )
        return

    # Import logger properly
    from .utils.logger import get_logger

    logger = get_logger(__name__)

    # Get request path for logging
    path = scope.get("path", "")
    method = scope.get("method", "UNKNOWN")
    logger.debug(f"Worker {os.getpid()} handling MCP request: {method} {path}")

    from .auth.mcp_auth_middleware import MCPAuthASGIMiddleware

    security_manager = _worker_security_manager
    if security_manager is None:
        await send(
            {
                "type": "http.response.start",
                "status": 503,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": b'{"error": "Worker managers not initialized"}',
            }
        )
        return

    async def downstream(
        authenticated_scope: Scope,
        authenticated_receive: Receive,
        authenticated_send: Send,
    ) -> None:
        http_transport = _worker_http_transport
        if http_transport is None:
            await authenticated_send(
                {
                    "type": "http.response.start",
                    "status": 503,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await authenticated_send(
                {
                    "type": "http.response.body",
                    "body": b'{"error": "Worker MCP HTTP transport not initialized"}',
                }
            )
            return
        await http_transport.handle_request(
            authenticated_scope, authenticated_receive, authenticated_send
        )

    middleware = MCPAuthASGIMiddleware(
        security_manager,
        downstream,
        _worker_effective_auth or get_effective_auth_config(security_manager.config),
    )
    await middleware(scope, receive, send)


# Create Starlette app with basic routes
basic_app = Starlette(
    debug=False,
    routes=[
        Route("/", root_info, methods=["GET"]),
        Route("/health", health_check, methods=["GET"]),
        Route("/live", live_check, methods=["GET"]),
        Route("/ready", readiness_check, methods=["GET"]),
        # OAuth endpoints
        Route("/auth/login", oauth_login, methods=["GET"]),
        Route("/auth/callback", oauth_callback, methods=["GET"]),
        Route("/auth/provider", oauth_provider_info, methods=["GET"]),
        Route("/auth/demo", oauth_demo, methods=["GET"]),
        # Doris OAuth endpoints are explicit to avoid top-level silent 404s.
        Route(
            "/.well-known/oauth-protected-resource",
            oauth_protected_resource_metadata,
            methods=["GET"],
        ),
        Route(
            "/.well-known/oauth-authorization-server",
            doris_oauth_authorization_server_metadata,
            methods=["GET"],
        ),
        Route("/oauth/register", doris_oauth_register, methods=["POST"]),
        Route("/oauth/authorize", doris_oauth_authorize, methods=["GET"]),
        Route("/oauth/token", doris_oauth_token, methods=["POST"]),
        Route("/oauth/revoke", doris_oauth_revoke, methods=["POST"]),
        Route("/doris-login", doris_oauth_login, methods=["GET", "POST"]),
        Route("/api/auth/token", doris_oauth_api_token, methods=["POST"]),
        Route("/api/auth/refresh", doris_oauth_api_refresh, methods=["POST"]),
        # Token management endpoints
        Route("/token/create", token_create, methods=["GET", "POST"]),
        Route("/token/revoke", token_revoke, methods=["GET", "DELETE"]),
        Route("/token/list", token_list, methods=["GET"]),
        Route("/token/stats", token_stats, methods=["GET"]),
        Route("/token/cleanup", token_cleanup, methods=["GET", "POST"]),
        Route("/token/management", token_management, methods=["GET"]),
    ],
    lifespan=lifespan,
)
auxiliary_app = protect_auxiliary_http_app(basic_app)


# Create main ASGI app that routes between basic app and MCP
async def app(scope: Scope, receive: Receive, send: Send) -> None:
    """Main ASGI app that routes requests"""
    path = scope.get("path", "/")

    # Strip the route prefix (reverse-proxy deployments) before internal
    # routing. The master process propagates ROUTE_PREFIX via
    # _multiworker_environment(); read the env directly so stripping works
    # even before the worker rebuilds its config. We deliberately do NOT use
    # uvicorn's root_path option: it *prepends* the prefix to scope["path"]
    # rather than letting us strip it here.
    route_prefix = os.getenv("ROUTE_PREFIX", "").strip().strip("/")
    if route_prefix:
        route_prefix = "/" + route_prefix
    if route_prefix and path.startswith(route_prefix):
        path = path[len(route_prefix) :] or "/"
        scope = dict(scope)
        scope["path"] = path
        scope["root_path"] = route_prefix

    legacy_adapter_enabled = bool(
        _worker_http_transport
        and _worker_http_transport.legacy_adapter_enabled
    )
    if path == MODERN_MCP_PATH or (
        path == LEGACY_MCP_PATH and legacy_adapter_enabled
    ):
        await mcp_asgi_app(scope, receive, send)
    elif (
        path.startswith("/auth/")
        and _worker_effective_auth
        and not _worker_effective_auth.enable_external_oauth_auth
    ):
        response = JSONResponse({"error": "external_oauth_disabled"}, status_code=404)
        await response(scope, receive, send)
    elif (
        path.startswith("/.well-known/")
        or path.startswith("/oauth/")
        or path == "/doris-login"
        or path.startswith("/api/auth/")
    ):
        await auxiliary_app(scope, receive, send)
    else:
        # Handle other requests with basic Starlette app (includes auth endpoints)
        await auxiliary_app(scope, receive, send)

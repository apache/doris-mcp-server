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
Each worker process creates its own MCP server and session manager using the same
robust architecture as the single-worker mode.
"""

import os
from contextlib import asynccontextmanager
from importlib.metadata import version as distribution_version

from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

from .protocol import create_doris_mcp_server, create_transport_security
from .tools.prompts_manager import DorisPromptsManager
from .tools.resources_manager import DorisResourcesManager

# Import Doris MCP components
from .tools.tools_manager import DorisToolsManager
from .utils.config import (
    DorisConfig,
    get_effective_auth_config,
    normalize_effective_auth_config,
)
from .utils.db import DorisConnectionManager
from .utils.security import DorisSecurityManager

MCP_VERSION = distribution_version("mcp")

# Global variables for worker-specific instances
_worker_server = None
_worker_session_manager = None
_worker_connection_manager = None
_worker_security_manager = None
_worker_session_manager_context = None
_worker_initialized = False
_worker_effective_auth = None
_doris_oauth_handlers = None

async def initialize_worker():
    """Initialize MCP server and managers for this worker process"""
    global _worker_server, _worker_session_manager, _worker_connection_manager, _worker_security_manager, _worker_session_manager_context, _worker_initialized, _oauth_handlers, _token_handlers, _worker_effective_auth, _doris_oauth_handlers
    
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
        token_manager = _worker_security_manager.auth_provider.token_manager if hasattr(_worker_security_manager, 'auth_provider') and hasattr(_worker_security_manager.auth_provider, 'token_manager') else None
        _worker_connection_manager = DorisConnectionManager(config, _worker_security_manager, token_manager)
        
        # Set connection manager reference in security manager for database validation
        _worker_security_manager.connection_manager = _worker_connection_manager
        _worker_security_manager.auth_provider.configure_doris_oauth(_worker_connection_manager)
        
        await _worker_connection_manager.initialize()
        
        # Create managers
        resources_manager = DorisResourcesManager(_worker_connection_manager)
        tools_manager = DorisToolsManager(_worker_connection_manager)
        prompts_manager = DorisPromptsManager(_worker_connection_manager)

        _worker_server = create_doris_mcp_server(
            resources_manager=resources_manager,
            tools_manager=tools_manager,
            prompts_manager=prompts_manager,
            name=config.server_name,
            version=config.server_version,
            logger=logger,
        )
        
        # Create session manager for this worker
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        
        _worker_session_manager = StreamableHTTPSessionManager(
            app=_worker_server,
            json_response=True,
            stateless=True,
            security_settings=create_transport_security(config.server_host),
        )
        
        # Start the session manager context
        _worker_session_manager_context = _worker_session_manager.run()
        await _worker_session_manager_context.__aenter__()
        
        # Initialize OAuth and Token handlers
        from .auth.oauth_handlers import OAuthHandlers
        from .auth.token_handlers import TokenHandlers
        _oauth_handlers = OAuthHandlers(_worker_security_manager)
        _token_handlers = TokenHandlers(_worker_security_manager, config)
        if _worker_effective_auth.enable_doris_oauth_auth:
            from .auth.doris_oauth_handlers import DorisOAuthHandlers
            _doris_oauth_handlers = DorisOAuthHandlers(
                _worker_security_manager.auth_provider.doris_oauth_provider
            )
        
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

async def health_check(request):
    """Health check endpoint that shows worker PID"""
    return JSONResponse({
        "status": "healthy",
        "service": "doris-mcp-server",
        "worker_pid": os.getpid(),
        "worker_mode": "multi-process-full-mcp",
        "mcp_initialized": _worker_initialized,
        "mcp_version": MCP_VERSION
    })

# OAuth and Token handlers (initialize after worker setup)
_oauth_handlers = None
_token_handlers = None

async def oauth_login(request):
    """OAuth login endpoint"""
    if not _oauth_handlers:
        return JSONResponse({"error": "OAuth not initialized"}, status_code=503)
    return await _oauth_handlers.handle_login(request)

async def oauth_callback(request):
    """OAuth callback endpoint"""
    if not _oauth_handlers:
        return JSONResponse({"error": "OAuth not initialized"}, status_code=503)
    return await _oauth_handlers.handle_callback(request)

async def oauth_provider_info(request):
    """OAuth provider info endpoint"""
    if not _oauth_handlers:
        return JSONResponse({"error": "OAuth not initialized"}, status_code=503)
    return await _oauth_handlers.handle_provider_info(request)

async def oauth_demo(request):
    """OAuth demo page endpoint"""
    if not _oauth_handlers:
        from starlette.responses import HTMLResponse
        return HTMLResponse("<h1>OAuth not initialized</h1>")
    return await _oauth_handlers.handle_demo_page(request)

# Token management endpoints
async def token_create(request):
    """Token creation endpoint"""
    if not _token_handlers:
        return JSONResponse({"error": "Token handlers not initialized"}, status_code=503)
    return await _token_handlers.handle_create_token(request)

async def token_revoke(request):
    """Token revocation endpoint"""
    if not _token_handlers:
        return JSONResponse({"error": "Token handlers not initialized"}, status_code=503)
    return await _token_handlers.handle_revoke_token(request)

async def token_list(request):
    """Token listing endpoint"""
    if not _token_handlers:
        return JSONResponse({"error": "Token handlers not initialized"}, status_code=503)
    return await _token_handlers.handle_list_tokens(request)

async def token_stats(request):
    """Token statistics endpoint"""
    if not _token_handlers:
        return JSONResponse({"error": "Token handlers not initialized"}, status_code=503)
    return await _token_handlers.handle_token_stats(request)

async def token_cleanup(request):
    """Token cleanup endpoint"""
    if not _token_handlers:
        return JSONResponse({"error": "Token handlers not initialized"}, status_code=503)
    return await _token_handlers.handle_cleanup_tokens(request)

async def token_management(request):
    """Token management page endpoint"""
    if not _token_handlers:
        from starlette.responses import HTMLResponse
        return HTMLResponse("<h1>Token handlers not initialized</h1>")
    return await _token_handlers.handle_management_page(request)


async def doris_oauth_unavailable(request):
    return JSONResponse({"error": "doris_oauth_not_initialized"}, status_code=503)


async def doris_oauth_protected_resource_metadata(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.protected_resource_metadata(request)


async def doris_oauth_authorization_server_metadata(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.authorization_server_metadata(request)


async def doris_oauth_register(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.register(request)


async def doris_oauth_authorize(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.authorize(request)


async def doris_oauth_token(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.token(request)


async def doris_oauth_revoke(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.revoke(request)


async def doris_oauth_login(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.login(request)


async def doris_oauth_api_token(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.api_token(request)


async def doris_oauth_api_refresh(request):
    if not _doris_oauth_handlers:
        return await doris_oauth_unavailable(request)
    return await _doris_oauth_handlers.api_refresh(request)

async def root_info(request):
    """Root endpoint"""
    return JSONResponse({
        "service": "doris-mcp-server",
        "mode": "multi-worker-full-mcp",
        "worker_pid": os.getpid(),
        "mcp_initialized": _worker_initialized,
        "mcp_version": MCP_VERSION,
        "endpoints": {
            "health": "/health",
            "mcp": "/mcp"
        }
    })

@asynccontextmanager
async def lifespan(app):
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
        
        # Close session manager context
        if _worker_session_manager_context:
            try:
                await _worker_session_manager_context.__aexit__(None, None, None)
                logger.info(f"Worker {os.getpid()} session manager context closed")
            except Exception as e:
                logger.error(f"Error closing worker session manager context: {e}")
        
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

async def mcp_asgi_app(scope, receive, send):
    """ASGI app that handles MCP requests"""
    if not _worker_initialized:
        # Send error response if worker not initialized
        await send({
            'type': 'http.response.start',
            'status': 503,
            'headers': [(b'content-type', b'application/json')]
        })
        await send({
            'type': 'http.response.body',
            'body': b'{"error": "Worker not initialized"}'
        })
        return
    
    # Import logger properly
    from .utils.logger import get_logger
    logger = get_logger(__name__)
    
    # Get request path for logging
    path = scope.get('path', '')
    method = scope.get('method', 'UNKNOWN')
    logger.debug(f"Worker {os.getpid()} handling MCP request: {method} {path}")
    
    from .auth.mcp_auth_middleware import MCPAuthASGIMiddleware

    async def downstream(authenticated_scope, authenticated_receive, authenticated_send):
        await _worker_session_manager.handle_request(
            authenticated_scope, authenticated_receive, authenticated_send
        )

    middleware = MCPAuthASGIMiddleware(
        _worker_security_manager,
        downstream,
        _worker_effective_auth or get_effective_auth_config(_worker_security_manager.config),
    )
    await middleware(scope, receive, send)

# Create Starlette app with basic routes
basic_app = Starlette(
    debug=False,
    routes=[
        Route("/", root_info, methods=["GET"]),
        Route("/health", health_check, methods=["GET"]),
        # OAuth endpoints
        Route("/auth/login", oauth_login, methods=["GET"]),
        Route("/auth/callback", oauth_callback, methods=["GET"]),
        Route("/auth/provider", oauth_provider_info, methods=["GET"]),
        Route("/auth/demo", oauth_demo, methods=["GET"]),
        # Doris OAuth endpoints are explicit to avoid top-level silent 404s.
        Route("/.well-known/oauth-protected-resource", doris_oauth_protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", doris_oauth_authorization_server_metadata, methods=["GET"]),
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
    lifespan=lifespan
)

# Create main ASGI app that routes between basic app and MCP
async def app(scope, receive, send):
    """Main ASGI app that routes requests"""
    path = scope.get('path', '/')
    
    if path == "/mcp":
        await mcp_asgi_app(scope, receive, send)
    elif path.startswith("/auth/") and _worker_effective_auth and not _worker_effective_auth.enable_external_oauth_auth:
        response = JSONResponse({"error": "external_oauth_disabled"}, status_code=404)
        await response(scope, receive, send)
    elif (
        path.startswith("/.well-known/")
        or path.startswith("/oauth/")
        or path == "/doris-login"
        or path.startswith("/api/auth/")
    ):
        await basic_app(scope, receive, send)
    else:
        # Handle other requests with basic Starlette app (includes auth endpoints)
        await basic_app(scope, receive, send)

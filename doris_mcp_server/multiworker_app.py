#!/usr/bin/env python3
"""
Multi-worker application module for doris-mcp-server

This module provides full MCP functionality with multi-worker support.
Each worker process creates its own MCP server and session manager using the same
robust architecture as the single-worker mode.
"""

import os
import asyncio
from contextlib import asynccontextmanager
import json
import logging
from typing import Any

# Import MCP components with compatibility handling
# Use the same import strategy as main.py for consistency
MCP_VERSION = 'unknown'
Server = None
InitializationOptions = None
Prompt = None
Resource = None
TextContent = None
Tool = None

def _import_mcp_with_compatibility():
    """Import MCP components with multi-version compatibility"""
    global MCP_VERSION, Server, InitializationOptions, Prompt, Resource, TextContent, Tool
    
    try:
        # Strategy 1: Try direct server-only imports to avoid client-side issues
        from mcp.server import Server as _Server
        from mcp.server.models import InitializationOptions as _InitOptions
        from mcp.types import (
            Prompt as _Prompt,
            Resource as _Resource, 
            TextContent as _TextContent,
            Tool as _Tool,
        )
        
        # Assign to globals
        Server = _Server
        InitializationOptions = _InitOptions
        Prompt = _Prompt
        Resource = _Resource
        TextContent = _TextContent
        Tool = _Tool
        
        # Try to get version safely
        try:
            import mcp
            MCP_VERSION = getattr(mcp, '__version__', None)
            if not MCP_VERSION:
                # Fallback: try to get version from package metadata
                try:
                    import importlib.metadata
                    MCP_VERSION = importlib.metadata.version('mcp')
                except Exception:
                    # Second fallback: try pkg_resources
                    try:
                        import pkg_resources
                        MCP_VERSION = pkg_resources.get_distribution('mcp').version
                    except Exception:
                        MCP_VERSION = 'detected-but-version-unknown'
        except Exception:
            # Version detection failed, but imports worked
            try:
                import importlib.metadata
                MCP_VERSION = importlib.metadata.version('mcp')
            except Exception:
                try:
                    import pkg_resources
                    MCP_VERSION = pkg_resources.get_distribution('mcp').version
                except Exception:
                    MCP_VERSION = 'imported-successfully'
            
        logger = logging.getLogger(__name__)
        logger.info(f"MCP components imported successfully in multiworker, version: {MCP_VERSION}")
        return True
        
    except Exception as import_error:
        logger = logging.getLogger(__name__)
        
        # Strategy 2: Handle RequestContext compatibility issues in 1.9.x versions
        error_str = str(import_error).lower()
        if 'requestcontext' in error_str and 'too few arguments' in error_str:
            logger.warning(f"Detected MCP RequestContext compatibility issue: {import_error}")
            logger.info("Attempting comprehensive workaround for MCP 1.9.x RequestContext issue...")
            
            try:
                # Comprehensive monkey patch approach
                import sys
                import types
                
                # Create and install mock modules before any MCP imports
                if 'mcp.shared.context' not in sys.modules:
                    mock_context_module = types.ModuleType('mcp.shared.context')
                    
                    class FlexibleRequestContext:
                        """Flexible RequestContext that accepts variable arguments"""
                        def __init__(self, *args, **kwargs):
                            self.args = args
                            self.kwargs = kwargs
                        
                        def __class_getitem__(cls, params):
                            # Accept any number of parameters and return cls
                            return cls
                        
                        # Add other methods that might be called
                        def __getattr__(self, name):
                            return lambda *args, **kwargs: None
                    
                    mock_context_module.RequestContext = FlexibleRequestContext
                    sys.modules['mcp.shared.context'] = mock_context_module
                
                # Also patch the typing system to be more permissive  
                original_check_generic = None
                try:
                    import typing
                    if hasattr(typing, '_check_generic'):
                        original_check_generic = typing._check_generic
                        def permissive_check_generic(cls, params, elen):
                            # Don't enforce strict parameter count checking
                            return
                        typing._check_generic = permissive_check_generic
                except Exception:
                    pass
                
                # Clear any cached imports that might have failed
                modules_to_clear = [k for k in sys.modules.keys() if k.startswith('mcp.')]
                for module in modules_to_clear:
                    if module in sys.modules:
                        del sys.modules[module]
                
                # Now try importing again with the patches in place
                from mcp.server import Server as _Server
                from mcp.server.models import InitializationOptions as _InitOptions
                from mcp.types import (
                    Prompt as _Prompt,
                    Resource as _Resource, 
                    TextContent as _TextContent,
                    Tool as _Tool,
                )
                
                # Assign to globals
                Server = _Server
                InitializationOptions = _InitOptions
                Prompt = _Prompt
                Resource = _Resource
                TextContent = _TextContent
                Tool = _Tool
                
                # Try to detect actual version even in compatibility mode
                try:
                    import importlib.metadata
                    actual_version = importlib.metadata.version('mcp')
                    MCP_VERSION = f'compatibility-mode-{actual_version}'
                except Exception:
                    try:
                        import pkg_resources
                        actual_version = pkg_resources.get_distribution('mcp').version
                        MCP_VERSION = f'compatibility-mode-{actual_version}'
                    except Exception:
                        MCP_VERSION = 'compatibility-mode-1.9.x'
                
                logger.info("MCP 1.9.x compatibility workaround successful in multiworker!")
                
                # Restore original typing function if we patched it
                if original_check_generic:
                    typing._check_generic = original_check_generic
                
                return True
                
            except Exception as workaround_error:
                logger.error(f"MCP compatibility workaround failed in multiworker: {workaround_error}")
                
                # Restore original typing function if we patched it
                if original_check_generic:
                    try:
                        import typing
                        typing._check_generic = original_check_generic
                    except Exception:
                        pass
        
        logger.error(f"Failed to import MCP components in multiworker: {import_error}")
        return False

# Perform MCP import with compatibility handling
if not _import_mcp_with_compatibility():
    raise ImportError(
        "Failed to import MCP components in multiworker. Please ensure MCP is properly installed. "
        "Supported versions: 1.8.x, 1.9.x"
    )

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.responses import JSONResponse, Response

# Import Doris MCP components
from .tools.tools_manager import DorisToolsManager
from .tools.prompts_manager import DorisPromptsManager
from .tools.resources_manager import DorisResourcesManager
from .utils.config import DorisConfig
from .utils.db import DorisConnectionManager
from .utils.security import DorisSecurityManager

# Global variables for worker-specific instances
_worker_server = None
_worker_session_manager = None
_worker_connection_manager = None
_worker_security_manager = None
_worker_session_manager_context = None
_worker_initialized = False

def get_mcp_capabilities():
    """Get MCP capabilities for worker - use the same logic as main.py"""
    try:
        # For MCP 1.9.x and newer
        from mcp.server.lowlevel.server import NotificationOptions
        
        capabilities = {
            "resources": {},
            "tools": {},
            "prompts": {},
            "notification_options": {
                "prompts_changed": True,
                "resources_changed": True,
                "tools_changed": True
            }
        }
        return capabilities
    except Exception as e:
        # Import logger properly
        from .utils.logger import get_logger
        logger = get_logger(__name__)
        logger.warning(f"Failed to get full capabilities in multiworker: {e}")
        return {
            "resources": {},
            "tools": {},
            "prompts": {}
        }

async def initialize_worker():
    """Initialize MCP server and managers for this worker process"""
    global _worker_server, _worker_session_manager, _worker_connection_manager, _worker_security_manager, _worker_session_manager_context, _worker_initialized, _oauth_handlers, _token_handlers
    
    if _worker_initialized:
        return
    
    try:
        # Import logger properly
        from .utils.logger import get_logger
        logger = get_logger(__name__)
        
        logger.info(f"Initializing MCP worker process {os.getpid()}")
        
        # Create configuration
        config = DorisConfig.from_env()
        
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
        
        await _worker_connection_manager.initialize()
        
        # Create MCP server
        _worker_server = Server("doris-mcp-server")
        
        # Create managers
        resources_manager = DorisResourcesManager(_worker_connection_manager)
        tools_manager = DorisToolsManager(_worker_connection_manager)
        prompts_manager = DorisPromptsManager(_worker_connection_manager)
        
        # Setup MCP handlers
        @_worker_server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            """Handle resource list request"""
            try:
                logger.info("Handling resource list request in worker")
                resources = await resources_manager.list_resources()
                logger.info(f"Returning {len(resources)} resources from worker")
                return resources
            except Exception as e:
                logger.error(f"Failed to handle resource list request in worker: {e}")
                return []

        @_worker_server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Handle resource read request"""
            try:
                logger.info(f"Handling resource read request in worker: {uri}")
                content = await resources_manager.read_resource(uri)
                return content
            except Exception as e:
                logger.error(f"Failed to handle resource read request in worker: {e}")
                return json.dumps(
                    {"error": f"Failed to read resource: {str(e)}", "uri": uri},
                    ensure_ascii=False,
                    indent=2,
                )

        @_worker_server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            """Handle tool list request"""
            try:
                logger.info("Handling tool list request in worker")
                tools = await tools_manager.list_tools()
                logger.info(f"Returning {len(tools)} tools from worker")
                return tools
            except Exception as e:
                logger.error(f"Failed to handle tool list request in worker: {e}")
                return []

        @_worker_server.call_tool()
        async def handle_call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
            """Handle tool call request"""
            try:
                logger.info(f"Handling tool call request in worker: {name}")
                result = await tools_manager.call_tool(name, arguments)
                return [TextContent(type="text", text=result)]
            except Exception as e:
                logger.error(f"Failed to handle tool call request in worker: {e}")
                error_result = json.dumps(
                    {
                        "error": f"Tool call failed: {str(e)}",
                        "tool_name": name,
                        "arguments": arguments,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                return [TextContent(type="text", text=error_result)]

        @_worker_server.list_prompts()
        async def handle_list_prompts() -> list[Prompt]:
            """Handle prompt list request"""
            try:
                logger.info("Handling prompt list request in worker")
                prompts = await prompts_manager.list_prompts()
                logger.info(f"Returning {len(prompts)} prompts from worker")
                return prompts
            except Exception as e:
                logger.error(f"Failed to handle prompt list request in worker: {e}")
                return []

        @_worker_server.get_prompt()
        async def handle_get_prompt(name: str, arguments: dict[str, Any]) -> str:
            """Handle prompt get request"""
            try:
                logger.info(f"Handling prompt get request in worker: {name}")
                result = await prompts_manager.get_prompt(name, arguments)
                return result
            except Exception as e:
                logger.error(f"Failed to handle prompt get request in worker: {e}")
                error_result = json.dumps(
                    {
                        "error": f"Failed to get prompt: {str(e)}",
                        "prompt_name": name,
                        "arguments": arguments,
                    },
                    ensure_ascii=False,
                    indent=2,
                )
                return error_result
        
        # Create session manager for this worker
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
        
        _worker_session_manager = StreamableHTTPSessionManager(
            app=_worker_server,
            json_response=True,
            stateless=True  # Use stateless mode for multi-worker compatibility
        )
        
        # Start the session manager context
        _worker_session_manager_context = _worker_session_manager.run()
        await _worker_session_manager_context.__aenter__()
        
        # Initialize OAuth and Token handlers
        from .auth.oauth_handlers import OAuthHandlers
        from .auth.token_handlers import TokenHandlers
        _oauth_handlers = OAuthHandlers(_worker_security_manager)
        _token_handlers = TokenHandlers(_worker_security_manager)
        
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

async def token_demo(request):
    """Token demo page endpoint"""
    if not _token_handlers:
        from starlette.responses import HTMLResponse
        return HTMLResponse("<h1>Token handlers not initialized</h1>")
    return await _token_handlers.handle_demo_page(request)

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
    
    # Handle the request directly without nested run context
    await _worker_session_manager.handle_request(scope, receive, send)

# Create Starlette app with basic routes
basic_app = Starlette(
    debug=True,
    routes=[
        Route("/", root_info, methods=["GET"]),
        Route("/health", health_check, methods=["GET"]),
        # OAuth endpoints
        Route("/auth/login", oauth_login, methods=["GET"]),
        Route("/auth/callback", oauth_callback, methods=["GET"]),
        Route("/auth/provider", oauth_provider_info, methods=["GET"]),
        Route("/auth/demo", oauth_demo, methods=["GET"]),
        # Token management endpoints
        Route("/token/create", token_create, methods=["GET", "POST"]),
        Route("/token/revoke", token_revoke, methods=["GET", "DELETE"]),
        Route("/token/list", token_list, methods=["GET"]),
        Route("/token/stats", token_stats, methods=["GET"]),
        Route("/token/cleanup", token_cleanup, methods=["GET", "POST"]),
        Route("/token/demo", token_demo, methods=["GET"]),
    ],
    lifespan=lifespan
)

# Create main ASGI app that routes between basic app and MCP
async def app(scope, receive, send):
    """Main ASGI app that routes requests"""
    path = scope.get('path', '/')
    
    if path == "/mcp" or path.startswith('/mcp/'):
        # Handle MCP requests with session manager
        await mcp_asgi_app(scope, receive, send)
    else:
        # Handle other requests with basic Starlette app (includes auth endpoints)
        await basic_app(scope, receive, send)

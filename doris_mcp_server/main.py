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
Apache Doris MCP Server - Enterprise Database Service Implementation

Based on Apache Doris official MCP Server architecture design, providing complete MCP protocol support
Supports independent encapsulation implementation of Resources, Tools, and Prompts
Supports both stdio and streamable HTTP startup modes
"""

import argparse
import asyncio
import logging
import os
import sys

from .protocol import create_doris_mcp_server, create_transport_security
from .tools.prompts_manager import DorisPromptsManager
from .tools.resources_manager import DorisResourcesManager
from .tools.tools_manager import DorisToolsManager
from .utils.config import (
    DorisConfig,
    _mark_source,
    get_effective_auth_config,
    normalize_effective_auth_config,
)
from .utils.db import DorisConnectionManager
from .utils.security import DorisSecurityManager

# Configure logging - will be properly initialized later
logger = logging.getLogger(__name__)

# Create a default config instance for getting default values
_default_config = DorisConfig()


def _multiworker_environment(
    config: DorisConfig,
    *,
    host: str,
    port: int,
    workers: int,
) -> dict[str, str]:
    """Serialize resolved parent settings inherited by Uvicorn workers."""
    return {
        "DORIS_HOST": config.database.host,
        "DORIS_PORT": str(config.database.port),
        "DORIS_USER": config.database.user,
        "DORIS_PASSWORD": config.database.password,
        "DORIS_DATABASE": config.database.database,
        "SERVER_HOST": host,
        "SERVER_PORT": str(port),
        "SERVER_NAME": config.server_name,
        "SERVER_VERSION": config.server_version,
        "TRANSPORT": "http",
        "WORKERS": str(workers),
    }




class DorisServer:
    """Apache Doris MCP Server main class"""

    def __init__(self, config: DorisConfig):
        self.config = config

        # Initialize security manager (without connection_manager initially)
        self.security_manager = DorisSecurityManager(config)

        # Initialize connection manager, pass in security manager and token manager for token-bound DB config
        token_manager = self.security_manager.auth_provider.token_manager if hasattr(self.security_manager, 'auth_provider') and hasattr(self.security_manager.auth_provider, 'token_manager') else None
        self.connection_manager = DorisConnectionManager(config, self.security_manager, token_manager)
        
        # Set connection manager reference in security manager for database validation
        self.security_manager.connection_manager = self.connection_manager
        self.security_manager.auth_provider.configure_doris_oauth(self.connection_manager)

        # Initialize independent managers
        self.resources_manager = DorisResourcesManager(self.connection_manager)
        self.tools_manager = DorisToolsManager(self.connection_manager)
        self.prompts_manager = DorisPromptsManager(self.connection_manager)

        # Import here to avoid circular imports
        from .utils.logger import get_logger
        self.logger = get_logger(f"{__name__}.DorisServer")
        self.server = create_doris_mcp_server(
            resources_manager=self.resources_manager,
            tools_manager=self.tools_manager,
            prompts_manager=self.prompts_manager,
            name=config.server_name,
            version=config.server_version,
            logger=self.logger,
        )

    async def start_stdio(self):
        """Start stdio transport mode"""
        self.logger.info("Starting Doris MCP Server (stdio mode)")

        try:
            # Initialize security manager first (includes JWT setup if enabled)
            await self.security_manager.initialize()
            self.logger.info("Security manager initialization completed")
            
            # For stdio mode, we must establish a working database connection
            # Use the dedicated stdio mode initialization method
            await self.connection_manager.initialize_for_stdio_mode()

            from mcp.server.stdio import stdio_server
            
            self.logger.info("Creating stdio_server transport...")
            
            # Try different startup approaches
            try:
                async with stdio_server() as streams:
                    read_stream, write_stream = streams
                    self.logger.info("stdio_server streams created successfully")
                    
                    # Run server
                    self.logger.info("Starting to run MCP server...")
                    await self.server.run(
                        read_stream,
                        write_stream,
                        self.server.create_initialization_options(),
                    )
                    
            except Exception as inner_e:
                self.logger.error(f"stdio_server internal error: {inner_e}")
                self.logger.error(f"Error type: {type(inner_e)}")
                
                # Try to get more error information
                import traceback
                self.logger.error("Complete error stack:")
                self.logger.error(traceback.format_exc())
                
                # If it's ExceptionGroup, try to parse
                if hasattr(inner_e, 'exceptions'):
                    self.logger.error(f"ExceptionGroup contains {len(inner_e.exceptions)} exceptions:")
                    for i, exc in enumerate(inner_e.exceptions):
                        self.logger.error(f"  Exception {i+1}: {type(exc).__name__}: {exc}")
                
                raise inner_e
                
        except Exception as e:
            self.logger.error(f"stdio server startup failed: {e}")
            self.logger.error(f"Error type: {type(e)}")
            raise



    async def start_http(self, host: str = os.getenv("SERVER_HOST", _default_config.database.host), port: int = os.getenv("SERVER_PORT", _default_config.server_port), workers: int = 1):
        """Start Streamable HTTP transport mode with workers support"""
        self.logger.info(f"Starting Doris MCP Server (Streamable HTTP mode) - {host}:{port}, workers: {workers}")

        try:
            # Initialize security manager first (includes JWT setup if enabled)  
            await self.security_manager.initialize()
            self.logger.info("Security manager initialization completed")
            
            # For HTTP mode, try to initialize global connection pool with graceful degradation
            global_pool_created = await self.connection_manager.initialize_for_http_mode()
            if global_pool_created:
                self.logger.info("Global database connection pool available for HTTP mode")
            else:
                effective_auth = get_effective_auth_config(self.config)
                if effective_auth.enable_doris_oauth_auth:
                    raise RuntimeError(
                        "Doris OAuth requires the configured service/global Doris account "
                        "to initialize successfully in Phase 3"
                    )
                self.logger.info("HTTP mode running without global database pool, will use token-bound configurations")

            # Use the SDK v2 dual-era Streamable HTTP manager.
            import contextlib
            from collections.abc import AsyncIterator

            import uvicorn
            from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
            from starlette.applications import Starlette
            from starlette.responses import JSONResponse, Response
            from starlette.routing import Route

            # Create session manager
            session_manager = StreamableHTTPSessionManager(
                app=self.server,
                json_response=True,
                stateless=True,
                security_settings=create_transport_security(host),
            )
            
            self.logger.info(f"StreamableHTTP session manager created, will start at http://{host}:{port}")
            
            # Health check endpoint
            async def health_check(request):
                return JSONResponse({"status": "healthy", "service": "doris-mcp-server"})
            
            # OAuth endpoints
            from .auth.oauth_handlers import OAuthHandlers
            oauth_handlers = OAuthHandlers(self.security_manager)
            
            async def oauth_login(request):
                return await oauth_handlers.handle_login(request)
            
            async def oauth_callback(request):
                return await oauth_handlers.handle_callback(request)
            
            async def oauth_provider_info(request):
                return await oauth_handlers.handle_provider_info(request)
                
            async def oauth_demo(request):
                return await oauth_handlers.handle_demo_page(request)
            
            # Token management endpoints
            from .auth.token_handlers import TokenHandlers
            token_handlers = TokenHandlers(self.security_manager, self.config)
            
            async def token_create(request):
                return await token_handlers.handle_create_token(request)
            
            async def token_revoke(request):
                return await token_handlers.handle_revoke_token(request)
            
            async def token_list(request):
                return await token_handlers.handle_list_tokens(request)
            
            async def token_stats(request):
                return await token_handlers.handle_token_stats(request)
            
            async def token_cleanup(request):
                return await token_handlers.handle_cleanup_tokens(request)
                
            async def token_management(request):
                return await token_handlers.handle_management_page(request)

            doris_oauth_handlers = None
            if self.security_manager.auth_provider.doris_oauth_provider:
                from .auth.doris_oauth_handlers import DorisOAuthHandlers
                doris_oauth_handlers = DorisOAuthHandlers(
                    self.security_manager.auth_provider.doris_oauth_provider
                )
            
            # Lifecycle manager - simplified since we manage session_manager externally
            @contextlib.asynccontextmanager
            async def lifespan(app: Starlette) -> AsyncIterator[None]:
                """Context manager for managing application lifecycle"""
                self.logger.info("Application started!")
                try:
                    yield
                finally:
                    self.logger.info("Application is shutting down...")
            
            effective_auth = get_effective_auth_config(self.config)
            routes = [Route("/health", health_check, methods=["GET"])]
            if effective_auth.enable_external_oauth_auth:
                routes.extend([
                    Route("/auth/login", oauth_login, methods=["GET"]),
                    Route("/auth/callback", oauth_callback, methods=["GET"]),
                    Route("/auth/provider", oauth_provider_info, methods=["GET"]),
                    Route("/auth/demo", oauth_demo, methods=["GET"]),
                ])
            if effective_auth.enable_doris_oauth_auth and doris_oauth_handlers:
                routes.extend(doris_oauth_handlers.routes())
            routes.extend([
                Route("/token/create", token_create, methods=["GET", "POST"]),
                Route("/token/revoke", token_revoke, methods=["GET", "DELETE"]),
                Route("/token/list", token_list, methods=["GET"]),
                Route("/token/stats", token_stats, methods=["GET"]),
                Route("/token/cleanup", token_cleanup, methods=["GET", "POST"]),
                Route("/token/management", token_management, methods=["GET"]),
            ])

            # Create ASGI application - use direct session manager as ASGI app
            starlette_app = Starlette(
                debug=False,
                routes=routes,
                lifespan=lifespan,
            )

            from .auth.mcp_auth_middleware import MCPAuthASGIMiddleware

            async def authenticated_mcp_downstream(scope, receive, send):
                """Handle authenticated MCP request after auth context is set."""
                await session_manager.handle_request(scope, receive, send)

            mcp_auth_middleware = MCPAuthASGIMiddleware(
                self.security_manager,
                authenticated_mcp_downstream,
                effective_auth,
            )

            # Custom ASGI app that keeps auxiliary routes outside MCP auth.
            async def mcp_app(scope, receive, send):
                # Handle lifespan events
                if scope["type"] == "lifespan":
                    await starlette_app(scope, receive, send)
                    return
                
                # Handle HTTP requests
                if scope["type"] == "http":
                    path = scope.get("path", "")
                    self.logger.info(f"Received request for path: {path}")
                    
                    try:
                        # Handle health check, auth, OAuth, and token management endpoints.
                        if effective_auth.enable_doris_oauth_auth and path.startswith("/auth/"):
                            response = JSONResponse({"error": "external_oauth_disabled"}, status_code=404)
                            await response(scope, receive, send)
                            return

                        if (path.startswith("/health") or 
                            path.startswith("/auth/") or 
                            path.startswith("/token/") or
                            path.startswith("/.well-known/") or
                            path.startswith("/oauth/") or
                            path == "/doris-login" or
                            path.startswith("/api/auth/")):
                            await starlette_app(scope, receive, send)
                            return
                        
                        if path == "/mcp":
                            self.logger.info(f"Handling MCP request for path: {path}")
                            await mcp_auth_middleware(scope, receive, send)
                            return
                        
                        # 404 for other paths
                        self.logger.info(f"Path not found: {path}")
                        response = Response("Not Found", status_code=404)
                        await response(scope, receive, send)
                    except Exception as e:
                        self.logger.error(f"Error handling request for {path}: {e}")
                        import traceback
                        self.logger.error(traceback.format_exc())
                        response = Response("Internal Server Error", status_code=500)
                        await response(scope, receive, send)
                else:
                    # For other scope types, just return
                    self.logger.warning(f"Unsupported scope type: {scope['type']}")
                    return
            
            # Choose startup method based on worker count
            if workers > 1:
                self.logger.info(f"Using multi-process mode with {workers} workers")
                self.logger.info("Note: Multi-worker mode provides full MCP functionality with independent worker processes")

                # Uvicorn workers import ``multiworker_app`` in fresh processes.
                # Persist the already-resolved parent configuration so CLI
                # overrides are not lost when each child calls ``from_env()``.
                os.environ.update(
                    _multiworker_environment(
                        self.config,
                        host=host,
                        port=port,
                        workers=workers,
                    )
                )

                # Use the dedicated multiworker app module with full MCP support
                uvicorn.run(
                    "doris_mcp_server.multiworker_app:app",
                    host=host,
                    port=port,
                    workers=workers,
                    log_level="info"
                )
                
            else:
                self.logger.info("Using single-process mode")
                # Single worker mode, use original logic with session manager lifecycle
                config = uvicorn.Config(
                    app=mcp_app,
                    host=host,
                    port=port,
                    log_level="info"
                )
                server = uvicorn.Server(config)
                
                # Run session manager and server together
                async with session_manager.run():
                    self.logger.info("Session manager started, now starting HTTP server")
                    await server.serve()

        except Exception as e:
            self.logger.error(f"Streamable HTTP server startup failed: {e}")
            import traceback
            self.logger.error("Complete error stack:")
            self.logger.error(traceback.format_exc())
            
            # If it's ExceptionGroup, try to parse
            if hasattr(e, 'exceptions'):
                self.logger.error(f"ExceptionGroup contains {len(e.exceptions)} exceptions:")
                for i, exc in enumerate(e.exceptions):
                    self.logger.error(f"  Exception {i+1}: {type(exc).__name__}: {exc}")
            raise



    async def shutdown(self):
        """Shutdown server"""
        self.logger.info("Shutting down Doris MCP Server")
        try:
            # Shutdown security manager first (includes JWT cleanup)
            await self.security_manager.shutdown()
            self.logger.info("Security manager shutdown completed")
            
            await self.connection_manager.close()
            self.logger.info("Doris MCP Server has been shut down")
        except Exception as e:
            self.logger.error(f"Error occurred while shutting down server: {e}")


def create_arg_parser():
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="Apache Doris MCP Server - Enterprise Database Service",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Transport Modes:
  stdio    - Standard input/output (for local process communication)
  http     - Streamable HTTP mode (MCP 2026-07-28 with legacy compatibility)

Examples:
  python -m doris_mcp_server --transport stdio
  python -m doris_mcp_server --transport http --host 0.0.0.0 --port 3000
  python -m doris_mcp_server --transport stdio --doris-host localhost --doris-port 9030
  python -m doris_mcp_server --transport http --doris-user admin --doris-database test_db
  
  # Backward compatibility: --db-* parameters are also supported
  python -m doris_mcp_server --transport stdio --db-host localhost --db-port 9030
        """
    )

    parser.add_argument(
        "--transport",
        type=str,
        choices=["stdio", "http"],
        default=os.getenv("TRANSPORT", _default_config.transport),
        help=f"Transport protocol type: stdio (local), http (Streamable HTTP) (default: {_default_config.transport})",
    )

    parser.add_argument(
        "--host",
        type=str,
        default=os.getenv("SERVER_HOST", _default_config.server_host),
        help=f"Host address for HTTP mode (default: {_default_config.server_host})",
    )

    parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help="Port number for HTTP mode (default: 3000)"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes for HTTP mode (default: 1, use 0 for auto-detect CPU cores)"
    )

    parser.add_argument(
        "--doris-host", "--db-host",
        type=str,
        default=os.getenv("DORIS_HOST", _default_config.database.host),
        help=f"Doris database host address (default: {_default_config.database.host})",
    )

    parser.add_argument(
        "--doris-port", "--db-port", type=int, default=9030, help="Doris database port number (default: 9030)"
    )

    parser.add_argument(
        "--doris-user", "--db-user", type=str, default=os.getenv("DORIS_USER", _default_config.database.user), help=f"Doris database username (default: {_default_config.database.user})"
    )

    parser.add_argument("--doris-password", "--db-password", type=str, default=os.getenv("DORIS_PASSWORD", ""), help="Doris database password")

    parser.add_argument(
        "--doris-database", "--db-database",
        type=str,
        default=os.getenv("DORIS_DATABASE", _default_config.database.database),
        help=f"Doris database name (default: {_default_config.database.database})",
    )

    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=os.getenv("LOG_LEVEL", _default_config.logging.level),
        help=f"Log level (default: {_default_config.logging.level})",
    )

    return parser


def update_configuration(config: DorisConfig):
    """Update doris configuration object"""
    # For some arguments, if not specified, environment variables or default configurations will be used as default values
    parser = create_arg_parser()
    args = parser.parse_args()
    argv = sys.argv[1:]

    def cli_has(*options: str) -> bool:
        return any(arg == option or arg.startswith(f"{option}=") for arg in argv for option in options)

    # Update config values
    # Command line arguments override configuration (if provided)
    # basic
    if cli_has("--transport"):
        config.transport = args.transport
        _mark_source(config, "transport", "cli")
    if cli_has("--host"):
        config.server_host = args.host
    if cli_has("--port"):
        config.server_port = args.port
    server_name = os.getenv("SERVER_NAME")
    if server_name:
        config.server_name = server_name
    server_version = os.getenv("SERVER_VERSION")
    if server_version:
        config.server_version = server_version
 
    # database
    if cli_has("--doris-host", "--db-host"):
        config.database.host = args.doris_host
    if cli_has("--doris-port", "--db-port"):
        config.database.port = args.doris_port
    if cli_has("--doris-user", "--db-user"):
        config.database.user = args.doris_user
    if cli_has("--doris-password", "--db-password"):
        config.database.password = args.doris_password
    if cli_has("--doris-database", "--db-name"):
        config.database.database = args.doris_database

    # logging
    if cli_has("--log-level"):
        config.logging.level = args.log_level
    
    # workers (add to config for HTTP mode)
    if hasattr(args, 'workers') and cli_has("--workers"):
        config.workers = args.workers
        _mark_source(config, "workers", "cli")


async def main():
    """Main function"""
    # Create configuration - priority: command line arguments > env variables > .env file > default values
    # First load from .env file and environment variables
    config = DorisConfig.from_env()
 
    # Then parse the command line arguments, and update the config object.
    update_configuration(config)

    # Initialize enhanced logging system
    from .utils.config import ConfigManager
    config_manager = ConfigManager(config)
    config_manager.setup_logging()
    
    # Get logger with proper configuration
    from .utils.logger import get_logger, log_system_info
    logger = get_logger(__name__)
    
    # Log system information for debugging
    log_system_info()
    
    logger.info("Starting Doris MCP Server...")
    logger.info(f"Transport: {config.transport}")
    logger.info(f"Log Level: {config.logging.level}")

    try:
        effective_auth = normalize_effective_auth_config(
            config, requested_workers=getattr(config, "workers", 1)
        )
    except Exception as auth_config_error:
        logger.error(f"Invalid authentication configuration: {auth_config_error}")
        return 1

    if effective_auth.auth_config_warnings:
        for warning in effective_auth.auth_config_warnings:
            logger.warning(warning)
    config.workers = effective_auth.effective_workers

    # Create server instance
    server = DorisServer(config)

    try:
        if config.transport == "stdio":
            await server.start_stdio()
        elif config.transport == "http":
            workers = getattr(config, 'workers', effective_auth.effective_workers)
            await server.start_http(config.server_host, config.server_port, workers)
        else:
            logger.error(f"Unsupported transport protocol: {config.transport}")
            await server.shutdown()
            return 1

    except KeyboardInterrupt:
        logger.info("Received interrupt signal, shutting down server...")
    except Exception as e:
        logger.error(f"Server runtime error: {e}")
        # Clean up resources even in case of exception
        try:
            await server.shutdown()
        except Exception as shutdown_error:
            logger.error(f"Error occurred while shutting down server: {shutdown_error}")
        return 1
    finally:
        # Cleanup in case of normal shutdown
        try:
            await server.shutdown()
        except Exception as shutdown_error:
            logger.error(f"Error occurred while shutting down server: {shutdown_error}")
        
        # Shutdown logging system
        from .utils.logger import shutdown_logging
        shutdown_logging()

    return 0


def main_sync():
    """Synchronous main function for entry point"""
    exit_code = asyncio.run(main())
    exit(exit_code)


if __name__ == "__main__":
    main_sync()

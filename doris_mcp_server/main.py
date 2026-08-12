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

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys

from starlette.requests import Request
from starlette.responses import Response
from starlette.types import Receive, Scope, Send

from ._version import __version__
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
from .tools.tools_manager import DorisToolsManager
from .utils.config import (
    DorisConfig,
    _mark_source,
    get_effective_auth_config,
    normalize_effective_auth_config,
    validate_http_bind_auth_policy,
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
    environment = {
        "DORIS_HOST": config.database.host,
        "DORIS_HOSTS": ",".join(config.database.hosts),
        "DORIS_PORT": str(config.database.port),
        "DORIS_USER": config.database.user,
        "DORIS_PASSWORD": config.database.password,
        "DORIS_DATABASE": config.database.database,
        "DORIS_FE_HTTP_HOST": config.database.fe_http_host,
        "DORIS_FE_HTTP_HOSTS": ",".join(config.database.fe_http_hosts),
        "DORIS_FE_HTTP_PORT": str(config.database.fe_http_port),
        "DORIS_BE_HOSTS": ",".join(config.database.be_hosts),
        "DORIS_BE_WEBSERVER_PORT": str(config.database.be_webserver_port),
        "SERVER_HOST": host,
        "SERVER_PORT": str(port),
        "MCP_ALLOWED_HOSTS": ",".join(config.mcp_allowed_hosts),
        "MCP_ALLOWED_ORIGINS": ",".join(config.mcp_allowed_origins),
        "ENABLE_LEGACY_HTTP_ADAPTER": str(
            config.enable_legacy_http_adapter
        ).lower(),
        "MCP_LIST_PAGE_SIZE": str(config.mcp_list_page_size),
        "MCP_TOOL_PROVIDERS": ",".join(config.mcp_tool_providers),
        "MCP_TOOL_EXPOSURE_MODE": config.tool_exposure.mode,
        "MCP_ADMIN_DOMAIN_ENABLED": str(
            config.administration.enabled
        ).lower(),
        "MCP_ADMIN_REQUIRE_CONFIRMATION": str(
            config.administration.require_confirmation
        ).lower(),
        "CAPABILITY_SNAPSHOT_TTL_SECONDS": str(
            config.capability.snapshot_ttl_seconds
        ),
        "CAPABILITY_PROBE_TIMEOUT_SECONDS": str(
            config.capability.probe_timeout_seconds
        ),
        "CAPABILITY_STALE_GRACE_SECONDS": str(
            config.capability.stale_grace_seconds
        ),
        "CAPABILITY_VERSION_BRAND_ALIASES": ",".join(
            config.capability.version_brand_aliases
        ),
        "GOVERNANCE_MAX_SAMPLE_RATIO": str(
            config.governance.max_sample_ratio
        ),
        "GOVERNANCE_MAX_AUDIT_WINDOW_DAYS": str(
            config.governance.max_audit_window_days
        ),
        "GOVERNANCE_MAX_LINEAGE_EDGES": str(
            config.governance.max_lineage_edges
        ),
        "GOVERNANCE_LINEAGE_STORE_TABLE": (
            config.governance.lineage_store_table
        ),
        "GOVERNANCE_LINEAGE_RECENT_EVENT_MINUTES": str(
            config.governance.lineage_recent_event_minutes
        ),
        "LAKEHOUSE_MAX_CATALOG_OBJECTS": str(
            config.lakehouse.max_catalog_objects
        ),
        "LAKEHOUSE_MAX_CATALOG_DATABASES": str(
            config.lakehouse.max_catalog_databases
        ),
        "LAKEHOUSE_MAX_SNAPSHOTS": str(
            config.lakehouse.max_snapshots
        ),
        "LAKEHOUSE_MAX_PARTITIONS": str(
            config.lakehouse.max_partitions
        ),
        "LAKEHOUSE_MAX_VARIANT_SAMPLE_ROWS": str(
            config.lakehouse.max_variant_sample_rows
        ),
        "LAKEHOUSE_MAX_VARIANT_PATHS": str(
            config.lakehouse.max_variant_paths
        ),
        "OSSIE_ENABLED": str(config.semantic.enabled).lower(),
        "OSSIE_MODEL_DIRECTORY": config.semantic.model_directory,
        "OSSIE_BINDING_MANIFEST": config.semantic.binding_manifest,
        "OSSIE_MAX_FILE_BYTES": str(config.semantic.max_file_bytes),
        "OSSIE_MAX_TOTAL_BYTES": str(config.semantic.max_total_bytes),
        "OSSIE_MAX_MODELS": str(config.semantic.max_models),
        "OSSIE_MAX_DEPTH": str(config.semantic.max_depth),
        "OSSIE_MAX_ALIASES": str(config.semantic.max_aliases),
        "OSSIE_MAX_STRING_BYTES": str(config.semantic.max_string_bytes),
        "OSSIE_MAX_EXPRESSION_BYTES": str(
            config.semantic.max_expression_bytes
        ),
        "OSSIE_CONTEXT_MAX_BYTES": str(config.semantic.context_max_bytes),
        "OSSIE_CONTEXT_HARD_MAX_BYTES": str(
            config.semantic.context_hard_max_bytes
        ),
        "DORIS_OAUTH_SEMANTIC_TOOLS_ENABLED": str(
            config.semantic.oauth_tools_enabled
        ).lower(),
        "DORIS_OAUTH_SEMANTIC_RESOURCES_ENABLED": str(
            config.semantic.oauth_resources_enabled
        ).lower(),
        "METRICFLOW_ENABLED": str(config.semantic.metricflow_enabled).lower(),
        "METRICFLOW_PROJECT_DIRECTORY": (
            config.semantic.metricflow_project_directory
        ),
        "METRICFLOW_TIMEOUT_SECONDS": str(
            config.semantic.metricflow_timeout_seconds
        ),
        "METRICFLOW_MAX_OUTPUT_BYTES": str(
            config.semantic.metricflow_max_output_bytes
        ),
        "MCP_STATE_HANDLE_SECRET": config.mcp_state_handle_secret,
        "MCP_STATE_HANDLE_TTL_SECONDS": str(config.mcp_state_handle_ttl_seconds),
        "SERVER_NAME": config.server_name,
        "TRANSPORT": "http",
        "WORKERS": str(workers),
        "ALLOW_UNAUTHENTICATED_NON_LOOPBACK": str(
            config.security.allow_unauthenticated_non_loopback
        ).lower(),
    }
    if config.semantic.metricflow_provider_command:
        environment["METRICFLOW_PROVIDER_COMMAND_JSON"] = json.dumps(
            config.semantic.metricflow_provider_command
        )
    return environment


class DorisServer:
    """Apache Doris MCP Server main class"""

    def __init__(self, config: DorisConfig):
        self.config = config

        # Initialize security manager (without connection_manager initially)
        self.security_manager = DorisSecurityManager(config)

        # Initialize connection manager, pass in security manager and token manager for token-bound DB config
        token_manager = (
            self.security_manager.auth_provider.token_manager
            if hasattr(self.security_manager, "auth_provider")
            and hasattr(self.security_manager.auth_provider, "token_manager")
            else None
        )
        self.connection_manager = DorisConnectionManager(
            config, self.security_manager, token_manager
        )

        # Set connection manager reference in security manager for database validation
        self.security_manager.connection_manager = self.connection_manager
        self.security_manager.auth_provider.configure_doris_oauth(
            self.connection_manager
        )

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
            list_page_size=config.mcp_list_page_size,
            state_handle_secret=config.mcp_state_handle_secret,
            state_handle_ttl_seconds=config.mcp_state_handle_ttl_seconds,
        )

    async def start_stdio(self) -> None:
        """Start stdio transport mode"""
        self.logger.info("Starting Doris MCP Server (stdio mode)")

        try:
            # Initialize security manager first (includes JWT setup if enabled)
            await self.security_manager.initialize()
            self.logger.info("Security manager initialization completed")

            # For stdio mode, we must establish a working database connection
            # Use the dedicated stdio mode initialization method
            await self.connection_manager.initialize_for_stdio_mode()
            await self.tools_manager.start()

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
                if hasattr(inner_e, "exceptions"):
                    self.logger.error(
                        f"ExceptionGroup contains {len(inner_e.exceptions)} exceptions:"
                    )
                    for i, exc in enumerate(inner_e.exceptions):
                        self.logger.error(
                            f"  Exception {i + 1}: {type(exc).__name__}: {exc}"
                        )

                raise inner_e

        except Exception as e:
            self.logger.error(f"stdio server startup failed: {e}")
            self.logger.error(f"Error type: {type(e)}")
            raise

    async def start_http(
        self,
        host: str = os.getenv("SERVER_HOST", _default_config.server_host),
        port: int = int(os.getenv("SERVER_PORT", str(_default_config.server_port))),
        workers: int = 1,
    ) -> None:
        """Start Streamable HTTP transport mode with workers support"""
        effective_auth = get_effective_auth_config(self.config)
        bind_warning = validate_http_bind_auth_policy(
            transport="http",
            host=host,
            auth_methods=effective_auth.auth_methods,
            allow_unauthenticated_non_loopback=(
                self.config.security.allow_unauthenticated_non_loopback
            ),
        )
        if bind_warning and bind_warning not in effective_auth.auth_config_warnings:
            self.logger.warning(bind_warning)
        self.logger.info(
            f"Starting Doris MCP Server (Streamable HTTP mode) - {host}:{port}, workers: {workers}"
        )

        try:
            # Initialize security manager first (includes JWT setup if enabled)
            await self.security_manager.initialize()
            self.logger.info("Security manager initialization completed")

            # For HTTP mode, try to initialize global connection pool with graceful degradation
            global_pool_created = (
                await self.connection_manager.initialize_for_http_mode()
            )
            if global_pool_created:
                self.logger.info(
                    "Global database connection pool available for HTTP mode"
                )
            else:
                effective_auth = get_effective_auth_config(self.config)
                if effective_auth.enable_doris_oauth_auth:
                    raise RuntimeError(
                        "Doris OAuth requires the configured service/global Doris account "
                        "to initialize successfully in Phase 3"
                    )
                self.logger.info(
                    "HTTP mode running without global database pool, will use token-bound configurations"
                )
            await self.tools_manager.start()

            # Use the SDK v2 dual-era Streamable HTTP manager.
            import contextlib
            from collections.abc import AsyncIterator

            import uvicorn
            from starlette.applications import Starlette
            from starlette.responses import JSONResponse
            from starlette.routing import Route

            # Create the exact modern/legacy HTTP boundary.
            http_transport = DorisMCPHTTPTransport(
                app=self.server,
                security_settings=create_transport_security(
                    host,
                    allowed_hosts=self.config.mcp_allowed_hosts,
                    allowed_origins=self.config.mcp_allowed_origins,
                ),
                legacy_adapter_enabled=self.config.enable_legacy_http_adapter,
            )

            self.logger.info(
                "Streamable HTTP transport created at "
                f"http://{host}:{port}{MODERN_MCP_PATH}; legacy adapter "
                f"{'enabled' if self.config.enable_legacy_http_adapter else 'disabled'}"
            )

            # Health check endpoint
            async def health_check(request: Request) -> Response:
                return JSONResponse(
                    liveness_payload(
                        service=self.config.server_name,
                        version=__version__,
                        legacy=True,
                    )
                )

            async def live_check(request: Request) -> Response:
                return JSONResponse(
                    liveness_payload(
                        service=self.config.server_name,
                        version=__version__,
                    )
                )

            async def readiness_check(request: Request) -> Response:
                payload, status_code = await readiness_payload(
                    self.connection_manager,
                    service=self.config.server_name,
                    version=__version__,
                )
                return JSONResponse(payload, status_code=status_code)

            # OAuth endpoints
            from .auth.oauth_handlers import OAuthHandlers

            oauth_handlers = OAuthHandlers(self.security_manager)

            async def oauth_login(request: Request) -> Response:
                return await oauth_handlers.handle_login(request)

            async def oauth_callback(request: Request) -> Response:
                return await oauth_handlers.handle_callback(request)

            async def oauth_provider_info(request: Request) -> Response:
                return await oauth_handlers.handle_provider_info(request)

            async def oauth_protected_resource_metadata(
                request: Request,
            ) -> Response:
                return await oauth_handlers.handle_protected_resource_metadata(request)

            async def oauth_demo(request: Request) -> Response:
                return await oauth_handlers.handle_demo_page(request)

            # Token management endpoints
            from .auth.token_handlers import TokenHandlers

            token_handlers = TokenHandlers(self.security_manager, self.config)

            async def token_create(request: Request) -> Response:
                return await token_handlers.handle_create_token(request)

            async def token_revoke(request: Request) -> Response:
                return await token_handlers.handle_revoke_token(request)

            async def token_list(request: Request) -> Response:
                return await token_handlers.handle_list_tokens(request)

            async def token_stats(request: Request) -> Response:
                return await token_handlers.handle_token_stats(request)

            async def token_cleanup(request: Request) -> Response:
                return await token_handlers.handle_cleanup_tokens(request)

            async def token_management(request: Request) -> Response:
                return await token_handlers.handle_management_page(request)

            doris_oauth_handlers = None
            if self.security_manager.auth_provider.doris_oauth_provider:
                from .auth.doris_oauth_handlers import DorisOAuthHandlers

                doris_oauth_handlers = DorisOAuthHandlers(
                    self.security_manager.auth_provider.doris_oauth_provider
                )

            # Lifecycle manager - the MCP transport lifespan is managed externally.
            @contextlib.asynccontextmanager
            async def lifespan(app: Starlette) -> AsyncIterator[None]:
                """Context manager for managing application lifecycle"""
                self.logger.info("Application started!")
                try:
                    yield
                finally:
                    self.logger.info("Application is shutting down...")

            effective_auth = get_effective_auth_config(self.config)
            routes = [
                Route("/health", health_check, methods=["GET"]),
                Route("/live", live_check, methods=["GET"]),
                Route("/ready", readiness_check, methods=["GET"]),
            ]
            if effective_auth.enable_external_oauth_auth:
                routes.extend(
                    [
                        Route(
                            "/.well-known/oauth-protected-resource",
                            oauth_protected_resource_metadata,
                            methods=["GET"],
                        ),
                        Route("/auth/login", oauth_login, methods=["GET"]),
                        Route("/auth/callback", oauth_callback, methods=["GET"]),
                        Route("/auth/provider", oauth_provider_info, methods=["GET"]),
                        Route("/auth/demo", oauth_demo, methods=["GET"]),
                    ]
                )
            if effective_auth.enable_doris_oauth_auth and doris_oauth_handlers:
                routes.extend(doris_oauth_handlers.routes())
            routes.extend(
                [
                    Route("/token/create", token_create, methods=["GET", "POST"]),
                    Route("/token/revoke", token_revoke, methods=["GET", "DELETE"]),
                    Route("/token/list", token_list, methods=["GET"]),
                    Route("/token/stats", token_stats, methods=["GET"]),
                    Route("/token/cleanup", token_cleanup, methods=["GET", "POST"]),
                    Route("/token/management", token_management, methods=["GET"]),
                ]
            )

            # Create the auxiliary ASGI application; MCP routing stays separate.
            starlette_app = Starlette(
                debug=False,
                routes=routes,
                lifespan=lifespan,
            )
            auxiliary_app = protect_auxiliary_http_app(starlette_app)

            from .auth.mcp_auth_middleware import MCPAuthASGIMiddleware

            async def authenticated_mcp_downstream(
                scope: Scope,
                receive: Receive,
                send: Send,
            ) -> None:
                """Handle authenticated MCP request after auth context is set."""
                await http_transport.handle_request(scope, receive, send)

            mcp_auth_middleware = MCPAuthASGIMiddleware(
                self.security_manager,
                authenticated_mcp_downstream,
                effective_auth,
            )

            # Custom ASGI app that keeps auxiliary routes outside MCP auth.
            async def mcp_app(
                scope: Scope,
                receive: Receive,
                send: Send,
            ) -> None:
                # Handle lifespan events
                if scope["type"] == "lifespan":
                    await auxiliary_app(scope, receive, send)
                    return

                # Handle HTTP requests
                if scope["type"] == "http":
                    path = scope.get("path", "")
                    self.logger.info(f"Received request for path: {path}")

                    try:
                        # Handle health check, auth, OAuth, and token management endpoints.
                        if effective_auth.enable_doris_oauth_auth and path.startswith(
                            "/auth/"
                        ):
                            response: Response = JSONResponse(
                                {"error": "external_oauth_disabled"},
                                status_code=404,
                            )
                            await response(scope, receive, send)
                            return

                        if (
                            path.rstrip("/") in {"/health", "/live", "/ready"}
                            or path.startswith("/auth/")
                            or path.startswith("/token/")
                            or path.startswith("/.well-known/")
                            or path.startswith("/oauth/")
                            or path == "/doris-login"
                            or path.startswith("/api/auth/")
                        ):
                            await auxiliary_app(scope, receive, send)
                            return

                        if path == MODERN_MCP_PATH or (
                            path == LEGACY_MCP_PATH
                            and self.config.enable_legacy_http_adapter
                        ):
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
                self.logger.info(
                    "Note: Multi-worker mode provides full MCP functionality with independent worker processes"
                )

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
                    log_level="info",
                )

            else:
                self.logger.info("Using single-process mode")
                # Single worker mode, use the shared MCP transport lifecycle.
                config = uvicorn.Config(
                    app=mcp_app, host=host, port=port, log_level="info"
                )
                server = uvicorn.Server(config)

                # Run MCP transport and server together.
                async with http_transport.run():
                    self.logger.info(
                        "MCP HTTP transport started, now starting HTTP server"
                    )
                    await server.serve()

        except Exception as e:
            self.logger.error(f"Streamable HTTP server startup failed: {e}")
            import traceback

            self.logger.error("Complete error stack:")
            self.logger.error(traceback.format_exc())

            # If it's ExceptionGroup, try to parse
            if hasattr(e, "exceptions"):
                self.logger.error(
                    f"ExceptionGroup contains {len(e.exceptions)} exceptions:"
                )
                for i, exc in enumerate(e.exceptions):
                    self.logger.error(
                        f"  Exception {i + 1}: {type(exc).__name__}: {exc}"
                    )
            raise

    async def shutdown(self) -> None:
        """Shutdown server"""
        self.logger.info("Shutting down Doris MCP Server")
        try:
            await self.tools_manager.close()

            # Shutdown security manager first (includes JWT cleanup)
            await self.security_manager.shutdown()
            self.logger.info("Security manager shutdown completed")

            await self.connection_manager.close()
            self.logger.info("Doris MCP Server has been shut down")
        except Exception as e:
            self.logger.error(f"Error occurred while shutting down server: {e}")


def create_arg_parser() -> argparse.ArgumentParser:
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
  python -m doris_mcp_server --transport http --host 127.0.0.1 --port 3000
  python -m doris_mcp_server --transport stdio --doris-host localhost --doris-port 9030
  python -m doris_mcp_server --transport http --doris-user admin --doris-database test_db

  # Backward compatibility: --db-* parameters are also supported
  python -m doris_mcp_server --transport stdio --db-host localhost --db-port 9030
        """,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
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
        help="Port number for HTTP mode (default: 3000)",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes for HTTP mode (default: 1, use 0 for auto-detect CPU cores)",
    )

    parser.add_argument(
        "--doris-host",
        "--db-host",
        type=str,
        default=os.getenv("DORIS_HOST", _default_config.database.host),
        help=f"Doris database host address (default: {_default_config.database.host})",
    )

    parser.add_argument(
        "--doris-port",
        "--db-port",
        type=int,
        default=9030,
        help="Doris database port number (default: 9030)",
    )

    parser.add_argument(
        "--doris-user",
        "--db-user",
        type=str,
        default=os.getenv("DORIS_USER", _default_config.database.user),
        help=f"Doris database username (default: {_default_config.database.user})",
    )

    parser.add_argument(
        "--doris-password",
        "--db-password",
        type=str,
        default=os.getenv("DORIS_PASSWORD", ""),
        help="Doris database password",
    )

    parser.add_argument(
        "--doris-database",
        "--db-database",
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


def update_configuration(config: DorisConfig) -> None:
    """Update doris configuration object"""
    # For some arguments, if not specified, environment variables or default configurations will be used as default values
    parser = create_arg_parser()
    args = parser.parse_args()
    argv = sys.argv[1:]

    def cli_has(*options: str) -> bool:
        return any(
            arg == option or arg.startswith(f"{option}=")
            for arg in argv
            for option in options
        )

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
    if hasattr(args, "workers") and cli_has("--workers"):
        config.workers = args.workers
        _mark_source(config, "workers", "cli")


async def main() -> int:
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
            workers = getattr(config, "workers", effective_auth.effective_workers)
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


def main_sync() -> None:
    """Synchronous main function for entry point"""
    exit_code = asyncio.run(main())
    exit(exit_code)


if __name__ == "__main__":
    main_sync()

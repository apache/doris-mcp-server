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
import json
import logging
from typing import Any

# MCP version compatibility handling
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
        logger.info(f"MCP components imported successfully, version: {MCP_VERSION}")
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
                
                logger.info("MCP 1.9.x compatibility workaround successful!")
                
                # Restore original typing function if we patched it
                if original_check_generic:
                    typing._check_generic = original_check_generic
                
                return True
                
            except Exception as workaround_error:
                logger.error(f"MCP compatibility workaround failed: {workaround_error}")
                
                # Restore original typing function if we patched it
                if original_check_generic:
                    try:
                        import typing
                        typing._check_generic = original_check_generic
                    except Exception:
                        pass
        
        logger.error(f"Failed to import MCP components: {import_error}")
        return False

# Perform MCP import with compatibility handling
if not _import_mcp_with_compatibility():
    raise ImportError(
        "Failed to import MCP components. Please ensure MCP is properly installed. "
        "Supported versions: 1.8.x, 1.9.x"
    )

from .tools.tools_manager import DorisToolsManager
from .tools.prompts_manager import DorisPromptsManager
from .tools.resources_manager import DorisResourcesManager
from .utils.config import DorisConfig
from .utils.db import DorisConnectionManager
from .utils.security import DorisSecurityManager
import os

# Configure logging - will be properly initialized later
logger = logging.getLogger(__name__)

# Create a default config instance for getting default values
_default_config = DorisConfig()




class DorisServer:
    """Apache Doris MCP Server main class"""

    def __init__(self, config: DorisConfig):
        self.config = config
        self.server = Server("doris-mcp-server")

        # Initialize security manager
        self.security_manager = DorisSecurityManager(config)

        # Initialize connection manager, pass in security manager
        self.connection_manager = DorisConnectionManager(config, self.security_manager)

        # Initialize independent managers
        self.resources_manager = DorisResourcesManager(self.connection_manager)
        self.tools_manager = DorisToolsManager(self.connection_manager)
        self.prompts_manager = DorisPromptsManager(self.connection_manager)

        # Import here to avoid circular imports
        from .utils.logger import get_logger
        self.logger = get_logger(f"{__name__}.DorisServer")
        self._setup_handlers()

    def _get_mcp_capabilities(self):
        """Get MCP capabilities with version compatibility"""
        try:
            # For MCP 1.9.x and newer
            from mcp.server.lowlevel.server import NotificationOptions
            
            return self.server.get_capabilities(
                notification_options=NotificationOptions(
                    prompts_changed=True,
                    resources_changed=True,
                    tools_changed=True
                ),
                experimental_capabilities={}
            )
        except TypeError:
            try:
                # For MCP 1.8.x
                from mcp.server.lowlevel.server import NotificationOptions
                
                return self.server.get_capabilities(
                    notification_options=NotificationOptions(
                        prompts_changed=True,
                        resources_changed=True,
                        tools_changed=True
                    ),
                    experimental_capabilities={}
                )
            except Exception as e:
                self.logger.warning(f"Could not get capabilities with NotificationOptions: {e}")
                # Fallback for older versions
                try:
                    return self.server.get_capabilities()
                except Exception as fallback_e:
                    self.logger.error(f"Failed to get capabilities: {fallback_e}")
                    # Return minimal capabilities
                    return {
                        "resources": {},
                        "tools": {},
                        "prompts": {}
                    }

    def _setup_handlers(self):
        """Setup MCP protocol handlers"""

        @self.server.list_resources()
        async def handle_list_resources() -> list[Resource]:
            """Handle resource list request"""
            try:
                self.logger.info("Handling resource list request")
                resources = await self.resources_manager.list_resources()
                self.logger.info(f"Returning {len(resources)} resources")
                return resources
            except Exception as e:
                self.logger.error(f"Failed to handle resource list request: {e}")
                return []

        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Handle resource read request"""
            try:
                self.logger.info(f"Handling resource read request: {uri}")
                content = await self.resources_manager.read_resource(uri)
                return content
            except Exception as e:
                self.logger.error(f"Failed to handle resource read request: {e}")
                return json.dumps(
                    {"error": f"Failed to read resource: {str(e)}", "uri": uri},
                    ensure_ascii=False,
                    indent=2,
                )

        @self.server.list_tools()
        async def handle_list_tools() -> list[Tool]:
            """Handle tool list request"""
            try:
                self.logger.info("Handling tool list request")
                tools = await self.tools_manager.list_tools()
                self.logger.info(f"Returning {len(tools)} tools")
                return tools
            except Exception as e:
                self.logger.error(f"Failed to handle tool list request: {e}")
                return []

        @self.server.call_tool()
        async def handle_call_tool(
            name: str, arguments: dict[str, Any]
        ) -> list[TextContent]:
            """Handle tool call request"""
            try:
                self.logger.info(f"Handling tool call request: {name}")
                result = await self.tools_manager.call_tool(name, arguments)

                return [TextContent(type="text", text=result)]
            except Exception as e:
                self.logger.error(f"Failed to handle tool call request: {e}")
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

        @self.server.list_prompts()
        async def handle_list_prompts() -> list[Prompt]:
            """Handle prompt list request"""
            try:
                self.logger.info("Handling prompt list request")
                prompts = await self.prompts_manager.list_prompts()
                self.logger.info(f"Returning {len(prompts)} prompts")
                return prompts
            except Exception as e:
                self.logger.error(f"Failed to handle prompt list request: {e}")
                return []

        @self.server.get_prompt()
        async def handle_get_prompt(name: str, arguments: dict[str, Any]) -> str:
            """Handle prompt get request"""
            try:
                self.logger.info(f"Handling prompt get request: {name}")
                result = await self.prompts_manager.get_prompt(name, arguments)
                return result
            except Exception as e:
                self.logger.error(f"Failed to handle prompt get request: {e}")
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

    async def start_stdio(self):
        """Start stdio transport mode"""
        self.logger.info("Starting Doris MCP Server (stdio mode)")

        try:
            # Ensure connection manager is initialized
            await self.connection_manager.initialize()
            self.logger.info("Connection manager initialization completed")

            # Start stdio server - using compatible import approach
            try:
                from mcp.server.stdio import stdio_server
            except ImportError:
                # Fallback for different MCP versions
                try:
                    from mcp.server import stdio_server
                except ImportError as stdio_import_error:
                    self.logger.error(f"Failed to import stdio_server: {stdio_import_error}")
                    raise RuntimeError("stdio_server module not available in this MCP version")
            
            self.logger.info("Creating stdio_server transport...")
            
            # Try different startup approaches
            try:
                async with stdio_server() as streams:
                    read_stream, write_stream = streams
                    self.logger.info("stdio_server streams created successfully")
                    
                    # Create initialization options with version compatibility
                    capabilities = self._get_mcp_capabilities()
                    
                    init_options = InitializationOptions(
                        server_name="doris-mcp-server",
                        server_version=os.getenv("SERVER_VERSION", _default_config.server_version),
                        capabilities=capabilities,
                    )
                    self.logger.info("Initialization options created successfully")
                    
                    # Run server
                    self.logger.info("Starting to run MCP server...")
                    await self.server.run(read_stream, write_stream, init_options)
                    
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
            # Ensure connection manager is initialized
            await self.connection_manager.initialize()

            # Use Starlette and StreamableHTTPSessionManager according to official example
            import uvicorn
            import contextlib
            from collections.abc import AsyncIterator
            from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
            from starlette.applications import Starlette
            from starlette.routing import Route
            from starlette.responses import JSONResponse, Response
            from starlette.types import Scope
            
            # Create session manager
            session_manager = StreamableHTTPSessionManager(
                app=self.server,
                json_response=True,  # Enable JSON response
                stateless=False  # Maintain session state
            )
            
            self.logger.info(f"StreamableHTTP session manager created, will start at http://{host}:{port}")
            
            # Health check endpoint
            async def health_check(request):
                return JSONResponse({"status": "healthy", "service": "doris-mcp-server"})
            
            # Lifecycle manager - simplified since we manage session_manager externally
            @contextlib.asynccontextmanager
            async def lifespan(app: Starlette) -> AsyncIterator[None]:
                """Context manager for managing application lifecycle"""
                self.logger.info("Application started!")
                try:
                    yield
                finally:
                    self.logger.info("Application is shutting down...")
            
            # Create ASGI application - use direct session manager as ASGI app
            starlette_app = Starlette(
                debug=True,
                routes=[
                    Route("/health", health_check, methods=["GET"]),
                ],
                lifespan=lifespan,
            )
            
            # Custom ASGI app that handles both /mcp and /mcp/ without redirects
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
                        # Handle health check
                        if path.startswith("/health"):
                            await starlette_app(scope, receive, send)
                            return
                        
                        # Handle MCP requests - both /mcp and /mcp/ go to session manager
                        if path == "/mcp" or path.startswith("/mcp/"):
                            self.logger.info(f"Handling MCP request for path: {path}")
                            # Log request details for debugging
                            method = scope.get("method", "UNKNOWN")
                            headers = dict(scope.get("headers", []))
                            self.logger.info(f"MCP Request - Method: {method}")
                            self.logger.info(f"MCP Request - Headers: {headers}")
                            
                            # Handle Dify compatibility for GET requests
                            if method == "GET":
                                accept_header = headers.get(b'accept', b'').decode('utf-8')
                                user_agent = headers.get(b'user-agent', b'').decode('utf-8')
                                

                                
                                # For other GET requests, try to add application/json to Accept header
                                if 'text/event-stream' in accept_header and 'application/json' not in accept_header:
                                    self.logger.info("Adding application/json to Accept header for GET request")
                                    # Modify headers to include both content types
                                    new_headers = []
                                    for name, value in scope.get("headers", []):
                                        if name == b'accept':
                                            # Add application/json to the accept header
                                            new_value = value.decode('utf-8') + ', application/json'
                                            new_headers.append((name, new_value.encode('utf-8')))
                                        else:
                                            new_headers.append((name, value))
                                    # Update scope with modified headers
                                    scope = dict(scope)
                                    scope["headers"] = new_headers
                                    self.logger.info(f"Modified Accept header to: {new_value}")
                            
                            await session_manager.handle_request(scope, receive, send)
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
  http     - Streamable HTTP mode (MCP 2025-03-26 protocol)

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
        default=os.getenv("SERVER_PORT", _default_config.server_port),
        help=f"Port number for HTTP mode (default: {_default_config.server_port})"
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("WORKERS", "1")),
        help="Number of worker processes for HTTP mode (default: 1, use 0 for auto-detect CPU cores)"
    )

    parser.add_argument(
        "--doris-host", "--db-host",
        type=str,
        default=os.getenv("DORIS_HOST", _default_config.database.host),
        help=f"Doris database host address (default: {_default_config.database.host})",
    )

    parser.add_argument(
        "--doris-port", "--db-port", type=int, default=os.getenv("DORIS_PORT", _default_config.database.port), help=f"Doris database port number (default: {_default_config.database.port})"
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

    # Update config values
    # Command line arguments override configuration (if provided)
    # basic
    if args.transport != _default_config.transport:
        config.transport = args.transport
    if args.host != _default_config.server_host:
        config.server_host = args.host
    if args.port != _default_config.server_port:
        config.server_port = args.port
    server_name = os.getenv("SERVER_NAME")
    if server_name:
        config.server_name = server_name
    server_version = os.getenv("SERVER_VERSION")
    if server_version:
        config.server_version = server_version
 
    # database
    if args.doris_host != _default_config.database.host:  # If not default value, use command line argument
        config.database.host = args.doris_host
    if args.doris_port != _default_config.database.port:
        config.database.port = args.doris_port
    if args.doris_user != _default_config.database.user:
        config.database.user = args.doris_user
    if args.doris_password:  # Use password if provided
        config.database.password = args.doris_password
    if args.doris_database != _default_config.database.database:
        config.database.database = args.doris_database

    # logging
    if args.log_level != _default_config.logging.level:
        config.logging.level = args.log_level
    
    # workers (add to config for HTTP mode)
    if hasattr(args, 'workers'):
        config.workers = args.workers


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

    # Create server instance
    server = DorisServer(config)

    try:
        if config.transport == "stdio":
            await server.start_stdio()
        elif config.transport == "http":
            # Get workers configuration with auto-detection support
            workers = getattr(config, 'workers', 1)
            if workers == 0:
                import multiprocessing
                workers = multiprocessing.cpu_count()
                logger.info(f"Auto-detected {workers} CPU cores for worker processes")
            
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

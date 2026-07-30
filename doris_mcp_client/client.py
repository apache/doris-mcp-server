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
Unified Doris MCP Client - Supports both stdio and Streamable HTTP modes

Combines the correct HTTP implementation from http_client.py and the complete architecture from client.py
Provides complete support for the three major primitives: Resources, Tools, and Prompts
"""

import argparse
import asyncio
import json
import logging
from collections.abc import Callable
from typing import Any

from mcp import Client as MCPClient
from mcp import StdioServerParameters
from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client
from mcp.types import (
    Prompt,
    Resource,
    Tool,
)

from doris_mcp_server import __version__

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DorisClientConfig:
    """Doris client configuration class"""

    def __init__(
        self,
        transport: str = "stdio",
        server_command: str | None = None,
        server_args: list[str] | None = None,
        server_url: str | None = None,
        timeout: int = 60,
    ):
        self.transport = transport
        self.server_command = server_command
        self.server_args = server_args or []
        self.server_url = server_url
        self.timeout = timeout

    @classmethod
    def stdio(cls, command: str, args: list[str] = None) -> "DorisClientConfig":
        """Create stdio connection configuration"""
        return cls(
            transport="stdio",
            server_command=command,
            server_args=args or []
        )

    @classmethod
    def http(cls, url: str, timeout: int = 60) -> "DorisClientConfig":
        """Create HTTP connection configuration"""
        return cls(
            transport="http",
            server_url=url,
            timeout=timeout
        )


class DorisResourceClient:
    """Doris resource client - Handles Resources related operations"""

    def __init__(self, session: ClientSession):
        self.session = session
        self.logger = logging.getLogger(f"{__name__}.DorisResourceClient")
        self._resources_cache = None

    async def list_resources(self) -> list[Resource]:
        """Get list of all available resources"""
        try:
            self.logger.info("Getting resource list")
            response = await self.session.list_resources()
            resources = response.resources if hasattr(response, "resources") else []
            self._resources_cache = resources
            self.logger.info(f"Retrieved {len(resources)} resources")
            return resources
        except Exception as e:
            self.logger.error(f"Failed to get resource list: {e}")
            return []

    async def read_resource(self, uri: str) -> str | None:
        """Read specified resource content"""
        try:
            self.logger.info(f"Reading resource: {uri}")
            response = await self.session.read_resource(uri)

            if hasattr(response, "contents") and response.contents:
                # Merge all content
                content_parts = []
                for content in response.contents:
                    if hasattr(content, "text"):
                        content_parts.append(content.text)
                content = "\n".join(content_parts)
                self.logger.info(f"Successfully read resource content: {len(content)} characters")
                return content
            elif hasattr(response, "content"):
                return str(response.content)
            else:
                self.logger.warning(f"Resource {uri} returned no content")
                return None

        except Exception as e:
            self.logger.error(f"Failed to read resource {uri}: {e}")
            return None

    async def filter_resources_by_type(self, resource_type: str) -> list[Resource]:
        """Filter resources by type"""
        if not self._resources_cache:
            await self.list_resources()

        if resource_type == "table":
            return [r for r in self._resources_cache if "table" in r.uri]
        elif resource_type == "view":
            return [r for r in self._resources_cache if "view" in r.uri]
        elif resource_type == "database":
            return [
                r for r in self._resources_cache
                if "database" in r.uri and "table" not in r.uri
            ]
        else:
            return self._resources_cache


class DorisToolsClient:
    """Doris tools client - Handles Tools related operations"""

    def __init__(self, session: ClientSession):
        self.session = session
        self.logger = logging.getLogger(f"{__name__}.DorisToolsClient")
        self._tools_cache = None

    async def list_tools(self) -> list[Tool]:
        """Get list of all available tools"""
        try:
            self.logger.info("Getting tool list")
            response = await self.session.list_tools()
            tools = response.tools if hasattr(response, "tools") else []
            self._tools_cache = tools
            self.logger.info(f"Retrieved {len(tools)} tools")
            return tools
        except Exception as e:
            self.logger.error(f"Failed to get tool list: {e}")
            return []

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call specified tool"""
        try:
            self.logger.info(f"Calling tool: {name}")
            self.logger.debug(f"Tool arguments: {arguments}")

            response = await self.session.call_tool(name, arguments)

            if hasattr(response, "content") and response.content:
                # Parse response content
                result_text = ""
                for content in response.content:
                    if hasattr(content, "text"):
                        result_text += content.text

                # Try to parse as JSON
                try:
                    result = json.loads(result_text)
                    self.logger.info(f"Tool call successful: {name}")
                    return result
                except json.JSONDecodeError:
                    # If not JSON format, return text directly
                    return {"success": True, "data": result_text}

            self.logger.warning(f"Tool {name} returned no content")
            return {"success": False, "error": "No response content"}

        except Exception as e:
            self.logger.error(f"Tool call failed {name}: {e}")
            return {"success": False, "error": str(e)}

    async def get_tool_by_name(self, name: str) -> Tool | None:
        """Get tool definition by name"""
        if not self._tools_cache:
            await self.list_tools()

        for tool in self._tools_cache:
            if tool.name == name:
                return tool
        return None

    async def get_tools_by_category(self, category: str) -> list[Tool]:
        """Filter tools by category"""
        if not self._tools_cache:
            await self.list_tools()

        category_lower = category.lower()
        return [
            tool for tool in self._tools_cache
            if category_lower in tool.description.lower()
            or category_lower in tool.name.lower()
        ]

    async def call_child(
        self,
        domain: str,
        child_tool: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Call one exact 1.0 child in hierarchical or formal flat mode."""
        tools = await self.list_tools()
        tool_names = {tool.name for tool in tools}
        if domain in tool_names:
            manifest = await self.call_tool(domain, {})
            children = manifest.get("children")
            if not isinstance(children, list) or not any(
                isinstance(child, dict) and child.get("name") == child_tool
                for child in children
            ):
                return {
                    "success": False,
                    "error": "Child capability not found",
                    "error_code": "CHILD_TOOL_NOT_FOUND",
                    "domain": domain,
                    "child_tool": child_tool,
                }
            request: dict[str, Any] = {
                "child_tool": child_tool,
                "arguments": arguments,
            }
            manifest_version = manifest.get("manifest_version")
            if isinstance(manifest_version, str):
                request["manifest_version"] = manifest_version
            return await self.call_tool(domain, request)

        flat_name = f"{domain}_{child_tool}"
        if flat_name in tool_names:
            return await self.call_tool(flat_name, arguments)

        return {
            "success": False,
            "error": "Child capability not found",
            "error_code": "CHILD_TOOL_NOT_FOUND",
            "domain": domain,
            "child_tool": child_tool,
        }


class DorisPromptClient:
    """Doris prompt client - Handles Prompts related operations"""

    def __init__(self, session: ClientSession):
        self.session = session
        self.logger = logging.getLogger(f"{__name__}.DorisPromptClient")
        self._prompts_cache = None

    async def list_prompts(self) -> list[Prompt]:
        """Get list of all available prompts"""
        try:
            self.logger.info("Getting prompt list")
            response = await self.session.list_prompts()
            prompts = response.prompts if hasattr(response, "prompts") else []
            self._prompts_cache = prompts
            self.logger.info(f"Retrieved {len(prompts)} prompts")
            return prompts
        except Exception as e:
            self.logger.error(f"Failed to get prompt list: {e}")
            return []

    async def get_prompt(self, name: str, arguments: dict[str, Any]) -> str | None:
        """Get specified prompt content"""
        try:
            self.logger.info(f"Getting prompt: {name}")
            self.logger.debug(f"Prompt arguments: {arguments}")

            response = await self.session.get_prompt(name, arguments)

            if hasattr(response, "messages") and response.messages:
                # Merge all message content
                content_parts = []
                for message in response.messages:
                    if hasattr(message, "content"):
                        if hasattr(message.content, "text"):
                            content_parts.append(message.content.text)
                        else:
                            content_parts.append(str(message.content))

                content = "\n".join(content_parts)
                self.logger.info(f"Successfully retrieved prompt content: {len(content)} characters")
                return content

            self.logger.warning(f"Prompt {name} returned no content")
            return None

        except Exception as e:
            self.logger.error(f"Failed to get prompt {name}: {e}")
            return None


class DorisUnifiedClient:
    """Unified Doris MCP client - Provides complete MCP functionality"""

    def __init__(self, config: DorisClientConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.DorisUnifiedClient")
        self.session = None
        self.resources = None
        self.tools = None
        self.prompts = None

    async def connect_and_run(self, callback_func: Callable):
        """Connect to server and execute callback function"""
        if self.config.transport == "stdio":
            await self._run_stdio_mode(callback_func)
        elif self.config.transport == "http":
            await self._run_http_mode(callback_func)
        else:
            raise ValueError(f"Unsupported transport type: {self.config.transport}")

    async def _run_stdio_mode(self, callback_func: Callable):
        """Run in stdio mode"""
        try:
            self.logger.info(f"Starting stdio client: {self.config.server_command}")

            server_params = StdioServerParameters(
                command=self.config.server_command,
                args=self.config.server_args,
            )

            async with MCPClient(
                stdio_client(server_params),
                read_timeout_seconds=self.config.timeout,
            ) as client:
                self.session = client.session
                self._init_sub_clients()
                self.logger.info(
                    "Server connected successfully using MCP %s",
                    client.protocol_version,
                )
                await callback_func(self)

        except Exception as e:
            self.logger.error(f"stdio mode execution failed: {e}")
            raise

    async def _run_http_mode(self, callback_func: Callable):
        """Run in HTTP mode"""
        try:
            self.logger.info(f"Starting HTTP client: {self.config.server_url}")

            async with MCPClient(
                self.config.server_url,
                read_timeout_seconds=self.config.timeout,
            ) as client:
                self.session = client.session
                self._init_sub_clients()
                self.logger.info(
                    "Server connected successfully using MCP %s",
                    client.protocol_version,
                )
                await callback_func(self)

        except Exception as e:
            self.logger.error(f"HTTP mode execution failed: {e}")
            raise

    def _init_sub_clients(self):
        """Initialize sub-clients"""
        self.resources = DorisResourceClient(self.session)
        self.tools = DorisToolsClient(self.session)
        self.prompts = DorisPromptClient(self.session)

    # Convenience methods
    async def list_all_resources(self) -> list[Resource]:
        """Get all resources"""
        return await self.resources.list_resources()

    async def list_all_tools(self) -> list[Tool]:
        """Get all tools"""
        return await self.tools.list_tools()

    async def list_all_prompts(self) -> list[Prompt]:
        """Get all prompts"""
        return await self.prompts.list_prompts()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call tool"""
        return await self.tools.call_tool(name, arguments)

    async def read_resource(self, uri: str) -> str | None:
        """Read resource"""
        return await self.resources.read_resource(uri)

    async def get_prompt(self, name: str, arguments: dict[str, Any]) -> str | None:
        """Get prompt"""
        return await self.prompts.get_prompt(name, arguments)

    # High-level business methods
    async def execute_sql(self, sql: str, **kwargs) -> dict[str, Any]:
        """Execute a read-only SQL query through the exact query child."""
        arguments = {"sql": sql, **kwargs}
        return await self.tools.call_child(
            "doris_query",
            "execute_query",
            arguments,
        )

    async def get_table_schema(
        self,
        table_name: str,
        db_name: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Get the schema section of the exact table-context child."""
        arguments = {
            "table": table_name,
            "database": db_name,
            "sections": ["schema"],
        }
        arguments.update(kwargs)

        return await self.tools.call_child(
            "doris_catalog",
            "get_table_context",
            arguments,
        )

    async def get_database_list(self, **kwargs) -> dict[str, Any]:
        """Get databases through the exact catalog child."""
        return await self.tools.call_child(
            "doris_catalog",
            "list_databases",
            kwargs,
        )

    async def get_memory_stats(
        self,
        detail: str = "summary",
        node_ids: list[str] | None = None,
        **kwargs,
    ) -> dict[str, Any]:
        """Get memory statistics through the exact cluster child."""
        arguments: dict[str, Any] = {"detail": detail}
        if node_ids is not None:
            arguments["node_ids"] = node_ids
        arguments.update(kwargs)
        return await self.tools.call_child(
            "doris_cluster",
            "get_memory_stats",
            arguments,
        )


# Convenience factory functions
async def create_stdio_client(command: str, args: list[str] = None) -> DorisUnifiedClient:
    """Create stdio client"""
    config = DorisClientConfig.stdio(command, args)
    return DorisUnifiedClient(config)


async def create_http_client(server_url: str, timeout: int = 60) -> DorisUnifiedClient:
    """Create HTTP client"""
    config = DorisClientConfig.http(server_url, timeout)
    return DorisUnifiedClient(config)


def create_arg_parser() -> argparse.ArgumentParser:
    """Create the command line parser for the packaged MCP client."""
    parser = argparse.ArgumentParser(
        description="Connect to an Apache Doris MCP server using SDK 2.0.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--transport",
        choices=["http", "stdio"],
        default="http",
        help="MCP transport to use (default: http)",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:3000/mcp",
        help="Streamable HTTP MCP endpoint",
    )
    parser.add_argument(
        "--command",
        default="doris-mcp-server",
        help="Server command used in stdio mode",
    )
    parser.add_argument(
        "--server-arg",
        action="append",
        default=[],
        help="Argument passed to the stdio server command; may be repeated",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Request timeout in seconds (default: 60)",
    )
    parser.add_argument(
        "--query",
        help="Execute one SQL query; otherwise list available tools",
    )
    return parser


async def _run_cli(args: argparse.Namespace) -> None:
    if args.transport == "stdio":
        config = DorisClientConfig.stdio(args.command, args.server_arg)
        config.timeout = args.timeout
    else:
        config = DorisClientConfig.http(args.url, args.timeout)

    client = DorisUnifiedClient(config)

    async def output(connected: DorisUnifiedClient) -> None:
        if args.query:
            payload = await connected.execute_sql(args.query)
        else:
            tools = await connected.list_all_tools()
            payload = {
                "tool_count": len(tools),
                "tools": [tool.name for tool in tools],
            }
        print(json.dumps(payload, ensure_ascii=False, indent=2))

    await client.connect_and_run(output)


def main() -> None:
    """Run the packaged Doris MCP client."""
    asyncio.run(_run_cli(create_arg_parser().parse_args()))


# Example usage
async def example_stdio():
    """stdio mode example"""
    client = await create_stdio_client("python", ["-m", "doris_mcp_server.main", "--transport", "stdio"])

    async def test_client(client: DorisUnifiedClient):
        # Get server capabilities
        resources = await client.list_all_resources()
        tools = await client.list_all_tools()
        prompts = await client.list_all_prompts()

        print(f"Resources: {len(resources)}")
        print(f"Tools: {len(tools)}")
        print(f"Prompts: {len(prompts)}")

        # Test SQL execution
        result = await client.execute_sql("SELECT 1 as test")
        print(f"SQL execution result: {result}")

    await client.connect_and_run(test_client)


async def example_http():
    """HTTP mode example"""
    client = await create_http_client("http://localhost:8080")

    async def test_client(client: DorisUnifiedClient):
        # Get server capabilities
        resources = await client.list_all_resources()
        tools = await client.list_all_tools()

        print(f"Resources: {len(resources)}")
        print(f"Tools: {len(tools)}")

        # Test database list
        result = await client.get_database_list()
        print(f"Database list: {result}")

    await client.connect_and_run(test_client)


if __name__ == "__main__":
    main()

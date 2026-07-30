<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->
# Doris Unified MCP Client

This is a unified Doris MCP client that supports both **stdio** and **Streamable HTTP** transport modes, providing complete MCP protocol support.

## 🚀 Features

- ✅ **Dual Mode Support**: Both stdio and HTTP transport methods
- ✅ **Complete MCP Support**: Resources, Tools, and Prompts primitives
- ✅ **Unified API**: Same interface for different transport modes
- ✅ **Asynchronous Design**: High-performance async client based on asyncio
- ✅ **Enterprise Features**: Connection pooling, error handling, logging
- ✅ **Convenience Methods**: High-level wrappers for common database operations

## 📦 Install Dependencies

```bash
pip install mcp
```

## 🎯 Quick Start

### 1. stdio Mode

```python
import asyncio
from client import create_stdio_client

async def main():
    # Create stdio client
    client = await create_stdio_client(
        "python", 
        ["-m", "doris_mcp_server.main", "--transport", "stdio"]
    )
    
    async def test_client(client):
        # Get database list
        db_result = await client.get_database_list()
        print(f"Databases: {db_result}")
        
        # Execute SQL query
        query_result = await client.execute_sql("SELECT 1 as test")
        print(f"Query result: {query_result}")
    
    await client.connect_and_run(test_client)

asyncio.run(main())
```

### 2. HTTP Mode

```python
import asyncio
from unified_client import create_http_client

async def main():
    # Create HTTP client
    client = await create_http_client("http://localhost:3000/mcp")
    
    async def test_client(client):
        # Get all tools
        tools = await client.list_all_tools()
        print(f"Available tools: {len(tools)}")
        
        # Execute query
        result = await client.execute_sql(
            "SELECT COUNT(*) FROM internal.ssb.lineorder LIMIT 1"
        )
        print(f"Query result: {result}")
    
    await client.connect_and_run(test_client)

asyncio.run(main())
```

## 🔧 API Reference

### Client Creation

```python
# stdio mode
client = await create_stdio_client(command, args)

# HTTP mode  
client = await create_http_client(server_url, timeout=60)
```

### Basic Operations

```python
async def test_client(client):
    # Get server capabilities
    tools = await client.list_all_tools()
    resources = await client.list_all_resources()
    prompts = await client.list_all_prompts()
    
    # Call tool
    result = await client.call_tool("tool_name", {"param": "value"})
    
    # Read resource
    content = await client.read_resource("resource://uri")
    
    # Get prompt
    prompt = await client.get_prompt("prompt_name", {"param": "value"})
```

### Advanced Database Operations

```python
async def database_operations(client):
    # Execute SQL query
    result = await client.execute_sql("SELECT * FROM table LIMIT 10")
    
    # Get database list
    databases = await client.get_database_list()
    
    # Get table schema
    schema = await client.get_table_schema("table_name", "db_name")
```

## 🧪 Testing

### Run Test Suite

```bash
# Interactive testing
python test_unified_client.py

# Test stdio mode
python test_unified_client.py stdio

# Test HTTP mode
python test_unified_client.py http

# Test both modes
python test_unified_client.py both

# Performance benchmark
python test_unified_client.py benchmark
```

### Test Output Example

```
🎯 Doris Unified Client Test Suite
============================================================

🚀 Testing HTTP Mode
==================================================
📋 Getting server capabilities...
✅ Found 8 domain tools
✅ Found 0 resources
✅ Found 0 prompts

🔧 Available tools:
  1. doris_catalog: Catalog and table metadata
  2. doris_query: Read-only query and diagnostics
  3. doris_cluster: Cluster runtime and health
  4. doris_pipeline: Ingestion and freshness
  5. doris_search: Search and index diagnostics
  6. doris_governance: Governance and lineage
  7. doris_lakehouse: Lakehouse capabilities
  8. doris_semantic: Explicit semantic-model access
  ...

🧪 Testing basic functionality...
1️⃣ Getting database list...
   ✅ Success: 3 databases
2️⃣ Executing simple query...
   ✅ Query successful
3️⃣ Executing SSB data query...
   ✅ SSB query successful
4️⃣ Getting table structure...
   ✅ Table structure retrieved successfully

✅ HTTP mode testing completed!
```

## 🏗️ Architecture Design

### Unified Client Architecture

```
DorisUnifiedClient
├── DorisResourceClient    # Resource management
├── DorisToolsClient      # Tool invocation
├── DorisPromptClient     # Prompt management
└── Transport Layer
    ├── stdio mode        # Standard input/output
    └── HTTP mode         # Streamable HTTP
```

### Key Features

1. **Unified Interface**: Same API for different transport modes
2. **Async Context**: Proper resource management and connection cleanup
3. **Error Handling**: Comprehensive exception handling and error recovery
4. **Performance Optimization**: Connection reuse and request caching

## 📚 Usage Examples

### Complete Example

```python
import asyncio
from client import DorisUnifiedClient, DorisClientConfig

async def comprehensive_example():
    # Create configuration
    config = DorisClientConfig.stdio(
        "python", 
        ["-m", "doris_mcp_server.main"]
    )
    
    client = DorisUnifiedClient(config)
    
    async def demo_operations(client):
        print("🔍 Discovering server capabilities...")
        
        # List all available tools
        tools = await client.list_all_tools()
        print(f"Available tools: {[tool.name for tool in tools]}")
        
        # Get database list
        print("\n📊 Getting database information...")
        db_result = await client.get_database_list()
        print(f"Databases: {db_result}")
        
        # Execute queries
        print("\n🔍 Executing queries...")
        
        # Simple query
        result1 = await client.execute_sql("SELECT 1 as test_column")
        print(f"Simple query result: {result1}")
        
        # Get table schema
        schema_result = await client.get_table_schema("lineorder", "ssb")
        print(f"Table schema: {schema_result}")
    
    await client.connect_and_run(demo_operations)

# Run the example
asyncio.run(comprehensive_example())
```

### Error Handling

```python
async def error_handling_example(client):
    try:
        # This might fail
        result = await client.execute_sql("INVALID SQL")
    except Exception as e:
        print(f"SQL execution failed: {e}")
        
    # Check result status
    result = await client.get_database_list()
    if result.get("success", True):
        print("Operation successful")
    else:
        print(f"Operation failed: {result.get('error')}")
```

## 🔧 Configuration

### Client Configuration Options

```python
# stdio mode with custom arguments
config = DorisClientConfig(
    transport="stdio",
    server_command="python",
    server_args=["-m", "doris_mcp_server.main", "--debug"],
    timeout=30
)

# HTTP mode with custom timeout
config = DorisClientConfig(
    transport="http",
    server_url="http://localhost:8080/mcp",
    timeout=60
)
```

### Environment Variables

```bash
# Set default server URL
export DORIS_MCP_SERVER_URL="http://localhost:8080"

# Set default timeout
export DORIS_MCP_TIMEOUT=60

# Enable debug logging
export DORIS_MCP_DEBUG=true
```

## 🚀 Performance Tips

1. **Connection Reuse**: Use the same client instance for multiple operations
2. **Batch Operations**: Group related queries together
3. **Async Context**: Always use proper async context management
4. **Error Recovery**: Implement retry logic for transient failures

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the Apache 2.0 License.

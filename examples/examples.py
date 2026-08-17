import asyncio
from doris_mcp_client.client import DorisUnifiedClient, DorisClientConfig
# HTTP 模式
async def example_http():
    config = DorisClientConfig.http("http://localhost:3000/doris-mcp/mcp", timeout=60)
    client = DorisUnifiedClient(config)
    async def operations(client: DorisUnifiedClient):
        # 列出所有工具
        tools = await client.list_all_tools()
        print(f"可用工具: {[t.name for t in tools]}")
        # 获取数据库列表
        db_list = await client.get_database_list()
        print(f"数据库列表: {db_list}")
        # 执行 SQL 查询
        result = await client.execute_sql("SELECT COUNT(*) FROM internal.ssb.customer")
        print(f"查询结果: {result}")
        # 获取表结构
        schema = await client.get_table_schema("customer", "ssb")
        print(f"表结构: {schema}")
    await client.connect_and_run(operations)
# Stdio 模式
async def example_stdio():
    config = DorisClientConfig.stdio(
        "doris-mcp-server", ["--transport", "stdio"]
    )
    client = DorisUnifiedClient(config)
    async def operations(client: DorisUnifiedClient):
        result = await client.execute_sql("SELECT 1 AS test")
        print(f"结果: {result}")
    await client.connect_and_run(operations)
asyncio.run(example_http())
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
Apache Doris MCP Prompts Manager
Provides standardized management of query templates and intelligent prompts
"""

from datetime import datetime
from typing import Any

from mcp.types import (
    GetPromptResult,
    Prompt,
    PromptArgument,
    PromptMessage,
    TextContent,
)

from ..utils.db import DorisConnectionManager
from ..utils.sql_security_utils import get_auth_context


class PromptTemplate:
    """Prompt template"""

    def __init__(
        self,
        name: str,
        description: str,
        template: str,
        arguments: list[PromptArgument] = None,
        category: str = "general",
    ):
        self.name = name
        self.description = description
        self.template = template
        self.arguments = arguments or []
        self.category = category
        self.created_at = datetime.now()

    def render(self, arguments: dict[str, Any]) -> str:
        """Render template content"""
        content = self.template
        for key, value in arguments.items():
            placeholder = f"{{{key}}}"
            content = content.replace(placeholder, str(value))
        return content


class DorisPromptsManager:
    """Apache Doris Prompts Manager"""

    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        self.templates = self._init_prompt_templates()

    def _init_prompt_templates(self) -> dict[str, PromptTemplate]:
        """Initialize prompt templates"""
        templates = {}

        # Sales data analysis template
        templates["sales_analysis"] = PromptTemplate(
            name="sales_analysis",
            description="Sales data analysis query template for generating sales statistics and trend analysis queries",
            template="""Please help me analyze sales data with the following requirements:

Analysis time range: {date_range}
{product_filter}
{region_filter}

Please generate SQL queries to analyze the following dimensions:
1. Total sales amount and order quantity
2. Sales trends by time dimension
3. Top-selling product rankings
4. Sales personnel performance statistics

Data table structure reference:
- Order table: Contains order ID, customer ID, salesperson ID, order amount, order time and other fields
- Product table: Contains product ID, product name, product category, price and other fields
- Customer table: Contains customer ID, customer name, region and other fields

Please ensure query results are easy to understand and analyze.""",
            arguments=[
                PromptArgument(
                    name="date_range",
                    description="Date range for analysis, such as 'Q1 2024' or 'last 30 days'",
                    required=True,
                ),
                PromptArgument(
                    name="product_category",
                    description="Product category filter condition, such as 'electronics'",
                    required=False,
                ),
                PromptArgument(
                    name="region",
                    description="Sales region filter condition, such as 'East China'",
                    required=False,
                ),
            ],
            category="business_analysis",
        )

        # User behavior analysis template
        templates["user_behavior_analysis"] = PromptTemplate(
            name="user_behavior_analysis",
            description="User behavior analysis query template for analyzing user activity patterns and preferences",
            template="""Please help me analyze user behavior data, analysis objectives:

User segment: {user_segment}
{behavior_filter}
Analysis period: {time_period}

Please generate SQL queries to analyze the following aspects:
1. User activity statistics (DAU, MAU)
2. User behavior path analysis
3. Feature usage preference statistics
4. User retention rate analysis

Data table structure reference:
- User table: Contains user ID, registration time, user type, region and other fields
- Behavior log table: Contains user ID, behavior type, behavior time, page path and other fields
- Session table: Contains session ID, user ID, session start time, session duration and other fields

Please provide easy-to-understand statistical results and visualization suggestions.""",
            arguments=[
                PromptArgument(
                    name="user_segment",
                    description="User segment conditions, such as 'new users', 'active users'",
                    required=True,
                ),
                PromptArgument(
                    name="behavior_type",
                    description="Behavior type filter, such as 'login', 'purchase', 'browse'",
                    required=False,
                ),
                PromptArgument(
                    name="time_period",
                    description="Analysis time period, such as 'last 7 days', 'this month'",
                    required=False,
                ),
            ],
            category="user_analysis",
        )

        # Performance optimization analysis template
        templates["performance_optimization"] = PromptTemplate(
            name="performance_optimization",
            description="Database performance optimization analysis template for identifying performance bottlenecks and optimization opportunities",
            template="""Please help me with database performance analysis and optimization recommendations:

Focus area: {focus_area}
{table_scope}
Performance metrics: {metrics}

Please generate SQL queries to analyze the following content:
1. Table and query performance statistics
2. Index usage efficiency analysis
3. Slow query identification and analysis
4. Storage space usage

Analysis objectives:
- Identify performance bottlenecks
- Provide optimization recommendations
- Evaluate optimization effects

Please provide specific optimization recommendations and implementation steps.""",
            arguments=[
                PromptArgument(
                    name="focus_area",
                    description="Performance area of focus, such as 'query performance', 'storage optimization'",
                    required=True,
                ),
                PromptArgument(
                    name="table_name",
                    description="Specific table name (optional), if analyzing specific table performance",
                    required=False,
                ),
                PromptArgument(
                    name="metrics",
                    description="Performance metrics of interest, such as 'response time', 'throughput'",
                    required=False,
                ),
            ],
            category="performance",
        )

        # Data quality check template
        templates["data_quality_check"] = PromptTemplate(
            name="data_quality_check",
            description="Data quality check template for detecting data integrity and consistency issues",
            template="""Please help me perform data quality checks:

Check target: {target_table}
{quality_dimensions}
Check level: {check_level}

Please generate SQL queries to check the following data quality issues:
1. Data integrity (null values, duplicate values)
2. Data consistency (format, range)
3. Data accuracy (business rule validation)
4. Data timeliness (update frequency)

Check items:
- Required field null value checks
- Primary key and unique constraint validation
- Data format and type checks
- Business logic consistency validation
- Data distribution anomaly detection

Please provide detailed problem reports and fix recommendations.""",
            arguments=[
                PromptArgument(
                    name="target_table", description="Target table name to check", required=True
                ),
                PromptArgument(
                    name="quality_dimensions",
                    description="Quality check dimensions, such as 'integrity', 'consistency', 'accuracy'",
                    required=False,
                ),
                PromptArgument(
                    name="check_level",
                    description="Check level, such as 'basic check', 'deep check'",
                    required=False,
                ),
            ],
            category="data_quality",
        )

        # Report generation template
        templates["report_generation"] = PromptTemplate(
            name="report_generation",
            description="Business report generation template for creating standardized business reports",
            template="""Please help me generate business reports:

Report type: {report_type}
Report period: {report_period}
{business_scope}

Please generate SQL queries to build the following report content:
1. Key business indicator summary
2. Trend analysis and year-over-year/month-over-month comparison
3. Anomaly data identification and explanation
4. Business insights and recommendations

Report requirements:
- Data accuracy and timeliness
- Clear hierarchical structure
- Easy-to-understand data presentation
- Decision-supporting analytical perspective

Please provide complete report structure and data acquisition logic.""",
            arguments=[
                PromptArgument(
                    name="report_type",
                    description="Report type, such as 'sales report', 'operations report', 'financial report'",
                    required=True,
                ),
                PromptArgument(
                    name="report_period",
                    description="Report period, such as 'daily report', 'weekly report', 'monthly report'",
                    required=True,
                ),
                PromptArgument(
                    name="business_unit",
                    description="Business unit scope, such as 'East China region', 'Product line A'",
                    required=False,
                ),
            ],
            category="reporting",
        )

        # Real-time monitoring template
        templates["real_time_monitoring"] = PromptTemplate(
            name="real_time_monitoring",
            description="Real-time monitoring query template for building real-time data monitoring and alerting",
            template="""Please help me design real-time monitoring queries:

Monitoring target: {monitoring_target}
Alert threshold: {alert_threshold}
Monitoring frequency: {monitoring_frequency}

Please generate SQL queries to implement the following monitoring functions:
1. Real-time statistics of key indicators
2. Anomaly detection and alerting
3. Trend change monitoring
4. System health status checks

Monitoring dimensions:
- Business indicator monitoring (transaction volume, user activity, etc.)
- Technical indicator monitoring (performance, error rate, etc.)
- Data quality monitoring (integrity, consistency, etc.)

Please provide complete monitoring solution and implementation recommendations.""",
            arguments=[
                PromptArgument(
                    name="monitoring_target",
                    description="Monitoring target, such as 'transaction system', 'user activity'",
                    required=True,
                ),
                PromptArgument(
                    name="alert_threshold",
                    description="Alert threshold setting, such as 'error rate > 5%'",
                    required=False,
                ),
                PromptArgument(
                    name="monitoring_frequency",
                    description="Monitoring frequency, such as 'real-time', 'every minute', 'every 5 minutes'",
                    required=False,
                ),
            ],
            category="monitoring",
        )

        return templates

    async def list_prompts(self) -> list[Prompt]:
        """List all available prompt templates"""
        prompts = []

        for template in self.templates.values():
            prompt = Prompt(
                name=template.name,
                description=template.description,
                arguments=template.arguments,
            )
            prompts.append(prompt)

        return prompts

    async def get_prompt(self, name: str, arguments: dict[str, Any]) -> GetPromptResult:
        """Get content of specific prompt template"""
        if name not in self.templates:
            raise ValueError(f"Prompt template named '{name}' not found")

        template = self.templates[name]

        # Process optional arguments
        processed_args = await self._process_arguments(template, arguments)

        # Render template content
        rendered_content = template.render(processed_args)

        # Add database context information
        context_info = await self._get_database_context()

        full_content = f"""{rendered_content}

Database context information:
{context_info}

Please generate accurate and efficient SQL queries based on the above requirements and database structure."""

        return GetPromptResult(
            description=template.description,
            messages=[
                PromptMessage(
                    role="user", content=TextContent(type="text", text=full_content)
                )
            ],
        )

    async def _process_arguments(
        self, template: PromptTemplate, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Process template arguments"""
        processed = {}

        for arg in template.arguments:
            if arg.name in arguments:
                processed[arg.name] = arguments[arg.name]
            elif arg.required:
                raise ValueError(f"Missing required parameter: {arg.name}")
            else:
                # Provide default handling for optional parameters
                processed[arg.name] = self._get_default_argument_text(arg.name)

        return processed

    def _get_default_argument_text(self, arg_name: str) -> str:
        """Get default text for optional parameters"""
        defaults = {
            "product_category": "",
            "region": "",
            "behavior_type": "",
            "time_period": "No time range restriction",
            "table_name": "",
            "metrics": "All performance metrics",
            "quality_dimensions": "All quality dimensions",
            "check_level": "Standard check",
            "business_unit": "Full business scope",
            "alert_threshold": "Use default threshold",
            "monitoring_frequency": "Real-time monitoring",
        }

        return defaults.get(arg_name, "")

    async def _get_database_context(self) -> str:
        """Get database context information"""
        try:
            connection = await self.connection_manager.get_connection("system")

            # Get basic database information
            db_info_sql = """
            SELECT
                COUNT(*) as table_count,
                SUM(table_rows) as total_rows
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
            AND table_type = 'BASE TABLE'
            """

            auth_context = get_auth_context()
            db_result = await connection.execute(db_info_sql, auth_context=auth_context)
            db_info = db_result.data[0] if db_result.data else {}

            # Get main table list
            tables_sql = """
            SELECT
                table_name,
                table_comment,
                table_rows
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
            AND table_type = 'BASE TABLE'
            ORDER BY table_rows DESC
            LIMIT 10
            """

            tables_result = await connection.execute(tables_sql, auth_context=auth_context)

            context = f"""Current database statistics:
- Total number of tables: {db_info.get("table_count", 0)}
- Total data rows: {db_info.get("total_rows", 0):,}

Main data tables:"""

            for table in tables_result.data:
                context += f"\n- {table['table_name']}"
                if table.get("table_comment"):
                    context += f": {table['table_comment']}"
                context += f" ({table.get('table_rows', 0):,} rows)"

            return context

        except Exception as e:
            return f"Unable to get database context information: {str(e)}"

    def get_templates_by_category(self, category: str) -> list[PromptTemplate]:
        """Get templates by category"""
        return [
            template
            for template in self.templates.values()
            if template.category == category
        ]

    def get_all_categories(self) -> list[str]:
        """Get all template categories"""
        categories = {template.category for template in self.templates.values()}
        return sorted(categories)

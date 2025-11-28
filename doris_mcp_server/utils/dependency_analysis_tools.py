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
Dependency Analysis Tools Module
Provides data flow dependency analysis and impact assessment capabilities
"""

import time
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque

from .db import DorisConnectionManager
from .logger import get_logger
from .sql_security_utils import (
    SQLSecurityError,
    validate_identifier,
    quote_identifier,
    build_table_reference,
    get_auth_context
)

logger = get_logger(__name__)


class DependencyAnalysisTools:
    """Dependency analysis tools for data flow and impact assessment"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        logger.info("DependencyAnalysisTools initialized")
    
    async def analyze_data_flow_dependencies(
        self, 
        target_table: Optional[str] = None,
        analysis_depth: int = 3,
        include_views: bool = True,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze data flow dependencies and impact relationships
        
        Args:
            target_table: Specific table to analyze (if None, analyzes all tables)
            analysis_depth: Maximum depth for dependency traversal
            include_views: Whether to include views in dependency analysis
            catalog_name: Catalog name
            db_name: Database name
        
        Returns:
            Comprehensive dependency analysis results
        """
        try:
            start_time = time.time()
            connection = await self.connection_manager.get_connection("query")
            
            # 1. Get table metadata and relationships
            tables_metadata = await self._get_tables_metadata(connection, catalog_name, db_name, include_views)
            
            if not tables_metadata:
                return {
                    "error": "No tables found for dependency analysis",
                    "analysis_timestamp": datetime.now().isoformat()
                }
            
            # 2. Build dependency graph from SQL analysis
            dependency_graph = await self._build_dependency_graph(connection, tables_metadata, analysis_depth)
            
            # 3. Analyze specific table or all tables
            if target_table:
                # Analyze specific table
                table_analysis = await self._analyze_single_table_dependencies(
                    target_table, dependency_graph, tables_metadata
                )
                impact_analysis = await self._calculate_impact_analysis(
                    target_table, dependency_graph, "both"
                )
            else:
                # Analyze all tables
                table_analysis = await self._analyze_all_tables_dependencies(
                    dependency_graph, tables_metadata
                )
                impact_analysis = await self._calculate_global_impact_analysis(dependency_graph)
            
            # 4. Generate insights and recommendations
            dependency_insights = await self._generate_dependency_insights(
                dependency_graph, table_analysis, impact_analysis
            )
            
            execution_time = time.time() - start_time
            
            return {
                "analysis_target": target_table or "all_tables",
                "analysis_timestamp": datetime.now().isoformat(),
                "execution_time_seconds": round(execution_time, 3),
                "tables_analyzed": len(tables_metadata),
                "dependency_graph_stats": self._get_dependency_graph_stats(dependency_graph),
                "table_dependencies": table_analysis,
                "impact_analysis": impact_analysis,
                "dependency_insights": dependency_insights,
                "recommendations": self._generate_dependency_recommendations(dependency_insights)
            }
            
        except Exception as e:
            logger.error(f"Data flow dependency analysis failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    # ==================== Private Helper Methods ====================
    
    async def _get_tables_metadata(self, connection, catalog_name: Optional[str], db_name: Optional[str], include_views: bool) -> List[Dict]:
        """Get metadata for all tables and views"""
        try:
            # Build conditions for query with parameterized values
            where_conditions = []
            params = []
            
            if db_name:
                # SECURITY FIX: Validate identifier and use parameterized query
                try:
                    validate_identifier(db_name, "database name")
                except SQLSecurityError as e:
                    logger.warning(f"Invalid database name rejected: {e}")
                    return []
                where_conditions.append("table_schema = %s")
                params.append(db_name)
            else:
                where_conditions.append("table_schema = DATABASE()")
            
            table_types = ["'BASE TABLE'"]
            if include_views:
                table_types.append("'VIEW'")
            
            where_conditions.append(f"table_type IN ({','.join(table_types)})")
            
            metadata_sql = f"""
            SELECT 
                table_schema as schema_name,
                table_name,
                table_type,
                table_comment,
                table_rows,
                data_length
            FROM information_schema.tables
            WHERE {' AND '.join(where_conditions)}
            ORDER BY table_schema, table_name
            """
            
            # SECURITY FIX: Get auth_context and pass to execute for security validation
            auth_context = get_auth_context()
            result = await connection.execute(
                metadata_sql, 
                params=tuple(params) if params else None,
                auth_context=auth_context
            )
            return result.data if result.data else []
            
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed in _get_tables_metadata: {str(e)}")
            return []
        except Exception as e:
            logger.warning(f"Failed to get tables metadata: {str(e)}")
            return []
    
    async def _build_dependency_graph(self, connection, tables_metadata: List[Dict], analysis_depth: int) -> Dict[str, Dict]:
        """Build dependency graph by analyzing SQL statements and DDL"""
        dependency_graph = defaultdict(lambda: {
            "upstream_dependencies": set(),
            "downstream_dependencies": set(),
            "table_type": "unknown",
            "dependency_strength": {},
            "sql_patterns": []
        })
        
        # Initialize graph with table metadata
        for table in tables_metadata:
            table_name = table["table_name"]
            schema_name = table.get("schema_name", "")
            full_table_name = f"{schema_name}.{table_name}" if schema_name else table_name
            
            dependency_graph[full_table_name]["table_type"] = table["table_type"]
        
        # 1. Analyze view definitions for dependencies
        await self._analyze_view_dependencies(connection, dependency_graph, tables_metadata)
        
        # 2. Analyze audit logs for runtime dependencies
        await self._analyze_runtime_dependencies(connection, dependency_graph, analysis_depth)
        
        # 3. Analyze foreign key relationships
        await self._analyze_foreign_key_dependencies(connection, dependency_graph, tables_metadata)
        
        return dict(dependency_graph)
    
    async def _analyze_view_dependencies(self, connection, dependency_graph: Dict, tables_metadata: List[Dict]) -> None:
        """Analyze view definitions to extract table dependencies"""
        # Get auth_context once for all operations in this method
        auth_context = get_auth_context()
        
        try:
            for table in tables_metadata:
                if table["table_type"] == "VIEW":
                    table_name = table["table_name"]
                    schema_name = table.get("schema_name", "")
                    
                    # SECURITY FIX: Validate identifiers before using in SQL
                    try:
                        validate_identifier(table_name, "table name")
                        if schema_name:
                            validate_identifier(schema_name, "schema name")
                    except SQLSecurityError as e:
                        logger.warning(f"Invalid identifier rejected in view analysis: {e}")
                        continue
                    
                    # Build safe view reference using quoted identifiers
                    view_ref = build_table_reference(table_name, schema_name) if schema_name else quote_identifier(table_name, "table name")
                    view_def_sql = f"SHOW CREATE VIEW {view_ref}"
                    
                    try:
                        # SECURITY FIX: Pass auth_context to execute
                        result = await connection.execute(view_def_sql, auth_context=auth_context)
                        if result.data and len(result.data) > 0:
                            # Extract view definition from result
                            view_definition = ""
                            for row in result.data:
                                for key, value in row.items():
                                    if "create" in key.lower() and value:
                                        view_definition = str(value)
                                        break
                            
                            if view_definition:
                                # Extract table dependencies from view definition
                                referenced_tables = self._extract_table_references(view_definition)
                                
                                full_view_name = f"{schema_name}.{table_name}" if schema_name else table_name
                                
                                for ref_table in referenced_tables:
                                    # Add upstream dependency
                                    dependency_graph[full_view_name]["upstream_dependencies"].add(ref_table)
                                    dependency_graph[full_view_name]["dependency_strength"][ref_table] = "direct"
                                    
                                    # Add downstream dependency for referenced table
                                    dependency_graph[ref_table]["downstream_dependencies"].add(full_view_name)
                                    
                                    dependency_graph[full_view_name]["sql_patterns"].append({
                                        "pattern_type": "view_definition",
                                        "referenced_table": ref_table,
                                        "confidence": 1.0
                                    })
                    
                    except Exception as e:
                        logger.warning(f"Failed to analyze view {table_name}: {str(e)}")
                        continue
        
        except Exception as e:
            logger.warning(f"Failed to analyze view dependencies: {str(e)}")
    
    async def _analyze_runtime_dependencies(self, connection, dependency_graph: Dict, analysis_depth: int) -> None:
        """Analyze audit logs to discover runtime table dependencies"""
        # Get auth_context for security validation
        auth_context = get_auth_context()
        
        try:
            # Get recent SQL statements from audit logs
            audit_sql = """
            SELECT 
                `stmt` as sql_statement,
                `user` as user_name,
                COUNT(*) as frequency
            FROM internal.__internal_schema.audit_log 
            WHERE `stmt` IS NOT NULL 
                AND `stmt` != ''
                AND `time` >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
            GROUP BY `stmt`, `user`
            HAVING frequency > 1
            ORDER BY frequency DESC
            LIMIT 1000
            """
            
            # SECURITY FIX: Pass auth_context to execute
            result = await connection.execute(audit_sql, auth_context=auth_context)
            
            if result.data:
                for row in result.data:
                    sql_statement = row.get("sql_statement", "")
                    frequency = row.get("frequency", 1)
                    
                    if sql_statement:
                        # Extract table references from SQL
                        referenced_tables = self._extract_table_references(sql_statement)
                        
                        if len(referenced_tables) > 1:
                            # Infer dependencies from multi-table queries
                            self._infer_dependencies_from_sql(
                                dependency_graph, sql_statement, referenced_tables, frequency
                            )
        
        except Exception as e:
            logger.warning(f"Failed to analyze runtime dependencies: {str(e)}")
    
    async def _analyze_foreign_key_dependencies(self, connection, dependency_graph: Dict, tables_metadata: List[Dict]) -> None:
        """Analyze foreign key constraints for explicit dependencies"""
        # Get auth_context for security validation
        auth_context = get_auth_context()
        
        try:
            # Get foreign key information
            fk_sql = """
            SELECT 
                TABLE_SCHEMA as schema_name,
                TABLE_NAME as table_name,
                COLUMN_NAME as column_name,
                REFERENCED_TABLE_SCHEMA as ref_schema,
                REFERENCED_TABLE_NAME as ref_table_name,
                REFERENCED_COLUMN_NAME as ref_column_name
            FROM information_schema.KEY_COLUMN_USAGE
            WHERE REFERENCED_TABLE_NAME IS NOT NULL
            """
            
            # SECURITY FIX: Pass auth_context to execute
            result = await connection.execute(fk_sql, auth_context=auth_context)
            
            if result.data:
                for row in result.data:
                    schema_name = row.get("schema_name", "")
                    table_name = row["table_name"]
                    ref_schema = row.get("ref_schema", "")
                    ref_table_name = row["ref_table_name"]
                    
                    # Build full table names
                    full_table_name = f"{schema_name}.{table_name}" if schema_name else table_name
                    full_ref_table = f"{ref_schema}.{ref_table_name}" if ref_schema else ref_table_name
                    
                    # Add foreign key dependency
                    dependency_graph[full_table_name]["upstream_dependencies"].add(full_ref_table)
                    dependency_graph[full_table_name]["dependency_strength"][full_ref_table] = "foreign_key"
                    dependency_graph[full_ref_table]["downstream_dependencies"].add(full_table_name)
                    
                    dependency_graph[full_table_name]["sql_patterns"].append({
                        "pattern_type": "foreign_key",
                        "referenced_table": full_ref_table,
                        "confidence": 1.0,
                        "column": row["column_name"],
                        "ref_column": row["ref_column_name"]
                    })
        
        except Exception as e:
            logger.warning(f"Failed to analyze foreign key dependencies: {str(e)}")
    
    def _extract_table_references(self, sql: str) -> List[str]:
        """Extract table references from SQL statement"""
        if not sql:
            return []
        
        # Normalize SQL
        sql = re.sub(r'/\*.*?\*/', '', sql, flags=re.DOTALL)  # Remove comments
        sql = re.sub(r'--.*', '', sql)  # Remove line comments
        sql = sql.upper()
        
        table_references = []
        
        # Pattern to match table names in various contexts
        patterns = [
            r'\bFROM\s+([`"]?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*[`"]?)',
            r'\bJOIN\s+([`"]?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*[`"]?)',
            r'\bINTO\s+([`"]?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*[`"]?)',
            r'\bUPDATE\s+([`"]?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*[`"]?)',
            r'\bDELETE\s+FROM\s+([`"]?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*[`"]?)',
            r'\bINSERT\s+INTO\s+([`"]?[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*[`"]?)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, sql, re.IGNORECASE)
            for match in matches:
                # Clean up table name
                table_name = match.strip('`"\'').split()[0]  # Remove quotes and aliases
                if table_name and not self._is_sql_keyword(table_name):
                    table_references.append(table_name.lower())
        
        return list(set(table_references))
    
    def _is_sql_keyword(self, word: str) -> bool:
        """Check if word is a SQL keyword"""
        keywords = {
            'SELECT', 'FROM', 'WHERE', 'JOIN', 'INNER', 'LEFT', 'RIGHT', 'OUTER',
            'ON', 'AND', 'OR', 'NOT', 'IN', 'EXISTS', 'BETWEEN', 'LIKE',
            'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP', 'INDEX',
            'TABLE', 'VIEW', 'DATABASE', 'SCHEMA', 'PRIMARY', 'KEY', 'FOREIGN',
            'REFERENCES', 'CONSTRAINT', 'NULL', 'DEFAULT', 'AUTO_INCREMENT'
        }
        return word.upper() in keywords
    
    def _infer_dependencies_from_sql(self, dependency_graph: Dict, sql: str, referenced_tables: List[str], frequency: int) -> None:
        """Infer table dependencies from SQL patterns"""
        # Analyze SQL pattern to determine dependency relationships
        sql_upper = sql.upper()
        
        # Look for INSERT ... SELECT patterns
        if 'INSERT' in sql_upper and 'SELECT' in sql_upper:
            # Find target table (after INSERT INTO)
            insert_match = re.search(r'INSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_.]*)', sql_upper)
            if insert_match:
                target_table = insert_match.group(1).lower()
                
                # All other tables are dependencies
                for ref_table in referenced_tables:
                    if ref_table != target_table:
                        dependency_graph[target_table]["upstream_dependencies"].add(ref_table)
                        dependency_graph[ref_table]["downstream_dependencies"].add(target_table)
                        
                        # Calculate confidence based on frequency
                        confidence = min(0.9, 0.3 + (frequency / 100))
                        dependency_graph[target_table]["sql_patterns"].append({
                            "pattern_type": "insert_select",
                            "referenced_table": ref_table,
                            "confidence": confidence,
                            "frequency": frequency
                        })
        
        # Look for CREATE TABLE AS SELECT patterns
        elif 'CREATE' in sql_upper and 'SELECT' in sql_upper:
            create_match = re.search(r'CREATE\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_.]*)', sql_upper)
            if create_match:
                target_table = create_match.group(1).lower()
                
                for ref_table in referenced_tables:
                    if ref_table != target_table:
                        dependency_graph[target_table]["upstream_dependencies"].add(ref_table)
                        dependency_graph[ref_table]["downstream_dependencies"].add(target_table)
                        
                        dependency_graph[target_table]["sql_patterns"].append({
                            "pattern_type": "create_table_as_select",
                            "referenced_table": ref_table,
                            "confidence": 0.95,
                            "frequency": frequency
                        })
    
    async def _analyze_single_table_dependencies(self, target_table: str, dependency_graph: Dict, tables_metadata: List[Dict]) -> Dict[str, Any]:
        """Analyze dependencies for a specific table"""
        if target_table not in dependency_graph:
            return {"error": f"Table {target_table} not found in dependency graph"}
        
        table_info = dependency_graph[target_table]
        
        # Get upstream dependencies (tables this table depends on)
        upstream_deps = await self._get_dependency_chain(target_table, dependency_graph, "upstream", 3)
        
        # Get downstream dependencies (tables that depend on this table)
        downstream_deps = await self._get_dependency_chain(target_table, dependency_graph, "downstream", 3)
        
        return {
            "table_name": target_table,
            "table_type": table_info["table_type"],
            "direct_upstream_dependencies": list(table_info["upstream_dependencies"]),
            "direct_downstream_dependencies": list(table_info["downstream_dependencies"]),
            "upstream_dependency_chain": upstream_deps,
            "downstream_dependency_chain": downstream_deps,
            "dependency_patterns": table_info["sql_patterns"],
            "dependency_metrics": {
                "upstream_count": len(table_info["upstream_dependencies"]),
                "downstream_count": len(table_info["downstream_dependencies"]),
                "total_upstream_chain": len(upstream_deps.get("all_dependencies", [])),
                "total_downstream_chain": len(downstream_deps.get("all_dependencies", [])),
                "dependency_depth": max(upstream_deps.get("max_depth", 0), downstream_deps.get("max_depth", 0))
            }
        }
    
    async def _get_dependency_chain(self, start_table: str, dependency_graph: Dict, direction: str, max_depth: int) -> Dict[str, Any]:
        """Get full dependency chain in specified direction"""
        visited = set()
        all_dependencies = []
        levels = []
        current_level = [start_table]
        depth = 0
        
        while current_level and depth < max_depth:
            next_level = []
            level_deps = []
            
            for table in current_level:
                if table in visited:
                    continue
                
                visited.add(table)
                
                if direction == "upstream":
                    dependencies = dependency_graph.get(table, {}).get("upstream_dependencies", set())
                else:
                    dependencies = dependency_graph.get(table, {}).get("downstream_dependencies", set())
                
                for dep in dependencies:
                    if dep not in visited:
                        next_level.append(dep)
                        level_deps.append(dep)
                        all_dependencies.append(dep)
            
            if level_deps:
                levels.append({
                    "level": depth + 1,
                    "tables": level_deps
                })
            
            current_level = next_level
            depth += 1
        
        return {
            "direction": direction,
            "max_depth": depth,
            "all_dependencies": list(set(all_dependencies)),
            "dependency_levels": levels,
            "total_count": len(set(all_dependencies))
        }
    
    async def _analyze_all_tables_dependencies(self, dependency_graph: Dict, tables_metadata: List[Dict]) -> Dict[str, Any]:
        """Analyze dependencies for all tables"""
        table_stats = {}
        
        for table_name, table_info in dependency_graph.items():
            upstream_count = len(table_info["upstream_dependencies"])
            downstream_count = len(table_info["downstream_dependencies"])
            
            table_stats[table_name] = {
                "table_type": table_info["table_type"],
                "upstream_count": upstream_count,
                "downstream_count": downstream_count,
                "total_connections": upstream_count + downstream_count,
                "dependency_score": self._calculate_dependency_score(upstream_count, downstream_count),
                "role_classification": self._classify_table_role(upstream_count, downstream_count)
            }
        
        # Find key tables
        most_critical_tables = sorted(
            table_stats.items(), 
            key=lambda x: x[1]["dependency_score"], 
            reverse=True
        )[:10]
        
        source_tables = [name for name, stats in table_stats.items() if stats["role_classification"] == "source"]
        sink_tables = [name for name, stats in table_stats.items() if stats["role_classification"] == "sink"]
        hub_tables = [name for name, stats in table_stats.items() if stats["role_classification"] == "hub"]
        
        return {
            "table_statistics": table_stats,
            "summary": {
                "total_tables": len(table_stats),
                "source_tables": len(source_tables),
                "sink_tables": len(sink_tables),
                "hub_tables": len(hub_tables),
                "isolated_tables": len([stats for stats in table_stats.values() if stats["total_connections"] == 0])
            },
            "critical_tables": [{"table": name, **stats} for name, stats in most_critical_tables],
            "table_roles": {
                "sources": source_tables[:10],
                "sinks": sink_tables[:10],
                "hubs": hub_tables[:10]
            }
        }
    
    def _calculate_dependency_score(self, upstream_count: int, downstream_count: int) -> float:
        """Calculate dependency importance score for a table"""
        # Score based on both incoming and outgoing dependencies
        # Higher weight for downstream dependencies (impact)
        return round(upstream_count * 0.3 + downstream_count * 0.7, 2)
    
    def _classify_table_role(self, upstream_count: int, downstream_count: int) -> str:
        """Classify table role based on dependency pattern"""
        if upstream_count == 0 and downstream_count > 0:
            return "source"  # Data source
        elif upstream_count > 0 and downstream_count == 0:
            return "sink"    # Data destination
        elif upstream_count > 2 and downstream_count > 2:
            return "hub"     # Data hub/transformation
        elif upstream_count > 0 and downstream_count > 0:
            return "intermediate"  # Intermediate transformation
        else:
            return "isolated"  # No dependencies
    
    async def _calculate_impact_analysis(self, target_table: str, dependency_graph: Dict, direction: str) -> Dict[str, Any]:
        """Calculate impact analysis for a specific table"""
        if direction == "upstream" or direction == "both":
            upstream_impact = await self._calculate_upstream_impact(target_table, dependency_graph)
        else:
            upstream_impact = {}
        
        if direction == "downstream" or direction == "both":
            downstream_impact = await self._calculate_downstream_impact(target_table, dependency_graph)
        else:
            downstream_impact = {}
        
        return {
            "target_table": target_table,
            "upstream_impact": upstream_impact,
            "downstream_impact": downstream_impact,
            "total_impact_score": self._calculate_total_impact_score(upstream_impact, downstream_impact)
        }
    
    async def _calculate_upstream_impact(self, target_table: str, dependency_graph: Dict) -> Dict[str, Any]:
        """Calculate what would be impacted if upstream dependencies fail"""
        upstream_deps = dependency_graph.get(target_table, {}).get("upstream_dependencies", set())
        
        impact_scenarios = []
        for dep_table in upstream_deps:
            # Simulate failure of this dependency
            affected_tables = await self._simulate_table_failure_impact(dep_table, dependency_graph)
            
            impact_scenarios.append({
                "failed_dependency": dep_table,
                "directly_affected_tables": len(affected_tables["direct"]),
                "indirectly_affected_tables": len(affected_tables["indirect"]),
                "total_affected": len(affected_tables["all"]),
                "critical_affected": [table for table in affected_tables["all"] 
                                    if dependency_graph.get(table, {}).get("downstream_dependencies", set())],
                "impact_severity": self._assess_impact_severity(len(affected_tables["all"]))
            })
        
        return {
            "dependency_count": len(upstream_deps),
            "impact_scenarios": impact_scenarios,
            "max_potential_impact": max([scenario["total_affected"] for scenario in impact_scenarios], default=0),
            "risk_assessment": self._assess_upstream_risk(impact_scenarios)
        }
    
    async def _calculate_downstream_impact(self, target_table: str, dependency_graph: Dict) -> Dict[str, Any]:
        """Calculate what would be impacted if target table fails"""
        affected_tables = await self._simulate_table_failure_impact(target_table, dependency_graph)
        
        return {
            "direct_impact": len(affected_tables["direct"]),
            "indirect_impact": len(affected_tables["indirect"]),
            "total_impact": len(affected_tables["all"]),
            "affected_table_details": [
                {
                    "table_name": table,
                    "impact_type": "direct" if table in affected_tables["direct"] else "indirect",
                    "table_role": self._classify_table_role(
                        len(dependency_graph.get(table, {}).get("upstream_dependencies", set())),
                        len(dependency_graph.get(table, {}).get("downstream_dependencies", set()))
                    )
                }
                for table in affected_tables["all"]
            ],
            "impact_severity": self._assess_impact_severity(len(affected_tables["all"]))
        }
    
    async def _simulate_table_failure_impact(self, failed_table: str, dependency_graph: Dict) -> Dict[str, List[str]]:
        """Simulate the impact of a table failure"""
        direct_affected = list(dependency_graph.get(failed_table, {}).get("downstream_dependencies", set()))
        
        # Find all indirectly affected tables using BFS
        visited = {failed_table}
        queue = deque(direct_affected)
        indirect_affected = []
        
        while queue:
            current_table = queue.popleft()
            if current_table in visited:
                continue
            
            visited.add(current_table)
            indirect_affected.append(current_table)
            
            # Add downstream dependencies to queue
            downstream = dependency_graph.get(current_table, {}).get("downstream_dependencies", set())
            for dep in downstream:
                if dep not in visited:
                    queue.append(dep)
        
        # Remove direct affected from indirect (they're already counted)
        indirect_only = [table for table in indirect_affected if table not in direct_affected]
        
        return {
            "direct": direct_affected,
            "indirect": indirect_only,
            "all": direct_affected + indirect_only
        }
    
    def _assess_impact_severity(self, affected_count: int) -> str:
        """Assess impact severity based on affected table count"""
        if affected_count == 0:
            return "none"
        elif affected_count <= 2:
            return "low"
        elif affected_count <= 5:
            return "medium"
        elif affected_count <= 10:
            return "high"
        else:
            return "critical"
    
    def _assess_upstream_risk(self, impact_scenarios: List[Dict]) -> str:
        """Assess upstream dependency risk"""
        if not impact_scenarios:
            return "low"
        
        max_impact = max([scenario["total_affected"] for scenario in impact_scenarios])
        high_impact_scenarios = len([s for s in impact_scenarios if s["impact_severity"] in ["high", "critical"]])
        
        if high_impact_scenarios > 0 or max_impact > 10:
            return "high"
        elif max_impact > 5 or len(impact_scenarios) > 3:
            return "medium"
        else:
            return "low"
    
    def _calculate_total_impact_score(self, upstream_impact: Dict, downstream_impact: Dict) -> float:
        """Calculate total impact score combining upstream and downstream risks"""
        upstream_score = 0
        downstream_score = 0
        
        if upstream_impact:
            max_upstream_impact = upstream_impact.get("max_potential_impact", 0)
            upstream_score = min(max_upstream_impact * 0.3, 10)  # Cap at 10
        
        if downstream_impact:
            downstream_score = min(downstream_impact.get("total_impact", 0) * 0.7, 10)  # Cap at 10
        
        return round(upstream_score + downstream_score, 2)
    
    async def _calculate_global_impact_analysis(self, dependency_graph: Dict) -> Dict[str, Any]:
        """Calculate global impact analysis for all tables"""
        table_impacts = {}
        
        for table_name in dependency_graph.keys():
            impact = await self._calculate_impact_analysis(table_name, dependency_graph, "downstream")
            table_impacts[table_name] = {
                "downstream_impact": impact["downstream_impact"]["total_impact"],
                "impact_severity": impact["downstream_impact"]["impact_severity"],
                "impact_score": impact["total_impact_score"]
            }
        
        # Find most critical tables
        critical_tables = sorted(
            table_impacts.items(),
            key=lambda x: x[1]["impact_score"],
            reverse=True
        )[:15]
        
        # Risk distribution
        risk_distribution = {
            "critical": len([t for t in table_impacts.values() if t["impact_severity"] == "critical"]),
            "high": len([t for t in table_impacts.values() if t["impact_severity"] == "high"]),
            "medium": len([t for t in table_impacts.values() if t["impact_severity"] == "medium"]),
            "low": len([t for t in table_impacts.values() if t["impact_severity"] == "low"]),
            "none": len([t for t in table_impacts.values() if t["impact_severity"] == "none"])
        }
        
        return {
            "global_impact_summary": {
                "total_tables_analyzed": len(table_impacts),
                "tables_with_impact": len([t for t in table_impacts.values() if t["downstream_impact"] > 0]),
                "average_impact_score": round(sum(t["impact_score"] for t in table_impacts.values()) / len(table_impacts), 2) if table_impacts else 0,
                "risk_distribution": risk_distribution
            },
            "most_critical_tables": [{"table": name, **stats} for name, stats in critical_tables],
            "risk_matrix": self._generate_risk_matrix(table_impacts)
        }
    
    def _generate_risk_matrix(self, table_impacts: Dict[str, Dict]) -> Dict[str, List[str]]:
        """Generate risk matrix categorizing tables by impact level"""
        risk_matrix = {
            "critical_risk": [],
            "high_risk": [],
            "medium_risk": [],
            "low_risk": [],
            "minimal_risk": []
        }
        
        for table_name, impact_data in table_impacts.items():
            severity = impact_data["impact_severity"]
            if severity == "critical":
                risk_matrix["critical_risk"].append(table_name)
            elif severity == "high":
                risk_matrix["high_risk"].append(table_name)
            elif severity == "medium":
                risk_matrix["medium_risk"].append(table_name)
            elif severity == "low":
                risk_matrix["low_risk"].append(table_name)
            else:
                risk_matrix["minimal_risk"].append(table_name)
        
        return risk_matrix
    
    def _get_dependency_graph_stats(self, dependency_graph: Dict) -> Dict[str, Any]:
        """Get statistics about the dependency graph"""
        total_tables = len(dependency_graph)
        total_dependencies = sum(
            len(table_info.get("upstream_dependencies", set())) + len(table_info.get("downstream_dependencies", set()))
            for table_info in dependency_graph.values()
        ) // 2  # Divide by 2 to avoid double counting
        
        tables_with_upstream = len([
            table for table, info in dependency_graph.items()
            if info.get("upstream_dependencies")
        ])
        
        tables_with_downstream = len([
            table for table, info in dependency_graph.items()
            if info.get("downstream_dependencies")
        ])
        
        isolated_tables = len([
            table for table, info in dependency_graph.items()
            if not info.get("upstream_dependencies") and not info.get("downstream_dependencies")
        ])
        
        return {
            "total_tables": total_tables,
            "total_dependencies": total_dependencies,
            "tables_with_upstream_deps": tables_with_upstream,
            "tables_with_downstream_deps": tables_with_downstream,
            "isolated_tables": isolated_tables,
            "connectivity_ratio": round((total_tables - isolated_tables) / total_tables, 3) if total_tables > 0 else 0,
            "avg_dependencies_per_table": round(total_dependencies / total_tables, 2) if total_tables > 0 else 0
        }
    
    async def _generate_dependency_insights(self, dependency_graph: Dict, table_analysis: Dict, impact_analysis: Dict) -> Dict[str, Any]:
        """Generate insights from dependency analysis"""
        insights = {
            "architectural_patterns": {},
            "risk_assessment": {},
            "optimization_opportunities": {}
        }
        
        # Architectural patterns
        graph_stats = self._get_dependency_graph_stats(dependency_graph)
        
        insights["architectural_patterns"] = {
            "connectivity_level": "high" if graph_stats["connectivity_ratio"] > 0.7 else "medium" if graph_stats["connectivity_ratio"] > 0.3 else "low",
            "architecture_type": self._classify_architecture_type(graph_stats),
            "complexity_score": round(graph_stats["avg_dependencies_per_table"] * graph_stats["connectivity_ratio"], 2),
            "isolated_tables_concern": graph_stats["isolated_tables"] > graph_stats["total_tables"] * 0.3
        }
        
        # Risk assessment
        if isinstance(impact_analysis, dict) and "global_impact_summary" in impact_analysis:
            global_impact = impact_analysis["global_impact_summary"]
            
            insights["risk_assessment"] = {
                "overall_risk_level": self._assess_overall_risk_level(global_impact["risk_distribution"]),
                "critical_tables_count": global_impact["risk_distribution"]["critical"],
                "high_risk_tables_count": global_impact["risk_distribution"]["high"],
                "impact_concentration": global_impact["average_impact_score"] > 5.0,
                "resilience_score": self._calculate_resilience_score(global_impact)
            }
        
        # Optimization opportunities
        insights["optimization_opportunities"] = self._identify_optimization_opportunities(dependency_graph, table_analysis)
        
        return insights
    
    def _classify_architecture_type(self, graph_stats: Dict) -> str:
        """Classify the overall architecture type"""
        connectivity = graph_stats["connectivity_ratio"]
        avg_deps = graph_stats["avg_dependencies_per_table"]
        
        if connectivity > 0.8 and avg_deps > 3:
            return "highly_interconnected"
        elif connectivity > 0.5 and avg_deps > 2:
            return "moderately_connected"
        elif connectivity < 0.3:
            return "loosely_coupled"
        else:
            return "mixed_architecture"
    
    def _assess_overall_risk_level(self, risk_distribution: Dict[str, int]) -> str:
        """Assess overall risk level from risk distribution"""
        total = sum(risk_distribution.values())
        if total == 0:
            return "minimal"
        
        critical_ratio = risk_distribution["critical"] / total
        high_ratio = risk_distribution["high"] / total
        
        if critical_ratio > 0.1 or high_ratio > 0.2:
            return "high"
        elif critical_ratio > 0.05 or high_ratio > 0.1:
            return "medium"
        else:
            return "low"
    
    def _calculate_resilience_score(self, global_impact: Dict) -> float:
        """Calculate system resilience score (0-1, higher is better)"""
        total_tables = global_impact["total_tables_analyzed"]
        risk_dist = global_impact["risk_distribution"]
        
        if total_tables == 0:
            return 0.0
        
        # Calculate weighted risk score
        weighted_risk = (
            risk_dist["critical"] * 5 +
            risk_dist["high"] * 3 +
            risk_dist["medium"] * 2 +
            risk_dist["low"] * 1
        ) / total_tables
        
        # Convert to resilience score (inverse of risk, normalized)
        max_possible_risk = 5.0
        resilience = max(0, (max_possible_risk - weighted_risk) / max_possible_risk)
        
        return round(resilience, 3)
    
    def _identify_optimization_opportunities(self, dependency_graph: Dict, table_analysis: Dict) -> List[Dict]:
        """Identify optimization opportunities"""
        opportunities = []
        
        # Find tables with excessive dependencies
        for table_name, table_info in dependency_graph.items():
            upstream_count = len(table_info.get("upstream_dependencies", set()))
            downstream_count = len(table_info.get("downstream_dependencies", set()))
            
            if upstream_count > 10:
                opportunities.append({
                    "type": "excessive_upstream_dependencies",
                    "table": table_name,
                    "description": f"Table has {upstream_count} upstream dependencies",
                    "recommendation": "Consider breaking down complex transformations or using intermediate tables",
                    "priority": "high" if upstream_count > 15 else "medium"
                })
            
            if downstream_count > 10:
                opportunities.append({
                    "type": "excessive_downstream_dependencies",
                    "table": table_name,
                    "description": f"Table has {downstream_count} downstream dependencies",
                    "recommendation": "Consider if this table is doing too much or if views could be used",
                    "priority": "high" if downstream_count > 15 else "medium"
                })
        
        # Find potential circular dependencies (simplified check)
        # This is a basic check - full cycle detection would be more complex
        for table_name, table_info in dependency_graph.items():
            upstream_deps = table_info.get("upstream_dependencies", set())
            for upstream_table in upstream_deps:
                if table_name in dependency_graph.get(upstream_table, {}).get("upstream_dependencies", set()):
                    opportunities.append({
                        "type": "potential_circular_dependency",
                        "table": table_name,
                        "related_table": upstream_table,
                        "description": f"Potential circular dependency between {table_name} and {upstream_table}",
                        "recommendation": "Review and eliminate circular dependencies",
                        "priority": "high"
                    })
        
        return opportunities
    
    def _generate_dependency_recommendations(self, dependency_insights: Dict) -> List[Dict]:
        """Generate recommendations based on dependency analysis"""
        recommendations = []
        
        # Architecture recommendations
        arch_patterns = dependency_insights.get("architectural_patterns", {})
        if arch_patterns.get("isolated_tables_concern", False):
            recommendations.append({
                "type": "architecture",
                "priority": "medium",
                "title": "High number of isolated tables",
                "description": "Many tables have no dependencies, which may indicate data silos",
                "action": "Review isolated tables and consider if they should be integrated into data flows"
            })
        
        complexity_score = arch_patterns.get("complexity_score", 0)
        if complexity_score > 5:
            recommendations.append({
                "type": "architecture",
                "priority": "high",
                "title": "High system complexity",
                "description": f"System complexity score is {complexity_score} (high)",
                "action": "Consider simplifying data architecture and reducing unnecessary dependencies"
            })
        
        # Risk recommendations
        risk_assessment = dependency_insights.get("risk_assessment", {})
        overall_risk = risk_assessment.get("overall_risk_level", "unknown")
        
        if overall_risk == "high":
            recommendations.append({
                "type": "risk_mitigation",
                "priority": "high",
                "title": "High overall system risk",
                "description": "System has high dependency risks that could cause widespread failures",
                "action": "Implement monitoring and backup strategies for critical tables"
            })
        
        critical_tables = risk_assessment.get("critical_tables_count", 0)
        if critical_tables > 0:
            recommendations.append({
                "type": "risk_mitigation",
                "priority": "high",
                "title": f"{critical_tables} critical impact tables identified",
                "description": "Tables with critical impact require special attention",
                "action": "Implement enhanced monitoring and backup procedures for critical tables"
            })
        
        # Optimization recommendations
        optimization_ops = dependency_insights.get("optimization_opportunities", [])
        if optimization_ops:
            high_priority_ops = [op for op in optimization_ops if op.get("priority") == "high"]
            if high_priority_ops:
                recommendations.append({
                    "type": "optimization",
                    "priority": "high",
                    "title": f"{len(high_priority_ops)} high-priority optimization opportunities",
                    "description": "System has optimization opportunities that should be addressed",
                    "action": "Review and implement suggested optimizations for better maintainability"
                })
        
        return recommendations 
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
Performance Analytics Tools Module
Provides slow query analysis and resource growth monitoring capabilities
"""

import time
import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict, Counter

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


class PerformanceAnalyticsTools:
    """Performance analytics tools for query and resource monitoring"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        logger.info("PerformanceAnalyticsTools initialized")
    
    async def analyze_slow_queries_topn(
        self, 
        days: int = 7,
        top_n: int = 20,
        min_execution_time_ms: int = 1000,
        include_patterns: bool = True
    ) -> Dict[str, Any]:
        """
        Analyze top N slowest queries and performance patterns
        
        Args:
            days: Number of days to analyze
            top_n: Number of top slow queries to return
            min_execution_time_ms: Minimum execution time threshold
            include_patterns: Whether to include query pattern analysis
        
        Returns:
            Slow query analysis results
        """
        try:
            start_time = time.time()
            connection = await self.connection_manager.get_connection("query")
            
            # Get slow query data
            slow_queries = await self._get_slow_query_data(
                connection, days, min_execution_time_ms
            )
            
            if not slow_queries:
                return {
                    "message": "No slow queries found for the specified criteria",
                    "analysis_period": {"days": days, "threshold_ms": min_execution_time_ms},
                    "analysis_timestamp": datetime.now().isoformat()
                }
            
            # Analyze top N queries
            top_queries = await self._analyze_top_slow_queries(slow_queries, top_n)
            
            # Performance insights
            performance_insights = await self._generate_performance_insights(slow_queries)
            
            # Query patterns analysis
            pattern_analysis = {}
            if include_patterns:
                pattern_analysis = await self._analyze_query_patterns(slow_queries)
            
            execution_time = time.time() - start_time
            
            return {
                "analysis_period": {
                    "days": days,
                    "threshold_ms": min_execution_time_ms,
                    "start_date": (datetime.now() - timedelta(days=days)).isoformat(),
                    "end_date": datetime.now().isoformat()
                },
                "analysis_timestamp": datetime.now().isoformat(),
                "execution_time_seconds": round(execution_time, 3),
                "summary": {
                    "total_slow_queries": len(slow_queries),
                    "unique_queries": len(set(q.get("sql_hash", q.get("sql", ""))[:100] for q in slow_queries)),
                    "top_n_analyzed": min(top_n, len(slow_queries))
                },
                "top_slow_queries": top_queries,
                "performance_insights": performance_insights,
                "query_patterns": pattern_analysis,
                "recommendations": self._generate_performance_recommendations(performance_insights, pattern_analysis)
            }
            
        except Exception as e:
            logger.error(f"Slow query analysis failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    async def analyze_resource_growth_curves(
        self, 
        days: int = 30,
        resource_types: List[str] = None,
        include_predictions: bool = False,
        detailed_response: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze resource growth patterns and trends based on real historical data
        
        Args:
            days: Number of days to analyze
            resource_types: Types of resources to analyze
            include_predictions: Whether to include growth predictions
            detailed_response: Whether to return detailed data including daily breakdowns
        
        Returns:
            Resource growth analysis results
        """
        try:
            start_time = time.time()
            connection = await self.connection_manager.get_connection("query")
            
            if resource_types is None:
                resource_types = ["storage", "query_volume", "user_activity"]
            
            # Analyze each resource type
            resource_analysis = {}
            
            if "storage" in resource_types:
                resource_analysis["storage"] = await self._analyze_storage_growth_with_real_data(
                    connection, days, detailed_response
                )
            
            if "query_volume" in resource_types:
                resource_analysis["query_volume"] = await self._analyze_query_volume_growth(
                    connection, days, detailed_response
                )
            
            if "user_activity" in resource_types:
                resource_analysis["user_activity"] = await self._analyze_user_activity_growth(
                    connection, days, detailed_response
                )
            
            # Generate growth insights
            growth_insights = await self._generate_enhanced_growth_insights(resource_analysis, days)
            
            # Growth predictions (based on real data)
            predictions = {}
            if include_predictions:
                predictions = await self._generate_statistical_growth_predictions(resource_analysis, days)
            
            execution_time = time.time() - start_time
            
            result = {
                "analysis_period": {
                    "days": days,
                    "start_date": (datetime.now() - timedelta(days=days)).isoformat(),
                    "end_date": datetime.now().isoformat()
                },
                "analysis_timestamp": datetime.now().isoformat(),
                "execution_time_seconds": round(execution_time, 3),
                "resource_types_analyzed": resource_types,
                "resource_analysis": resource_analysis,
                "growth_insights": growth_insights,
                "growth_predictions": predictions,
                "recommendations": self._generate_enhanced_growth_recommendations(growth_insights, predictions),
                "data_quality": {
                    "historical_data_available": True,
                    "analysis_methods": ["partition_based", "timestamp_based", "audit_log_based"],
                    "confidence_level": "high"
                }
            }
            
            # Add execution info for debugging
            result["_execution_info"] = {
                "tool_name": "analyze_resource_growth_curves",
                "execution_time": round(execution_time, 3),
                "timestamp": datetime.now().isoformat(),
                "detailed_response": detailed_response,
                "version": "2.0_real_data_based"
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Resource growth analysis failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    # ==================== Private Helper Methods ====================
    
    async def _analyze_query_volume_growth(self, connection, days: int, detailed_response: bool = False) -> Dict[str, Any]:
        """Analyze query volume growth patterns"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            
            # Get daily query counts from audit logs
            query_volume_sql = f"""
            SELECT 
                DATE(`time`) as query_date,
                COUNT(*) as total_queries,
                COUNT(DISTINCT `user`) as unique_users,
                AVG(`query_time`) as avg_execution_time_ms,
                SUM(`scan_bytes`) as total_scan_bytes,
                SUM(`scan_rows`) as total_scan_rows
            FROM internal.__internal_schema.audit_log 
            WHERE `time` >= '{start_date.strftime('%Y-%m-%d %H:%M:%S')}'
                AND `stmt` IS NOT NULL
                AND `stmt` != ''
            GROUP BY DATE(`time`)
            ORDER BY query_date
            """
            
            auth_context = get_auth_context()
            result = await connection.execute(query_volume_sql, auth_context=auth_context)
            daily_data = result.data if result.data else []
            
            if not daily_data:
                return {
                    "growth_trend": "no_data",
                    "daily_query_count": {
                        "current": 0,
                        "average": 0,
                        "growth_rate_percent": 0
                    },
                    "query_complexity_trend": "stable",
                    "user_adoption_trend": "stable"
                }
            
            # Calculate growth metrics
            query_counts = [row.get("total_queries", 0) for row in daily_data]
            user_counts = [row.get("unique_users", 0) for row in daily_data]
            
            avg_queries = sum(query_counts) / len(query_counts) if query_counts else 0
            current_queries = query_counts[-1] if query_counts else 0
            
            # Calculate growth rate
            if len(query_counts) >= 2:
                early_avg = sum(query_counts[:len(query_counts)//2]) / (len(query_counts)//2)
                late_avg = sum(query_counts[len(query_counts)//2:]) / (len(query_counts) - len(query_counts)//2)
                growth_rate = ((late_avg - early_avg) / early_avg * 100) if early_avg > 0 else 0
            else:
                growth_rate = 0
            
            return {
                "growth_trend": "increasing" if growth_rate > 5 else "decreasing" if growth_rate < -5 else "stable",
                "daily_query_count": {
                    "current": current_queries,
                    "average": round(avg_queries, 2),
                    "growth_rate_percent": round(growth_rate, 2)
                },
                "query_complexity_trend": "stable",  # Could be enhanced with more analysis
                "user_adoption_trend": "stable",     # Could be enhanced with more analysis
                "analysis_period_days": days,
                "data_points": len(daily_data)
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze query volume growth: {str(e)}")
            return {
                "growth_trend": "unknown",
                "daily_query_count": {
                    "current": 0,
                    "average": 0,
                    "growth_rate_percent": 0
                },
                "error": str(e)
            }
    
    async def _analyze_user_activity_growth(self, connection, days: int, detailed_response: bool = False) -> Dict[str, Any]:
        """Analyze user activity growth patterns"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            
            # Get daily user activity from audit logs
            user_activity_sql = f"""
            SELECT 
                DATE(`time`) as activity_date,
                COUNT(DISTINCT `user`) as daily_active_users,
                COUNT(*) as total_queries,
                COUNT(DISTINCT `client_ip`) as unique_ips
            FROM internal.__internal_schema.audit_log 
            WHERE `time` >= '{start_date.strftime('%Y-%m-%d %H:%M:%S')}'
                AND `stmt` IS NOT NULL
                AND `stmt` != ''
            GROUP BY DATE(`time`)
            ORDER BY activity_date
            """
            
            auth_context = get_auth_context()
            result = await connection.execute(user_activity_sql, auth_context=auth_context)
            daily_data = result.data if result.data else []
            
            if not daily_data:
                return {
                    "growth_trend": "no_data",
                    "daily_active_users": {
                        "current": 0,
                        "average": 0,
                        "growth_rate_percent": 0
                    },
                    "user_engagement_trend": "stable"
                }
            
            # Calculate user activity metrics
            user_counts = [row.get("daily_active_users", 0) for row in daily_data]
            avg_users = sum(user_counts) / len(user_counts) if user_counts else 0
            current_users = user_counts[-1] if user_counts else 0
            
            # Calculate growth rate
            if len(user_counts) >= 2:
                early_avg = sum(user_counts[:len(user_counts)//2]) / (len(user_counts)//2)
                late_avg = sum(user_counts[len(user_counts)//2:]) / (len(user_counts) - len(user_counts)//2)
                growth_rate = ((late_avg - early_avg) / early_avg * 100) if early_avg > 0 else 0
            else:
                growth_rate = 0
            
            return {
                "growth_trend": "increasing" if growth_rate > 10 else "decreasing" if growth_rate < -10 else "stable",
                "daily_active_users": {
                    "current": current_users,
                    "average": round(avg_users, 2),
                    "growth_rate_percent": round(growth_rate, 2)
                },
                "user_engagement_trend": "stable",  # Could be enhanced with more analysis
                "analysis_period_days": days,
                "data_points": len(daily_data)
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze user activity growth: {str(e)}")
            return {
                "growth_trend": "unknown",
                "daily_active_users": {
                    "current": 0,
                    "average": 0,
                    "growth_rate_percent": 0
                },
                "error": str(e)
            }
    
    async def _get_slow_query_data(self, connection, days: int, min_execution_time_ms: int) -> List[Dict]:
        """Get slow query data from audit logs"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            
            slow_query_sql = f"""
            SELECT 
                `user` as user_name,
                `client_ip` as host,
                `time` as query_time,
                `stmt` as sql_statement,
                `query_time` as execution_time_ms,
                `scan_bytes` as scan_bytes,
                `scan_rows` as scan_rows,
                `return_rows` as return_rows
            FROM internal.__internal_schema.audit_log 
            WHERE `time` >= '{start_date.strftime('%Y-%m-%d %H:%M:%S')}'
                AND `query_time` >= {min_execution_time_ms}
                AND `stmt` IS NOT NULL
                AND `stmt` != ''
                AND `stmt` NOT LIKE '%__internal_schema%'
                AND `stmt` NOT LIKE '%information_schema%'
                AND `stmt` NOT LIKE '%mysql%'
                AND `state` != 'ERR'
            ORDER BY `query_time` DESC
            LIMIT 5000
            """
            
            auth_context = get_auth_context()
            result = await connection.execute(slow_query_sql, auth_context=auth_context)
            return result.data if result.data else []
            
        except Exception as e:
            logger.warning(f"Failed to get slow query data: {str(e)}")
            return []
    
    async def _analyze_top_slow_queries(self, slow_queries: List[Dict], top_n: int) -> List[Dict]:
        """Analyze top N slowest queries"""
        # Sort by execution time and take top N
        sorted_queries = sorted(
            slow_queries, 
            key=lambda x: x.get("execution_time_ms", 0), 
            reverse=True
        )[:top_n]
        
        analyzed_queries = []
        for i, query in enumerate(sorted_queries):
            sql = query.get("sql_statement", "")
            execution_time = query.get("execution_time_ms", 0)
            
            analyzed_query = {
                "rank": i + 1,
                "execution_time_ms": execution_time,
                "execution_time_seconds": round(execution_time / 1000, 2),
                "user_name": query.get("user_name", "unknown"),
                "query_time": str(query.get("query_time", "")),
                "sql_statement": sql[:500] + "..." if len(sql) > 500 else sql,
                "sql_length": len(sql),
                "query_type": self._classify_query_type(sql),
                "scan_metrics": {
                    "scan_bytes": query.get("scan_bytes", 0),
                    "scan_rows": query.get("scan_rows", 0),
                    "return_rows": query.get("return_rows", 0)
                },
                "performance_issues": self._identify_performance_issues(query)
            }
            
            analyzed_queries.append(analyzed_query)
        
        return analyzed_queries
    
    def _classify_query_type(self, sql: str) -> str:
        """Classify SQL query type"""
        if not sql:
            return "unknown"
        
        sql_upper = sql.upper().strip()
        
        if sql_upper.startswith('SELECT'):
            return "SELECT"
        elif sql_upper.startswith('INSERT'):
            return "INSERT"
        elif sql_upper.startswith('UPDATE'):
            return "UPDATE"
        elif sql_upper.startswith('DELETE'):
            return "DELETE"
        else:
            return "OTHER"
    
    def _identify_performance_issues(self, query: Dict) -> List[str]:
        """Identify potential performance issues in query"""
        issues = []
        
        sql = query.get("sql_statement", "").upper()
        execution_time = query.get("execution_time_ms", 0)
        scan_bytes = query.get("scan_bytes", 0)
        scan_rows = query.get("scan_rows", 0)
        return_rows = query.get("return_rows", 0)
        
        # High execution time
        if execution_time > 60000:  # > 1 minute
            issues.append("very_long_execution")
        elif execution_time > 10000:  # > 10 seconds
            issues.append("long_execution")
        
        # Large data scan
        if scan_bytes > 1024**3:  # > 1GB
            issues.append("large_data_scan")
        
        # High row scan vs return ratio
        if scan_rows > 0 and return_rows > 0:
            scan_ratio = scan_rows / return_rows
            if scan_ratio > 1000:
                issues.append("inefficient_filtering")
        
        # SQL pattern issues
        if "SELECT *" in sql:
            issues.append("select_all_columns")
        
        if "ORDER BY" in sql and "LIMIT" not in sql:
            issues.append("unlimited_sort")
        
        return issues
    
    async def _generate_performance_insights(self, slow_queries: List[Dict]) -> Dict[str, Any]:
        """Generate performance insights from slow queries"""
        if not slow_queries:
            return {}
        
        execution_times = [q.get("execution_time_ms", 0) for q in slow_queries]
        scan_bytes = [q.get("scan_bytes", 0) for q in slow_queries if q.get("scan_bytes", 0) > 0]
        
        # User analysis
        user_query_counts = Counter(q.get("user_name", "unknown") for q in slow_queries)
        
        # Query type distribution
        query_types = Counter(self._classify_query_type(q.get("sql_statement", "")) for q in slow_queries)
        
        # Time pattern analysis
        query_hours = []
        for query in slow_queries:
            try:
                query_time = query.get("query_time")
                if query_time:
                    if isinstance(query_time, str):
                        dt = datetime.fromisoformat(query_time.replace('Z', '+00:00'))
                    else:
                        dt = query_time
                    query_hours.append(dt.hour)
            except:
                continue
        
        hour_distribution = Counter(query_hours)
        
        return {
            "execution_time_stats": {
                "avg_ms": round(statistics.mean(execution_times), 2) if execution_times else 0,
                "median_ms": round(statistics.median(execution_times), 2) if execution_times else 0,
                "max_ms": max(execution_times) if execution_times else 0,
                "min_ms": min(execution_times) if execution_times else 0
            },
            "data_scan_stats": {
                "avg_bytes": round(statistics.mean(scan_bytes), 2) if scan_bytes else 0,
                "max_bytes": max(scan_bytes) if scan_bytes else 0,
                "total_bytes_scanned": sum(scan_bytes) if scan_bytes else 0
            },
            "user_analysis": {
                "top_slow_query_users": dict(user_query_counts.most_common(10)),
                "unique_users": len(user_query_counts)
            },
            "query_type_distribution": dict(query_types),
            "temporal_patterns": {
                "hourly_distribution": dict(hour_distribution),
                "peak_hour": max(hour_distribution, key=hour_distribution.get) if hour_distribution else None
            }
        }
    
    async def _analyze_query_patterns(self, slow_queries: List[Dict]) -> Dict[str, Any]:
        """Analyze query patterns in slow queries"""
        patterns = {
            "common_issues": Counter(),
            "table_access_patterns": Counter(),
            "query_complexity": []
        }
        
        for query in slow_queries:
            sql = query.get("sql_statement", "")
            
            # Identify common issues
            issues = self._identify_performance_issues(query)
            patterns["common_issues"].update(issues)
            
            # Extract table names
            tables = self._extract_table_names(sql)
            patterns["table_access_patterns"].update(tables)
            
            # Query complexity metrics
            complexity = self._calculate_query_complexity(sql)
            patterns["query_complexity"].append(complexity)
        
        return {
            "common_performance_issues": dict(patterns["common_issues"].most_common(10)),
            "frequently_accessed_tables": dict(patterns["table_access_patterns"].most_common(15)),
            "complexity_analysis": {
                "avg_complexity": round(statistics.mean(patterns["query_complexity"]), 2) if patterns["query_complexity"] else 0,
                "max_complexity": max(patterns["query_complexity"]) if patterns["query_complexity"] else 0,
                "high_complexity_queries": len([c for c in patterns["query_complexity"] if c > 10])
            }
        }
    
    def _extract_table_names(self, sql: str) -> List[str]:
        """Extract table names from SQL (simplified)"""
        import re
        
        if not sql:
            return []
        
        # Simple pattern matching for table names
        patterns = [
            r'\bFROM\s+([a-zA-Z_][a-zA-Z0-9_.]*)',
            r'\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_.]*)',
            r'\bINTO\s+([a-zA-Z_][a-zA-Z0-9_.]*)',
            r'\bUPDATE\s+([a-zA-Z_][a-zA-Z0-9_.]*)'
        ]
        
        tables = []
        for pattern in patterns:
            matches = re.findall(pattern, sql, re.IGNORECASE)
            tables.extend(matches)
        
        return [table.lower() for table in tables if table]
    
    def _calculate_query_complexity(self, sql: str) -> int:
        """Calculate query complexity score"""
        if not sql:
            return 0
        
        sql_upper = sql.upper()
        complexity = 0
        
        # Basic complexity factors
        complexity += sql_upper.count('JOIN') * 2
        complexity += sql_upper.count('SUBQUERY') * 3
        complexity += sql_upper.count('UNION') * 2
        complexity += sql_upper.count('GROUP BY') * 1
        complexity += sql_upper.count('ORDER BY') * 1
        complexity += sql_upper.count('HAVING') * 2
        complexity += sql_upper.count('CASE') * 1
        
        # Length factor
        complexity += len(sql) // 100
        
        return complexity
    
    async def _analyze_storage_growth_with_real_data(
        self, connection, days: int, detailed_response: bool = False
    ) -> Dict[str, Any]:
        """Analyze storage growth patterns based on real historical data with intelligent table selection"""
        try:
            logger.info("🔍 Starting optimized storage growth analysis...")
            
            # Step 1: Fast data size collection using SHOW DATA
            logger.info("📊 Fast scanning all tables data sizes...")
            all_tables_sizes = await self._get_all_tables_sizes_fast(connection)
            if not all_tables_sizes:
                return {"error": "No tables found for storage analysis"}
            
            # Step 2: Calculate data distribution and select top tables
            logger.info("🎯 Selecting high-impact tables for detailed analysis...")
            selected_tables = await self._select_high_impact_tables(all_tables_sizes, target_coverage=0.8)
            
            logger.info(f"📈 Analyzing {len(selected_tables)} high-impact tables (covering {selected_tables['coverage_percentage']:.1f}% of total data)")
            
            # Step 3: Detailed analysis only for selected tables
            table_growth_data = []
            total_current_size = selected_tables["total_selected_size_mb"]
            total_historical_data_points = 0
            
            for table_info in selected_tables["tables"]:
                table_name = table_info["table_name"]
                schema_name = table_info["schema_name"]
                full_table_name = f"{schema_name}.{table_name}" if schema_name else table_name
                
                logger.info(f"🔍 Analyzing table: {full_table_name} ({table_info['size_mb']:.1f}MB)")
                
                # Analyze historical growth for single table
                table_growth = await self._analyze_single_table_storage_growth(
                    connection, full_table_name, table_name, schema_name, days
                )
                
                if table_growth and table_growth.get("current_size_mb", 0) > 0:
                    table_growth_data.append(table_growth)
                    total_historical_data_points += len(table_growth.get("historical_data", []))
            
            # Calculate overall storage growth trends
            overall_growth = await self._calculate_overall_storage_growth(table_growth_data, days)
            
            result = {
                "analysis_method": "optimized_high_impact_analysis",
                "total_tables_scanned": len(all_tables_sizes),
                "high_impact_tables_analyzed": len(table_growth_data),
                "data_coverage_percentage": round(selected_tables["coverage_percentage"], 1),
                "total_cluster_storage_mb": round(selected_tables["total_cluster_size_mb"], 2),
                "analyzed_storage_mb": round(total_current_size, 2),
                "historical_data_points": total_historical_data_points,
                "overall_growth_metrics": overall_growth,
                "confidence_level": self._calculate_storage_confidence_level(table_growth_data),
                "optimization_info": {
                    "strategy": "80/20 rule - analyze top tables covering 80% of data",
                    "performance_gain": f"Analyzed {len(table_growth_data)} tables instead of {len(all_tables_sizes)}",
                    "time_saved_percentage": round((1 - len(table_growth_data) / len(all_tables_sizes)) * 100, 1) if all_tables_sizes else 0
                }
            }
            
            # Include detailed table-level data
            if detailed_response:
                result["table_level_analysis"] = table_growth_data
            else:
                # Only include top 10 largest tables
                result["top_growing_tables"] = sorted(
                    table_growth_data, 
                    key=lambda x: x.get("growth_rate_mb_per_day", 0), 
                    reverse=True
                )[:10]
            
            logger.info(f"✅ Storage growth analysis completed: {len(table_growth_data)} tables analyzed")
            return result
            
        except Exception as e:
            logger.error(f"Failed to analyze storage growth with real data: {str(e)}")
            return {"error": str(e)}
    
    async def _get_all_tables_sizes_fast(self, connection) -> List[Dict]:
        """Fast collection of all tables sizes using information_schema optimization"""
        try:
            # Stage 1: Get database-level overview using information_schema
            logger.info("🔍 Stage 1: Getting database-level data overview from information_schema...")
            
            db_sizes_sql = """
            SELECT 
                TABLE_SCHEMA as db_name,
                ROUND(SUM(COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) / 1024 / 1024, 2) as size_mb,
                COUNT(*) as table_count
            FROM information_schema.tables 
            WHERE TABLE_SCHEMA NOT IN ('information_schema', '__internal_schema', 'mysql')
                AND TABLE_TYPE = 'BASE TABLE'
            GROUP BY TABLE_SCHEMA
            HAVING size_mb > 0
            ORDER BY size_mb DESC
            """
            
            auth_context = get_auth_context()
            db_result = await connection.execute(db_sizes_sql, auth_context=auth_context)
            
            if not db_result.data:
                logger.warning("No database size information available")
                return []
            
            # Parse database-level data sizes
            db_sizes = []
            for row in db_result.data:
                db_name = row.get("db_name", "")
                size_mb = row.get("size_mb", 0)
                table_count = row.get("table_count", 0)
                
                # Ensure size_mb is a valid number
                try:
                    size_mb = float(size_mb) if size_mb is not None else 0.0
                except (ValueError, TypeError):
                    size_mb = 0.0
                
                # Ensure table_count is a valid number
                try:
                    table_count = int(table_count) if table_count is not None else 0
                except (ValueError, TypeError):
                    table_count = 0
                
                if db_name and size_mb > 0:
                    db_sizes.append({
                        "db_name": db_name,
                        "size_mb": size_mb,
                        "table_count": table_count,
                        "size_display": f"{size_mb:.2f}MB"
                    })
            
            if not db_sizes:
                logger.warning("No databases with data found")
                return []
            
            # Select top databases covering 85% of data
            selected_dbs = self._select_top_databases(db_sizes, target_coverage=0.85)
            logger.info(f"🎯 Stage 1 completed: Selected {len(selected_dbs['databases'])} databases covering {selected_dbs['coverage_percentage']:.1f}% of data")
            
            # Stage 2: Get table-level details for selected databases
            logger.info("📊 Stage 2: Getting table-level details for selected databases...")
            all_tables_sizes = []
            
            for db_info in selected_dbs['databases']:
                db_name = db_info['db_name']
                try:
                    # Get table details for this database using information_schema
                    table_details = await self._get_database_table_details_from_schema(connection, db_name)
                    all_tables_sizes.extend(table_details)
                    
                except Exception as e:
                    logger.warning(f"Failed to get table details for database {db_name}: {str(e)}")
                    continue
            
            # Sort by size descending, handle None values
            all_tables_sizes.sort(key=lambda x: x.get("size_mb", 0) or 0, reverse=True)
            logger.info(f"✅ Two-stage scan completed: {len(all_tables_sizes)} tables from {len(selected_dbs['databases'])} databases")
            
            return all_tables_sizes
            
        except Exception as e:
            logger.error(f"❌ Failed to get tables sizes fast: {str(e)}")
            return []
    
    def _select_top_databases(self, db_sizes: List[Dict], target_coverage: float = 0.85) -> Dict:
        """Select top databases that cover target percentage of total data"""
        if not db_sizes:
            return {"databases": [], "total_size_mb": 0, "selected_size_mb": 0, "coverage_percentage": 0}
        
        # Sort by size descending, handle None values
        db_sizes.sort(key=lambda x: x.get("size_mb", 0) or 0, reverse=True)
        
        total_size = sum(db["size_mb"] for db in db_sizes)
        target_size = total_size * target_coverage
        
        selected_databases = []
        selected_size = 0
        
        for db in db_sizes:
            selected_databases.append(db)
            selected_size += db["size_mb"]
            
            # Stop when we reach target coverage or have enough databases
            if selected_size >= target_size or len(selected_databases) >= 10:
                break
        
        coverage_percentage = (selected_size / total_size * 100) if total_size > 0 else 0
        
        return {
            "databases": selected_databases,
            "total_size_mb": total_size,
            "selected_size_mb": selected_size,
            "coverage_percentage": coverage_percentage
        }
    
    async def _get_database_table_details_from_schema(self, connection, db_name: str) -> List[Dict]:
        """Get table details for a specific database using information_schema"""
        try:
            # SECURITY FIX: Validate db_name and use parameterized query
            auth_context = get_auth_context()
            
            try:
                validate_identifier(db_name, "database name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid database name rejected: {e}")
                return []
            
            table_details_sql = """
            SELECT 
                TABLE_SCHEMA as schema_name,
                TABLE_NAME as table_name,
                COALESCE(ROUND((COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) / 1024 / 1024, 2), 0) as size_mb,
                COALESCE(TABLE_ROWS, 0) as row_count,
                CREATE_TIME as create_time,
                UPDATE_TIME as update_time
            FROM information_schema.tables 
            WHERE TABLE_SCHEMA = %s
                AND TABLE_TYPE = 'BASE TABLE'
                AND (COALESCE(DATA_LENGTH, 0) + COALESCE(INDEX_LENGTH, 0)) > 0
            ORDER BY size_mb DESC
            """
            
            result = await connection.execute(table_details_sql, params=(db_name,), auth_context=auth_context)
            
            if not result.data:
                logger.warning(f"No table details found for database {db_name}")
                return []
            
            table_details = []
            for row in result.data:
                schema_name = row.get("schema_name", "")
                table_name = row.get("table_name", "")
                size_mb = row.get("size_mb", 0)
                row_count = row.get("row_count", 0)
                
                # Ensure size_mb is a valid number
                try:
                    size_mb = float(size_mb) if size_mb is not None else 0.0
                except (ValueError, TypeError):
                    size_mb = 0.0
                
                # Ensure row_count is a valid number
                try:
                    row_count = int(row_count) if row_count is not None else 0
                except (ValueError, TypeError):
                    row_count = 0
                
                if table_name and size_mb > 0:
                    table_details.append({
                        "schema_name": schema_name,
                        "table_name": table_name,
                        "full_table_name": f"{schema_name}.{table_name}",
                        "size_mb": size_mb,
                        "row_count": row_count,
                        "size_display": f"{size_mb:.2f}MB",
                        "create_time": str(row.get("create_time", "")),
                        "update_time": str(row.get("update_time", ""))
                    })
            
            logger.info(f"📋 Found {len(table_details)} tables in database {db_name}")
            return table_details
            
        except Exception as e:
            logger.error(f"Failed to get table details for database {db_name}: {str(e)}")
            return []
    
    async def _get_database_table_details(self, connection, db_name: str) -> List[Dict]:
        """Get table details for a specific database using session-consistent queries"""
        try:
            # SECURITY FIX: Validate db_name before using in SQL
            try:
                validate_identifier(db_name, "database name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid database name rejected: {e}")
                return []
            
            # Method 1: Try to use session-consistent approach with raw connection
            # This requires accessing the underlying connection to maintain session state
            
            # First, try to get the raw connection if possible
            raw_conn = getattr(connection, '_connection', None) or getattr(connection, 'connection', None)
            
            if raw_conn:
                # Use raw connection to maintain session state
                cursor = await raw_conn.cursor()
                try:
                    # SECURITY FIX: Use quoted identifier for USE statement
                    quoted_db = quote_identifier(db_name, "database name")
                    await cursor.execute(f"USE {quoted_db}")
                    await cursor.execute("SHOW DATA")
                    
                    result = await cursor.fetchall()
                    columns = [desc[0] for desc in cursor.description]
                    
                    # Convert to dict format
                    table_data = []
                    for row in result:
                        row_dict = dict(zip(columns, row))
                        table_name = row_dict.get("TableName", "")
                        size_str = row_dict.get("Size", "")
                        
                        # Skip summary rows
                        if (table_name and size_str and 
                            table_name not in ["Total", "Quota", "Left", "Transaction Quota"]):
                            
                            size_mb = self._parse_size_to_mb(size_str)
                            if size_mb is not None and size_mb > 0:
                                table_data.append({
                                    "schema_name": db_name,
                                    "table_name": table_name,
                                    "size_mb": size_mb,
                                    "size_display": size_str
                                })
                    
                    await cursor.close()
                    return table_data
                    
                except Exception as e:
                    await cursor.close()
                    raise e
            
            # Method 2: Fallback to individual table queries
            logger.info(f"Using fallback method for database {db_name}")
            return await self._get_database_table_details_fallback(connection, db_name)
            
        except Exception as e:
            logger.warning(f"Failed to get table details for {db_name}: {str(e)}")
            return []
    
    async def _get_database_table_details_fallback(self, connection, db_name: str) -> List[Dict]:
        """Fallback method to get table details using individual queries"""
        try:
            # SECURITY FIX: Validate db_name and get auth_context
            auth_context = get_auth_context()
            
            try:
                validate_identifier(db_name, "database name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid database name rejected: {e}")
                return []
            
            # Get all tables in the database using quoted identifier
            quoted_db = quote_identifier(db_name, "database name")
            tables_sql = f"SHOW TABLES FROM {quoted_db}"
            tables_result = await connection.execute(tables_sql, auth_context=auth_context)
            
            if not tables_result.data:
                return []
            
            table_details = []
            for table_row in tables_result.data:
                table_name = table_row.get(f"Tables_in_{db_name}", "") or table_row.get("table_name", "")
                if table_name:
                    try:
                        # SECURITY FIX: Validate table_name and use safe reference
                        validate_identifier(table_name, "table name")
                        safe_table_ref = build_table_reference(table_name, db_name)
                        data_sql = f"SHOW DATA FROM {safe_table_ref}"
                        data_result = await connection.execute(data_sql, auth_context=auth_context)
                        
                        if data_result.data:
                            for row in data_result.data:
                                if row.get("TableName") == table_name:
                                    size_str = row.get("Size", "")
                                    if size_str:
                                        size_mb = self._parse_size_to_mb(size_str)
                                        if size_mb is not None and size_mb > 0:
                                            table_details.append({
                                                "schema_name": db_name,
                                                "table_name": table_name,
                                                "size_mb": size_mb,
                                                "size_display": size_str
                                            })
                                        break
                    except Exception as table_e:
                        logger.warning(f"Failed to get size for table {db_name}.{table_name}: {str(table_e)}")
                        continue
            
            return table_details
            
        except Exception as e:
            logger.warning(f"Fallback method failed for database {db_name}: {str(e)}")
            return []
    
    def _parse_size_to_mb(self, size_str: str) -> float:
        """Parse size string to MB"""
        try:
            if not size_str:
                return 0.0
            
            size_str = size_str.strip().upper()
            if not size_str or size_str == "--" or size_str == "0.000":
                return 0.0
            
            # Extract number and unit
            import re
            match = re.match(r'^([\d.]+)\s*([KMGT]?B?)$', size_str)
            if not match:
                return 0.0
            
            value = float(match.group(1))
            unit = match.group(2)
            
            # Convert to MB
            if unit in ['B', '']:
                return value / (1024 * 1024)
            elif unit in ['KB', 'K']:
                return value / 1024
            elif unit in ['MB', 'M']:
                return value
            elif unit in ['GB', 'G']:
                return value * 1024
            elif unit in ['TB', 'T']:
                return value * 1024 * 1024
            else:
                return 0.0
                
        except Exception as e:
            logger.warning(f"Failed to parse size string '{size_str}': {str(e)}")
            return 0.0
    
    async def _select_high_impact_tables(self, all_tables_sizes: List[Dict], target_coverage: float = 0.8) -> Dict:
        """Select high-impact tables that cover target percentage of total data"""
        if not all_tables_sizes:
            return {"tables": [], "total_cluster_size_mb": 0, "total_selected_size_mb": 0, "coverage_percentage": 0}
        
        # Filter out tables with None or invalid size_mb
        valid_tables = [table for table in all_tables_sizes if table.get("size_mb") is not None and table.get("size_mb", 0) > 0]
        
        if not valid_tables:
            return {"tables": [], "total_cluster_size_mb": 0, "total_selected_size_mb": 0, "coverage_percentage": 0}
        
        total_size = sum(table["size_mb"] for table in valid_tables)
        target_size = total_size * target_coverage
        
        selected_tables = []
        selected_size = 0
        
        for table in valid_tables:
            selected_tables.append(table)
            selected_size += table["size_mb"]
            
            # Stop when we reach target coverage or have enough tables for analysis
            if selected_size >= target_size or len(selected_tables) >= 20:
                break
        
        coverage_percentage = (selected_size / total_size * 100) if total_size > 0 else 0
        
        return {
            "tables": selected_tables,
            "total_cluster_size_mb": total_size,
            "total_selected_size_mb": selected_size,
            "coverage_percentage": coverage_percentage
        }

    async def _get_all_tables_info(self, connection) -> List[Dict]:
        """Get basic information for all tables (fallback method)"""
        try:
            auth_context = get_auth_context()
            tables_sql = """
            SELECT 
                table_schema,
                table_name,
                table_rows,
                data_length,
                index_length,
                (data_length + index_length) as total_size,
                create_time,
                update_time,
                engine
            FROM information_schema.tables
            WHERE table_type = 'BASE TABLE'
                AND (data_length > 0 OR table_rows > 0)
            ORDER BY (data_length + index_length) DESC
            """
            
            result = await connection.execute(tables_sql, auth_context=auth_context)
            return result.data if result.data else []
            
        except Exception as e:
            logger.warning(f"Failed to get tables info: {str(e)}")
            return []
    
    async def _analyze_single_table_storage_growth(
        self, connection, full_table_name: str, table_name: str, schema_name: str, days: int
    ) -> Optional[Dict]:
        """Analyze storage growth for a single table"""
        try:
            # Get current table size
            current_size = await self._get_current_table_size(connection, full_table_name)
            if not current_size:
                return None
            
            # Try multiple methods to get historical data
            historical_data = []
            data_source = "unknown"
            
            # Method 1: Partition-based historical data
            partition_data = await self._get_partition_based_growth_data(
                connection, table_name, schema_name, days
            )
            if partition_data:
                historical_data = partition_data
                data_source = "partition_based"
            
            # Method 2: Timestamp field-based historical data
            if not historical_data:
                timestamp_data = await self._get_timestamp_based_growth_data(
                    connection, full_table_name, table_name, schema_name, days
                )
                if timestamp_data:
                    historical_data = timestamp_data
                    data_source = "timestamp_based"
            
            # Method 3: Audit log-based growth estimation
            if not historical_data:
                audit_data = await self._get_audit_based_growth_estimation(
                    connection, table_name, days
                )
                if audit_data:
                    historical_data = audit_data
                    data_source = "audit_log_based"
            
            # Calculate growth rate
            growth_metrics = self._calculate_table_growth_metrics(historical_data, current_size)
            
            return {
                "table_name": full_table_name,
                "current_size_mb": current_size["size_mb"],
                "current_rows": current_size["rows"],
                "data_source": data_source,
                "historical_data": historical_data,
                "growth_metrics": growth_metrics,
                "analysis_period_days": days
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze growth for table {full_table_name}: {str(e)}")
            return None
    
    async def _get_current_table_size(self, connection, full_table_name: str) -> Optional[Dict]:
        """Get current table size"""
        try:
            # SECURITY FIX: Get auth_context and use parameterized query
            auth_context = get_auth_context()
            
            # Extract table name for parameterized query
            table_name_only = full_table_name.split('.')[-1] if '.' in full_table_name else full_table_name
            
            # Validate identifiers
            try:
                validate_identifier(table_name_only, "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return None
            
            # Use parameterized query for safety
            size_sql = """
            SELECT 
                COALESCE(ROUND((COALESCE(data_length, 0) + COALESCE(index_length, 0)) / 1024 / 1024, 2), 0) as size_mb,
                COALESCE(table_rows, 0) as `rows`
            FROM information_schema.tables
            WHERE CONCAT(table_schema, '.', table_name) = %s
                OR table_name = %s
            """
            
            result = await connection.execute(size_sql, params=(full_table_name, table_name_only), auth_context=auth_context)
            if result.data and result.data[0]:
                return result.data[0]
            
            # If information_schema has no data, try COUNT query
            # full_table_name should already be validated by caller using build_table_reference
            count_sql = f"SELECT COUNT(*) as rows FROM {full_table_name}"
            count_result = await connection.execute(count_sql, auth_context=auth_context)
            if count_result.data:
                return {
                    "size_mb": 0,  # Cannot get exact size
                    "rows": count_result.data[0]["rows"]
                }
            
            return None
            
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed for {full_table_name}: {str(e)}")
            return None
        except Exception as e:
            logger.warning(f"Failed to get current size for {full_table_name}: {str(e)}")
            return None
    
    async def _get_partition_based_growth_data(
        self, connection, table_name: str, schema_name: str, days: int
    ) -> List[Dict]:
        """Get historical growth data based on partitions"""
        try:
            # SECURITY FIX: Validate identifiers and use parameterized query
            auth_context = get_auth_context()
            
            try:
                validate_identifier(table_name, "table name")
                if schema_name:
                    validate_identifier(schema_name, "schema name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid identifier rejected: {e}")
                return []
            
            # Use parameterized query for safety
            partition_sql = """
            SELECT 
                partition_name,
                partition_description,
                table_rows,
                data_length,
                create_time
            FROM information_schema.partitions
            WHERE table_schema = %s
                AND table_name = %s
                AND partition_name IS NOT NULL
                AND create_time IS NOT NULL
                AND create_time >= DATE_SUB(NOW(), INTERVAL %s DAY)
            ORDER BY create_time DESC
            """
            
            result = await connection.execute(
                partition_sql, 
                params=(schema_name or "", table_name, days),
                auth_context=auth_context
            )
            if not result.data:
                return []
            
            # Process partition data, aggregate by date
            daily_data = defaultdict(lambda: {"rows": 0, "size_mb": 0})
            
            for partition in result.data:
                create_date = partition["create_time"]
                if isinstance(create_date, str):
                    create_date = datetime.fromisoformat(create_date.replace('Z', '+00:00'))
                
                date_key = create_date.date().isoformat()
                table_rows = partition.get("table_rows", 0) or 0
                data_length = partition.get("data_length", 0) or 0
                daily_data[date_key]["rows"] += table_rows
                daily_data[date_key]["size_mb"] += (data_length / 1024 / 1024)
            
            # Convert to list format
            historical_data = []
            for date_str, data in sorted(daily_data.items()):
                historical_data.append({
                    "date": date_str,
                    "rows": data["rows"],
                    "size_mb": round(data["size_mb"], 2),
                    "data_source": "partition_create_time"
                })
            
            return historical_data
            
        except Exception as e:
            logger.warning(f"Failed to get partition-based growth data: {str(e)}")
            return []
    
    async def _get_timestamp_based_growth_data(
        self, connection, full_table_name: str, table_name: str, schema_name: str, days: int
    ) -> List[Dict]:
        """Get historical growth data based on timestamp fields"""
        try:
            # SECURITY FIX: Get auth_context
            auth_context = get_auth_context()
            
            # Find possible timestamp fields
            timestamp_columns = await self._find_timestamp_columns(connection, table_name, schema_name)
            if not timestamp_columns:
                return []
            
            # Use best timestamp field for analysis
            time_column = timestamp_columns[0]
            
            # SECURITY FIX: Validate time_column before using in SQL
            try:
                validate_identifier(time_column, "column name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid column name rejected: {e}")
                return []
            
            quoted_time_column = quote_identifier(time_column, "column name")
            
            # Aggregate data by date (full_table_name should be validated by caller)
            growth_sql = f"""
            SELECT 
                DATE({quoted_time_column}) as date,
                COUNT(*) as daily_records,
                COUNT(*) / SUM(COUNT(*)) OVER() * 100 as percentage
            FROM {full_table_name}
            WHERE {quoted_time_column} >= DATE_SUB(NOW(), INTERVAL %s DAY)
                AND {quoted_time_column} IS NOT NULL
            GROUP BY DATE({quoted_time_column})
            ORDER BY date DESC
            """
            
            result = await connection.execute(growth_sql, params=(days,), auth_context=auth_context)
            if not result.data:
                return []
            
            # Calculate cumulative growth
            cumulative_rows = 0
            historical_data = []
            
            for row in reversed(result.data):  # Start from earliest date
                cumulative_rows += row["daily_records"]
                historical_data.append({
                    "date": row["date"].isoformat() if hasattr(row["date"], 'isoformat') else str(row["date"]),
                    "daily_records": row["daily_records"],
                    "cumulative_rows": cumulative_rows,
                    "data_source": f"timestamp_field_{time_column}"
                })
            
            return list(reversed(historical_data))  # Return with latest date first
            
        except Exception as e:
            logger.warning(f"Failed to get timestamp-based growth data: {str(e)}")
            return []
    
    async def _find_timestamp_columns(self, connection, table_name: str, schema_name: str) -> List[str]:
        """Find timestamp fields in table"""
        try:
            # SECURITY FIX: Validate identifiers and use parameterized query
            auth_context = get_auth_context()
            
            try:
                validate_identifier(table_name, "table name")
                if schema_name:
                    validate_identifier(schema_name, "schema name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid identifier rejected: {e}")
                return []
            
            timestamp_sql = """
            SELECT column_name, data_type
            FROM information_schema.columns
            WHERE table_schema = %s
                AND table_name = %s
                AND (
                    data_type IN ('datetime', 'timestamp', 'date')
                    OR column_name REGEXP '(create|insert|update|modify).*time'
                    OR column_name REGEXP '.*date'
                    OR column_name REGEXP '(created|updated|modified)_(at|on)'
                )
            ORDER BY 
                CASE 
                    WHEN column_name REGEXP '(create|insert).*time' THEN 1
                    WHEN column_name REGEXP 'update.*time' THEN 2
                    WHEN data_type IN ('datetime', 'timestamp') THEN 3
                    WHEN data_type = 'date' THEN 4
                    ELSE 5
                END
            """
            
            result = await connection.execute(
                timestamp_sql, 
                params=(schema_name or "", table_name),
                auth_context=auth_context
            )
            return [row["column_name"] for row in result.data] if result.data else []
            
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed: {str(e)}")
            return []
        except Exception as e:
            logger.warning(f"Failed to find timestamp columns: {str(e)}")
            return []
    
    async def _get_audit_based_growth_estimation(
        self, connection, table_name: str, days: int
    ) -> List[Dict]:
        """Estimate growth data based on audit logs"""
        try:
            # SECURITY FIX: Validate table_name and use parameterized query
            auth_context = get_auth_context()
            
            try:
                validate_identifier(table_name.split(".")[-1], "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return []
            
            # Extract just the table name for LIKE pattern
            table_name_only = table_name.split(".")[-1]
            like_pattern_full = f"%{table_name}%"
            like_pattern_short = f"%{table_name_only}%"
            
            # Analyze operation history for this table
            audit_sql = """
            SELECT 
                DATE(`time`) as operation_date,
                COUNT(*) as operation_count,
                SUM(CASE WHEN stmt LIKE 'INSERT%' THEN 1 ELSE 0 END) as insert_count,
                SUM(CASE WHEN stmt LIKE 'UPDATE%' THEN 1 ELSE 0 END) as update_count,
                SUM(CASE WHEN stmt LIKE 'DELETE%' THEN 1 ELSE 0 END) as delete_count
            FROM internal.__internal_schema.audit_log
            WHERE `time` >= DATE_SUB(NOW(), INTERVAL %s DAY)
                AND stmt IS NOT NULL
                AND (
                    stmt LIKE %s
                    OR stmt LIKE %s
                )
            GROUP BY DATE(`time`)
            ORDER BY operation_date DESC
            """
            
            result = await connection.execute(
                audit_sql, 
                params=(days, like_pattern_full, like_pattern_short),
                auth_context=auth_context
            )
            if not result.data:
                return []
            
            # Estimate growth based on operation patterns
            historical_data = []
            for row in result.data:
                # Simple growth estimation: INSERT operations indicate data growth
                estimated_growth = row["insert_count"] * 1000  # Assume each INSERT operation inserts 1000 rows on average
                
                historical_data.append({
                    "date": row["operation_date"].isoformat() if hasattr(row["operation_date"], 'isoformat') else str(row["operation_date"]),
                    "operation_count": row["operation_count"],
                    "insert_operations": row["insert_count"],
                    "estimated_records_added": estimated_growth,
                    "data_source": "audit_log_estimation"
                })
            
            return historical_data
            
        except Exception as e:
            logger.warning(f"Failed to get audit-based growth estimation: {str(e)}")
            return []
    
    def _calculate_table_growth_metrics(self, historical_data: List[Dict], current_size: Dict) -> Dict[str, Any]:
        """Calculate table growth metrics"""
        if not historical_data or len(historical_data) < 2:
            return {
                "growth_rate_mb_per_day": 0,
                "growth_rate_rows_per_day": 0,
                "growth_trend": "insufficient_data",
                "confidence": "low"
            }
        
        try:
            # Extract numerical data
            dates = []
            sizes = []
            rows = []
            
            for data_point in historical_data:
                try:
                    date_obj = datetime.fromisoformat(data_point["date"])
                    dates.append(date_obj)
                    
                    # Handle fields from different data sources
                    if "size_mb" in data_point:
                        sizes.append(data_point["size_mb"])
                    if "cumulative_rows" in data_point:
                        rows.append(data_point["cumulative_rows"])
                    elif "rows" in data_point:
                        rows.append(data_point["rows"])
                    elif "estimated_records_added" in data_point:
                        rows.append(data_point["estimated_records_added"])
                        
                except (ValueError, KeyError):
                    continue
            
            if len(dates) < 2:
                return {"growth_rate_mb_per_day": 0, "growth_rate_rows_per_day": 0, "growth_trend": "insufficient_data"}
            
            # Calculate time span (days)
            time_span_days = (max(dates) - min(dates)).days
            if time_span_days == 0:
                time_span_days = 1
            
            # Calculate growth rate
            growth_metrics = {}
            
            # Size growth rate
            if len(sizes) >= 2:
                size_growth = (max(sizes) - min(sizes)) / time_span_days
                growth_metrics["growth_rate_mb_per_day"] = round(size_growth, 4)
            else:
                growth_metrics["growth_rate_mb_per_day"] = 0
            
            # Row count growth rate
            if len(rows) >= 2:
                rows_growth = (max(rows) - min(rows)) / time_span_days
                growth_metrics["growth_rate_rows_per_day"] = round(rows_growth, 2)
            else:
                growth_metrics["growth_rate_rows_per_day"] = 0
            
            # Growth trend analysis
            if len(historical_data) >= 3:
                # Use linear regression to analyze trends
                growth_metrics["growth_trend"] = self._analyze_growth_trend(dates, sizes if sizes else rows)
                growth_metrics["confidence"] = "high" if len(historical_data) >= 7 else "medium"
            else:
                growth_metrics["growth_trend"] = "stable"
                growth_metrics["confidence"] = "low"
            
            return growth_metrics
            
        except Exception as e:
            logger.warning(f"Failed to calculate growth metrics: {str(e)}")
            return {"growth_rate_mb_per_day": 0, "growth_rate_rows_per_day": 0, "growth_trend": "error"}
    
    def _analyze_growth_trend(self, dates: List[datetime], values: List[float]) -> str:
        """Analyze growth trend"""
        if len(dates) != len(values) or len(values) < 3:
            return "unknown"
        
        try:
            # Convert dates to numerical values (days)
            base_date = min(dates)
            x_values = [(date - base_date).days for date in dates]
            
            # Simple linear regression
            n = len(x_values)
            sum_x = sum(x_values)
            sum_y = sum(values)
            sum_xy = sum(x * y for x, y in zip(x_values, values))
            sum_x2 = sum(x * x for x in x_values)
            
            # Calculate slope
            denominator = n * sum_x2 - sum_x * sum_x
            if denominator == 0:
                return "stable"
            
            slope = (n * sum_xy - sum_x * sum_y) / denominator
            
            # Determine trend
            if slope > 0.1:
                return "increasing"
            elif slope < -0.1:
                return "decreasing"
            else:
                return "stable"
                
        except Exception:
            return "unknown"
    
    async def _calculate_overall_storage_growth(self, table_growth_data: List[Dict], days: int) -> Dict[str, Any]:
        """Calculate overall storage growth"""
        if not table_growth_data:
            return {"error": "No table growth data available"}
        
        try:
            # Aggregate growth data from all tables
            total_growth_mb_per_day = sum(
                table.get("growth_metrics", {}).get("growth_rate_mb_per_day", 0)
                for table in table_growth_data
            )
            
            total_growth_rows_per_day = sum(
                table.get("growth_metrics", {}).get("growth_rate_rows_per_day", 0)
                for table in table_growth_data
            )
            
            # Calculate growth trend distribution
            trend_counts = Counter(
                table.get("growth_metrics", {}).get("growth_trend", "unknown")
                for table in table_growth_data
            )
            
            # Calculate confidence level
            high_confidence_tables = sum(
                1 for table in table_growth_data
                if table.get("growth_metrics", {}).get("confidence") == "high"
            )
            
            overall_confidence = "high" if high_confidence_tables > len(table_growth_data) * 0.5 else "medium"
            
            return {
                "daily_growth_mb": round(total_growth_mb_per_day, 2),
                "daily_growth_rows": round(total_growth_rows_per_day, 2),
                "monthly_growth_mb": round(total_growth_mb_per_day * 30, 2),
                "monthly_growth_rows": round(total_growth_rows_per_day * 30, 2),
                "trend_distribution": dict(trend_counts),
                "overall_trend": trend_counts.most_common(1)[0][0] if trend_counts else "unknown",
                "confidence_level": overall_confidence,
                "analysis_method": "aggregated_real_data"
            }
            
        except Exception as e:
            logger.error(f"Failed to calculate overall storage growth: {str(e)}")
            return {"error": str(e)}
    
    def _calculate_storage_confidence_level(self, table_growth_data: List[Dict]) -> str:
        """Calculate confidence level for storage analysis"""
        if not table_growth_data:
            return "none"
        
        # Count tables with historical data
        tables_with_data = sum(
            1 for table in table_growth_data
            if table.get("historical_data") and len(table.get("historical_data", [])) > 0
        )
        
        # Count tables with high confidence
        high_confidence_tables = sum(
            1 for table in table_growth_data
            if table.get("growth_metrics", {}).get("confidence") == "high"
        )
        
        total_tables = len(table_growth_data)
        
        if high_confidence_tables > total_tables * 0.7:
            return "high"
        elif tables_with_data > total_tables * 0.5:
            return "medium"
        else:
            return "low"
    
    async def _generate_enhanced_growth_insights(self, resource_analysis: Dict, days: int) -> Dict[str, Any]:
        """Generate enhanced growth insights"""
        insights = {}
        
        # Storage insights
        if "storage" in resource_analysis:
            storage = resource_analysis["storage"]
            if "overall_growth_metrics" in storage:
                metrics = storage["overall_growth_metrics"]
                insights["storage"] = {
                    "current_status": f"Total storage: {storage.get('current_total_storage_mb', 0):.2f} MB",
                    "growth_rate": f"Daily growth: {metrics.get('daily_growth_mb', 0):.2f} MB",
                    "monthly_projection": f"Monthly growth estimate: {metrics.get('monthly_growth_mb', 0):.2f} MB",
                    "trend": metrics.get("overall_trend", "unknown"),
                    "confidence": metrics.get("confidence_level", "unknown"),
                    "analysis_quality": f"Based on real historical data from {storage.get('total_tables_analyzed', 0)} tables"
                }
        
        # Query volume insights (keep original logic as it's already based on real data)
        if "query_volume" in resource_analysis:
            query_vol = resource_analysis["query_volume"]
            insights["query_volume"] = {
                "avg_daily_queries": query_vol.get("avg_daily_queries", 0),
                "trend": query_vol.get("trend", "stable"),
                "analysis_period": f"{days} days of historical data"
            }
        
        # User activity insights (keep original logic)
        if "user_activity" in resource_analysis:
            user_activity = resource_analysis["user_activity"]
            insights["user_activity"] = {
                "avg_daily_users": user_activity.get("avg_daily_active_users", 0),
                "max_daily_users": user_activity.get("max_daily_users", 0),
                "analysis_period": f"{days} days of historical data"
            }
        
        return insights
    
    async def _generate_statistical_growth_predictions(self, resource_analysis: Dict, days: int) -> Dict[str, Any]:
        """Generate growth predictions based on statistical methods"""
        predictions = {}
        
        try:
            # Storage predictions
            if "storage" in resource_analysis:
                storage = resource_analysis["storage"]
                if "overall_growth_metrics" in storage:
                    metrics = storage["overall_growth_metrics"]
                    daily_growth = metrics.get("daily_growth_mb", 0)
                    confidence = metrics.get("confidence_level", "low")
                    
                    # Make predictions based on real growth rates
                    predictions["storage"] = {
                        "next_30_days_mb": round(daily_growth * 30, 2),
                        "next_90_days_mb": round(daily_growth * 90, 2),
                        "next_365_days_mb": round(daily_growth * 365, 2),
                        "prediction_method": "linear_extrapolation_from_real_data",
                        "confidence": confidence,
                        "warning": "Predictions based on historical trends, actual growth may vary due to business changes"
                    }
            
            # Query volume predictions
            if "query_volume" in resource_analysis:
                query_vol = resource_analysis["query_volume"]
                avg_queries = query_vol.get("avg_daily_queries", 0)
                trend = query_vol.get("trend", "stable")
                
                # Adjust predictions based on trends
                growth_factor = 1.0
                if trend == "increasing":
                    growth_factor = 1.1  # 10% growth
                elif trend == "decreasing":
                    growth_factor = 0.9   # 10% decline
                
                predictions["query_volume"] = {
                    "next_30_days_avg": round(avg_queries * growth_factor, 2),
                    "prediction_method": "trend_based_extrapolation",
                    "confidence": "medium"
                }
            
            return predictions
            
        except Exception as e:
            logger.error(f"Failed to generate statistical predictions: {str(e)}")
            return {"error": str(e)}
    
    def _generate_enhanced_growth_recommendations(self, growth_insights: Dict, predictions: Dict) -> List[Dict]:
        """Generate enhanced growth recommendations"""
        recommendations = []
        
        try:
            # Storage-related recommendations
            if "storage" in growth_insights:
                storage_insight = growth_insights["storage"]
                confidence = storage_insight.get("confidence", "low")
                trend = storage_insight.get("trend", "unknown")
                
                if confidence == "high" and trend == "increasing":
                    recommendations.append({
                        "category": "storage_capacity",
                        "priority": "high",
                        "title": "Storage Capacity Planning",
                        "description": "Based on real historical data analysis, storage shows significant growth trend",
                        "action": "Recommend advance storage expansion planning, consider data archiving strategies"
                    })
                
                if "storage" in predictions:
                    storage_pred = predictions["storage"]
                    yearly_growth = storage_pred.get("next_365_days_mb", 0)
                    if yearly_growth > 100000:  # 100GB
                        recommendations.append({
                            "category": "storage_optimization",
                            "priority": "medium",
                            "title": "Data Compression Optimization",
                            "description": f"Expected annual growth {yearly_growth/1024:.1f} GB",
                            "action": "Consider enabling data compression and optimizing storage formats"
                        })
            
            # Data quality recommendations
            recommendations.append({
                "category": "data_monitoring",
                "priority": "medium",
                "title": "Continuous Monitoring",
                "description": "Establish growth monitoring system based on real historical data",
                "action": "Regularly analyze partition growth and timestamp field distribution, detect abnormal growth promptly"
            })
            
            return recommendations
            
        except Exception as e:
            logger.error(f"Failed to generate enhanced recommendations: {str(e)}")
            return []
    
    def _generate_performance_recommendations(self, performance_insights: Dict, pattern_analysis: Dict) -> List[Dict]:
        """Generate performance improvement recommendations"""
        recommendations = []
        
        # Execution time recommendations
        exec_stats = performance_insights.get("execution_time_stats", {})
        avg_time = exec_stats.get("avg_ms", 0)
        
        if avg_time > 30000:  # > 30 seconds
            recommendations.append({
                "type": "query_optimization",
                "priority": "high",
                "title": "High average query execution time",
                "description": f"Average slow query time is {avg_time/1000:.1f} seconds",
                "action": "Review and optimize slowest queries, consider indexing strategies"
            })
        
        # Pattern-based recommendations
        if pattern_analysis:
            common_issues = pattern_analysis.get("common_performance_issues", {})
            
            if common_issues.get("select_all_columns", 0) > 5:
                recommendations.append({
                    "type": "query_best_practices",
                    "priority": "medium",
                    "title": "Frequent SELECT * usage detected",
                    "description": "Many queries use SELECT * which can impact performance",
                    "action": "Replace SELECT * with specific column names in queries"
                })
            
            if common_issues.get("large_data_scan", 0) > 3:
                recommendations.append({
                    "type": "data_access_optimization",
                    "priority": "high",
                    "title": "Large data scans detected",
                    "description": "Multiple queries are scanning large amounts of data",
                    "action": "Review partitioning strategies and add appropriate indexes"
                })
        
        return recommendations 
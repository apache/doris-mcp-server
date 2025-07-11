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
        Analyze resource growth patterns and trends
        
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
                resource_analysis["storage"] = await self._analyze_storage_growth(connection, days, detailed_response)
            
            if "query_volume" in resource_types:
                resource_analysis["query_volume"] = await self._analyze_query_volume_growth(connection, days, detailed_response)
            
            if "user_activity" in resource_types:
                resource_analysis["user_activity"] = await self._analyze_user_activity_growth(connection, days, detailed_response)
            
            # Generate growth insights
            growth_insights = await self._generate_growth_insights(resource_analysis, days)
            
            # Growth predictions
            predictions = {}
            if include_predictions:
                predictions = await self._generate_growth_predictions(resource_analysis)
            
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
                "recommendations": self._generate_growth_recommendations(growth_insights, predictions)
            }
            
            # Add execution info for debugging
            result["_execution_info"] = {
                "tool_name": "analyze_resource_growth_curves",
                "execution_time": round(execution_time, 3),
                "timestamp": datetime.now().isoformat(),
                "detailed_response": detailed_response
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Resource growth analysis failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    # ==================== Private Helper Methods ====================
    
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
            ORDER BY `query_time` DESC
            LIMIT 5000
            """
            
            result = await connection.execute(slow_query_sql)
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
    
    async def _analyze_storage_growth(self, connection, days: int, detailed_response: bool = False) -> Dict[str, Any]:
        """Analyze storage growth patterns"""
        try:
            # Get table size data over time
            # This is a simplified approach - in practice you'd need historical data
            size_sql = """
            SELECT 
                table_schema,
                table_name,
                ROUND(data_length / 1024 / 1024, 2) as size_mb,
                table_rows
            FROM information_schema.tables
            WHERE table_type = 'BASE TABLE'
                AND data_length > 0
            ORDER BY data_length DESC
            LIMIT 50
            """
            
            result = await connection.execute(size_sql)
            
            if result.data:
                total_size = sum(row.get("size_mb", 0) for row in result.data)
                total_rows = sum(row.get("table_rows", 0) for row in result.data)
                
                # Estimate growth (simplified - would need historical data for real analysis)
                growth_estimate = self._estimate_storage_growth(result.data)
                
                storage_result = {
                    "current_storage_mb": round(total_size, 2),
                    "total_rows": total_rows,
                    "table_count": len(result.data),
                    "estimated_growth": growth_estimate,
                    "growth_trend": "stable"  # Simplified
                }
                
                # Include detailed table information only if requested
                if detailed_response:
                    storage_result["largest_tables"] = result.data[:10]
                else:
                    # Only include top 3 for summary
                    storage_result["top_tables_summary"] = result.data[:3]
                
                return storage_result
            
            return {"current_storage_mb": 0, "message": "No storage data available"}
            
        except Exception as e:
            logger.warning(f"Failed to analyze storage growth: {str(e)}")
            return {"error": str(e)}
    
    def _estimate_storage_growth(self, table_data: List[Dict]) -> Dict[str, Any]:
        """Estimate storage growth based on current data"""
        # This is a simplified estimation - real implementation would use historical data
        total_size = sum(row.get("size_mb", 0) for row in table_data)
        
        return {
            "daily_growth_estimate_mb": round(total_size * 0.01, 2),  # 1% daily growth estimate
            "monthly_growth_estimate_mb": round(total_size * 0.3, 2),  # 30% monthly growth estimate
            "confidence": "low",  # Low confidence without historical data
            "method": "simplified_estimation"
        }
    
    async def _analyze_query_volume_growth(self, connection, days: int, detailed_response: bool = False) -> Dict[str, Any]:
        """Analyze query volume growth patterns"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            
            volume_sql = f"""
            SELECT 
                DATE(`time`) as query_date,
                COUNT(*) as query_count,
                COUNT(DISTINCT `user`) as unique_users
            FROM internal.__internal_schema.audit_log 
            WHERE `time` >= '{start_date.strftime('%Y-%m-%d')}'
                AND `stmt` IS NOT NULL
            GROUP BY DATE(`time`)
            ORDER BY query_date DESC
            LIMIT {days}
            """
            
            result = await connection.execute(volume_sql)
            
            if result.data:
                daily_volumes = [row.get("query_count", 0) for row in result.data]
                avg_daily_queries = statistics.mean(daily_volumes) if daily_volumes else 0
                
                # Simple trend analysis
                trend = "stable"
                if len(daily_volumes) > 3:
                    recent_avg = statistics.mean(daily_volumes[:3])
                    older_avg = statistics.mean(daily_volumes[-3:])
                    if recent_avg > older_avg * 1.1:
                        trend = "increasing"
                    elif recent_avg < older_avg * 0.9:
                        trend = "decreasing"
                
                volume_result = {
                    "avg_daily_queries": round(avg_daily_queries, 2),
                    "max_daily_queries": max(daily_volumes) if daily_volumes else 0,
                    "min_daily_queries": min(daily_volumes) if daily_volumes else 0,
                    "total_queries": sum(daily_volumes) if daily_volumes else 0,
                    "trend": trend
                }
                
                # Include detailed daily data only if requested
                if detailed_response:
                    # Fix date serialization in daily_data
                    serializable_data = []
                    for row in result.data:
                        serializable_row = {}
                        for key, value in row.items():
                            if hasattr(value, 'isoformat'):  # datetime/date object
                                serializable_row[key] = value.isoformat()
                            else:
                                serializable_row[key] = value
                        serializable_data.append(serializable_row)
                    volume_result["daily_data"] = serializable_data
                else:
                    # Only include recent data summary
                    volume_result["recent_days_summary"] = {
                        "last_7_days_avg": round(statistics.mean(daily_volumes[:7]) if len(daily_volumes) >= 7 else avg_daily_queries, 2),
                        "data_points": min(len(daily_volumes), 7)
                    }
                
                return volume_result
            
            return {"avg_daily_queries": 0, "message": "No query volume data available"}
            
        except Exception as e:
            logger.warning(f"Failed to analyze query volume growth: {str(e)}")
            return {"error": str(e)}
    
    async def _analyze_user_activity_growth(self, connection, days: int, detailed_response: bool = False) -> Dict[str, Any]:
        """Analyze user activity growth patterns"""
        try:
            start_date = datetime.now() - timedelta(days=days)
            
            activity_sql = f"""
            SELECT 
                DATE(`time`) as activity_date,
                COUNT(DISTINCT `user`) as active_users,
                COUNT(*) as total_queries
            FROM internal.__internal_schema.audit_log 
            WHERE `time` >= '{start_date.strftime('%Y-%m-%d')}'
                AND `stmt` IS NOT NULL
            GROUP BY DATE(`time`)
            ORDER BY activity_date DESC
            LIMIT {days}
            """
            
            result = await connection.execute(activity_sql)
            
            if result.data:
                daily_users = [row.get("active_users", 0) for row in result.data]
                avg_daily_users = statistics.mean(daily_users) if daily_users else 0
                
                activity_result = {
                    "avg_daily_active_users": round(avg_daily_users, 2),
                    "max_daily_users": max(daily_users) if daily_users else 0,
                    "total_unique_users": len(set(row.get("active_users", 0) for row in result.data))
                }
                
                # Include detailed daily activity only if requested
                if detailed_response:
                    # Fix date serialization in daily_activity
                    serializable_activity = []
                    for row in result.data:
                        serializable_row = {}
                        for key, value in row.items():
                            if hasattr(value, 'isoformat'):  # datetime/date object
                                serializable_row[key] = value.isoformat()
                            else:
                                serializable_row[key] = value
                        serializable_activity.append(serializable_row)
                    activity_result["daily_activity"] = serializable_activity
                else:
                    # Only include recent activity summary
                    recent_queries = [row.get("total_queries", 0) for row in result.data[:7]]
                    activity_result["recent_activity_summary"] = {
                        "last_7_days_avg_queries": round(statistics.mean(recent_queries) if recent_queries else 0, 2),
                        "activity_trend": "active" if avg_daily_users > 1 else "low"
                    }
                
                return activity_result
            
            return {"avg_daily_active_users": 0, "message": "No user activity data available"}
            
        except Exception as e:
            logger.warning(f"Failed to analyze user activity growth: {str(e)}")
            return {"error": str(e)}
    
    async def _generate_growth_insights(self, resource_analysis: Dict, days: int) -> Dict[str, Any]:
        """Generate insights from resource growth analysis"""
        insights = {}
        
        # Storage insights
        if "storage" in resource_analysis:
            storage = resource_analysis["storage"]
            if "current_storage_mb" in storage:
                insights["storage"] = {
                    "current_size_gb": round(storage["current_storage_mb"] / 1024, 2),
                    "growth_rate": storage.get("estimated_growth", {}).get("daily_growth_estimate_mb", 0),
                    "capacity_concern": storage["current_storage_mb"] > 10000  # > 10GB
                }
        
        # Query volume insights
        if "query_volume" in resource_analysis:
            volume = resource_analysis["query_volume"]
            insights["query_volume"] = {
                "daily_average": volume.get("avg_daily_queries", 0),
                "load_level": "high" if volume.get("avg_daily_queries", 0) > 1000 else "normal",
                "trend": volume.get("trend", "stable")
            }
        
        # User activity insights
        if "user_activity" in resource_analysis:
            activity = resource_analysis["user_activity"]
            insights["user_activity"] = {
                "active_user_base": activity.get("avg_daily_active_users", 0),
                "user_engagement": "high" if activity.get("avg_daily_active_users", 0) > 10 else "normal"
            }
        
        return insights
    
    async def _generate_growth_predictions(self, resource_analysis: Dict) -> Dict[str, Any]:
        """Generate growth predictions (simplified)"""
        predictions = {}
        
        # This is a simplified prediction model
        # Real implementation would use time series analysis
        
        if "storage" in resource_analysis:
            storage = resource_analysis["storage"]
            current_size = storage.get("current_storage_mb", 0)
            daily_growth = storage.get("estimated_growth", {}).get("daily_growth_estimate_mb", 0)
            
            predictions["storage"] = {
                "30_day_projection_mb": round(current_size + (daily_growth * 30), 2),
                "90_day_projection_mb": round(current_size + (daily_growth * 90), 2),
                "confidence": "low"
            }
        
        return predictions
    
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
    
    def _generate_growth_recommendations(self, growth_insights: Dict, predictions: Dict) -> List[Dict]:
        """Generate resource growth recommendations"""
        recommendations = []
        
        # Storage recommendations
        storage_insights = growth_insights.get("storage", {})
        if storage_insights.get("capacity_concern", False):
            recommendations.append({
                "type": "capacity_planning",
                "priority": "medium",
                "title": "Storage capacity monitoring needed",
                "description": "Current storage usage is significant",
                "action": "Implement storage monitoring and consider data archival strategies"
            })
        
        # Query volume recommendations
        query_insights = growth_insights.get("query_volume", {})
        if query_insights.get("load_level") == "high":
            recommendations.append({
                "type": "performance_scaling",
                "priority": "medium",
                "title": "High query volume detected",
                "description": "System is handling high query volumes",
                "action": "Monitor system performance and consider scaling strategies"
            })
        
        return recommendations 
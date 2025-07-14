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
Security Analytics Tools Module
Provides data access analysis, user behavior monitoring, and security insights
"""

import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import Counter, defaultdict

from .db import DorisConnectionManager
from .logger import get_logger

logger = get_logger(__name__)


class SecurityAnalyticsTools:
    """Security analytics tools for access pattern analysis and user monitoring"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        logger.info("SecurityAnalyticsTools initialized")
    
    async def analyze_data_access_patterns(
        self, 
        days: int = 7,
        include_system_users: bool = False,
        min_query_threshold: int = 5
    ) -> Dict[str, Any]:
        """
        Analyze data access patterns for users and roles
        
        Args:
            days: Number of days to analyze
            include_system_users: Whether to include system/service users
            min_query_threshold: Minimum queries for a user to be included in analysis
        
        Returns:
            Comprehensive access pattern analysis
        """
        try:
            start_time = time.time()
            
            # 🚀 PROGRESS: Initialize security analysis
            logger.info("=" * 70)
            logger.info(f"🔒 Starting Data Access Pattern Analysis")
            logger.info(f"📅 Analysis period: {days} days")
            logger.info(f"👥 Include system users: {include_system_users}")
            logger.info(f"🎯 Min query threshold: {min_query_threshold}")
            logger.info("=" * 70)
            
            connection = await self.connection_manager.get_connection("query")
            
            # Define analysis period
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)
            
            logger.info(f"📊 Period: {start_date.strftime('%Y-%m-%d')} to {end_date.strftime('%Y-%m-%d')}")
            
            # 🚀 PROGRESS: Step 1 - Get audit log data
            logger.info("📋 Step 1/5: Retrieving audit log data...")
            audit_start = time.time()
            audit_data = await self._get_audit_log_data(connection, start_date, end_date, include_system_users)
            audit_time = time.time() - audit_start
            
            if not audit_data:
                logger.warning("⚠️ No audit data available for the specified period")
                return {
                    "error": "No audit data available for the specified period",
                    "analysis_period": {
                        "start_date": start_date.isoformat(),
                        "end_date": end_date.isoformat(),
                        "days": days
                    }
                }
            
            logger.info(f"✅ Retrieved {len(audit_data)} audit records in {audit_time:.2f}s")
            
            # 🚀 PROGRESS: Step 2 - Analyze user access patterns
            logger.info("👤 Step 2/5: Analyzing user access patterns...")
            user_start = time.time()
            user_access_analysis = await self._analyze_user_access_patterns(
                audit_data, min_query_threshold
            )
            user_time = time.time() - user_start
            logger.info(f"✅ Analyzed {len(user_access_analysis)} users in {user_time:.2f}s")
            
            # 🚀 PROGRESS: Step 3 - Analyze role-based access
            logger.info("🎭 Step 3/5: Analyzing role-based access patterns...")
            role_start = time.time()
            role_access_analysis = await self._analyze_role_access_patterns(
                connection, user_access_analysis
            )
            role_time = time.time() - role_start
            logger.info(f"✅ Role analysis completed in {role_time:.2f}s")
            
            # 🚀 PROGRESS: Step 4 - Detect security anomalies
            logger.info("🚨 Step 4/5: Detecting security anomalies...")
            anomaly_start = time.time()
            security_alerts = await self._detect_security_anomalies(
                audit_data, user_access_analysis
            )
            anomaly_time = time.time() - anomaly_start
            logger.info(f"✅ Found {len(security_alerts)} security alerts in {anomaly_time:.2f}s")
            
            # Log alert summary
            if security_alerts:
                high_alerts = sum(1 for alert in security_alerts if alert.get("severity") == "high")
                medium_alerts = sum(1 for alert in security_alerts if alert.get("severity") == "medium")
                logger.info(f"🚨 Alert breakdown: {high_alerts} high, {medium_alerts} medium")
            
            # 🚀 PROGRESS: Step 5 - Generate access insights
            logger.info("💡 Step 5/5: Generating access insights...")
            insights_start = time.time()
            access_insights = await self._generate_access_insights(
                user_access_analysis, role_access_analysis
            )
            insights_time = time.time() - insights_start
            logger.info(f"✅ Access insights generated in {insights_time:.2f}s")
            
            execution_time = time.time() - start_time
            
            return {
                "analysis_period": {
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "days": days
                },
                "analysis_timestamp": datetime.now().isoformat(),
                "execution_time_seconds": round(execution_time, 3),
                "user_access_summary": self._generate_user_access_summary(user_access_analysis),
                "user_access_details": user_access_analysis,
                "role_analysis": role_access_analysis,
                "security_alerts": security_alerts,
                "access_insights": access_insights,
                "recommendations": self._generate_security_recommendations(security_alerts, access_insights)
            }
            
        except Exception as e:
            logger.error(f"Data access pattern analysis failed: {str(e)}")
            return {
                "error": str(e),
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    # ==================== Private Helper Methods ====================
    
    async def _get_audit_log_data(self, connection, start_date: datetime, end_date: datetime, include_system_users: bool) -> List[Dict]:
        """Retrieve audit log data for the specified period"""
        try:
            # System users filter
            system_user_filter = ""
            if not include_system_users:
                system_users = ['root', 'admin', 'system', 'doris', 'information_schema']
                user_list = ','.join([f'"{user}"' for user in system_users])
                system_user_filter = f"AND `user` NOT IN ({user_list})"
            
            audit_sql = f"""
            SELECT 
                `user` as user_name,
                `client_ip` as host,
                `time` as query_time,
                `stmt` as sql_statement,
                `state` as query_status,
                `scan_bytes` as scan_bytes,
                `scan_rows` as scan_rows,
                `return_rows` as return_rows,
                `query_time` as execution_time_ms
            FROM internal.__internal_schema.audit_log 
            WHERE `time` >= '{start_date.strftime('%Y-%m-%d %H:%M:%S')}'
                AND `time` <= '{end_date.strftime('%Y-%m-%d %H:%M:%S')}'
                AND `stmt` IS NOT NULL
                AND `stmt` != ''
                {system_user_filter}
            ORDER BY `time` DESC
            LIMIT 10000
            """
            
            result = await connection.execute(audit_sql)
            return result.data if result.data else []
            
        except Exception as e:
            logger.warning(f"Failed to get audit log data: {str(e)}")
            # Try alternative method without detailed metrics
            try:
                simple_audit_sql = f"""
                SELECT 
                    `user` as user_name,
                    `client_ip` as host,
                    `time` as query_time,
                    `stmt` as sql_statement,
                    `state` as query_status
                FROM internal.__internal_schema.audit_log 
                WHERE `time` >= '{start_date.strftime('%Y-%m-%d %H:%M:%S')}'
                    AND `time` <= '{end_date.strftime('%Y-%m-%d %H:%M:%S')}'
                    AND `stmt` IS NOT NULL
                    {system_user_filter}
                ORDER BY `time` DESC
                LIMIT 10000
                """
                
                result = await connection.execute(simple_audit_sql)
                return result.data if result.data else []
                
            except Exception as e2:
                logger.error(f"Failed to get simplified audit log data: {str(e2)}")
                return []
    
    async def _analyze_user_access_patterns(self, audit_data: List[Dict], min_query_threshold: int) -> List[Dict]:
        """Analyze access patterns for individual users"""
        user_stats = defaultdict(lambda: {
            "total_queries": 0,
            "unique_tables_accessed": set(),
            "hosts": set(),
            "query_types": Counter(),
            "query_times": [],
            "failed_queries": 0,
            "data_volume_read_bytes": 0,
            "data_volume_read_rows": 0,
            "hourly_pattern": [0] * 24,
            "daily_pattern": [0] * 7,
            "query_statements": []
        })
        
        # Process audit data
        for entry in audit_data:
            user_name = entry.get("user_name", "unknown")
            query_time = entry.get("query_time")
            sql_statement = entry.get("sql_statement", "")
            query_status = entry.get("query_status", "")
            
            stats = user_stats[user_name]
            stats["total_queries"] += 1
            
            # Extract table names from SQL
            tables = self._extract_table_names_from_sql(sql_statement)
            stats["unique_tables_accessed"].update(tables)
            
            # Host tracking
            if entry.get("host"):
                stats["hosts"].add(entry["host"])
            
            # Query type analysis
            query_type = self._classify_query_type(sql_statement)
            stats["query_types"][query_type] += 1
            
            # Query time patterns
            if query_time:
                try:
                    if isinstance(query_time, str):
                        query_dt = datetime.fromisoformat(query_time.replace('Z', '+00:00'))
                    else:
                        query_dt = query_time
                    
                    stats["query_times"].append(query_dt)
                    stats["hourly_pattern"][query_dt.hour] += 1
                    stats["daily_pattern"][query_dt.weekday()] += 1
                except Exception:
                    pass
            
            # Error tracking
            if query_status and "error" in query_status.lower():
                stats["failed_queries"] += 1
            
            # Data volume tracking
            if entry.get("scan_bytes"):
                try:
                    stats["data_volume_read_bytes"] += int(entry["scan_bytes"])
                except (ValueError, TypeError):
                    pass
            
            if entry.get("scan_rows"):
                try:
                    stats["data_volume_read_rows"] += int(entry["scan_rows"])
                except (ValueError, TypeError):
                    pass
            
            # Store sample queries
            if len(stats["query_statements"]) < 10:
                stats["query_statements"].append({
                    "sql": sql_statement[:200] + "..." if len(sql_statement) > 200 else sql_statement,
                    "timestamp": str(query_time),
                    "type": query_type
                })
        
        # Convert to analysis results
        user_analysis = []
        for user_name, stats in user_stats.items():
            if stats["total_queries"] >= min_query_threshold:
                # Calculate patterns and insights
                access_pattern = self._classify_access_pattern(stats["hourly_pattern"])
                table_access_frequency = dict(Counter(
                    table for entry in audit_data 
                    if entry.get("user_name") == user_name
                    for table in self._extract_table_names_from_sql(entry.get("sql_statement", ""))
                ).most_common(10))
                
                user_analysis.append({
                    "user_name": user_name,
                    "access_stats": {
                        "total_queries": stats["total_queries"],
                        "unique_tables_accessed": len(stats["unique_tables_accessed"]),
                        "unique_hosts": len(stats["hosts"]),
                        "data_volume_read_gb": round(stats["data_volume_read_bytes"] / (1024**3), 3),
                        "data_volume_read_rows": stats["data_volume_read_rows"],
                        "failed_queries": stats["failed_queries"],
                        "success_rate": round((stats["total_queries"] - stats["failed_queries"]) / stats["total_queries"], 3) if stats["total_queries"] > 0 else 0,
                        "peak_access_hour": stats["hourly_pattern"].index(max(stats["hourly_pattern"])) if max(stats["hourly_pattern"]) > 0 else None,
                        "access_pattern": access_pattern
                    },
                    "query_type_distribution": dict(stats["query_types"]),
                    "table_access_frequency": table_access_frequency,
                    "hosts_used": list(stats["hosts"]),
                    "sample_queries": stats["query_statements"],
                    "temporal_patterns": {
                        "hourly_distribution": stats["hourly_pattern"],
                        "daily_distribution": stats["daily_pattern"]
                    }
                })
        
        return sorted(user_analysis, key=lambda x: x["access_stats"]["total_queries"], reverse=True)
    
    def _extract_table_names_from_sql(self, sql: str) -> List[str]:
        """Extract table names from SQL statement (simplified implementation)"""
        if not sql:
            return []
        
        import re
        
        # Simple regex patterns to match table names
        patterns = [
            r'\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)',
            r'\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)',
            r'\bINTO\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)',
            r'\bUPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)',
            r'\bDELETE\s+FROM\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
        ]
        
        tables = []
        for pattern in patterns:
            matches = re.findall(pattern, sql, re.IGNORECASE)
            tables.extend(matches)
        
        # Clean up table names (remove quotes, aliases, etc.)
        cleaned_tables = []
        for table in tables:
            # Remove backticks, quotes, and get just the table name
            clean_table = table.strip('`"\'').split(' ')[0]
            if clean_table and not clean_table.upper() in ['SELECT', 'WHERE', 'AND', 'OR']:
                cleaned_tables.append(clean_table)
        
        return list(set(cleaned_tables))
    
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
        elif sql_upper.startswith('CREATE'):
            return "CREATE"
        elif sql_upper.startswith('ALTER'):
            return "ALTER"
        elif sql_upper.startswith('DROP'):
            return "DROP"
        elif sql_upper.startswith('SHOW'):
            return "SHOW"
        elif sql_upper.startswith('DESCRIBE') or sql_upper.startswith('DESC'):
            return "DESCRIBE"
        else:
            return "OTHER"
    
    def _classify_access_pattern(self, hourly_pattern: List[int]) -> str:
        """Classify user access pattern based on hourly distribution"""
        if not hourly_pattern or max(hourly_pattern) == 0:
            return "no_pattern"
        
        # Find peak hours
        max_queries = max(hourly_pattern)
        peak_hours = [i for i, count in enumerate(hourly_pattern) if count == max_queries]
        
        # Business hours: 9-17
        business_hours = set(range(9, 18))
        peak_in_business_hours = any(hour in business_hours for hour in peak_hours)
        
        # Night hours: 22-6
        night_hours = set(list(range(22, 24)) + list(range(0, 7)))
        peak_in_night_hours = any(hour in night_hours for hour in peak_hours)
        
        if peak_in_business_hours and not peak_in_night_hours:
            return "regular_business_hours"
        elif peak_in_night_hours:
            return "night_shift_or_batch"
        elif len(peak_hours) > 6:  # Distributed throughout day
            return "distributed_access"
        else:
            return "irregular_pattern"
    
    async def _analyze_role_access_patterns(self, connection, user_access_analysis: List[Dict]) -> Dict[str, Any]:
        """Analyze access patterns by role"""
        try:
            # Get user roles information
            user_roles = await self._get_user_roles(connection)
            
            # Group users by roles
            role_stats = defaultdict(lambda: {
                "user_count": 0,
                "total_queries": 0,
                "unique_tables": set(),
                "query_types": Counter(),
                "avg_queries_per_user": 0,
                "users": []
            })
            
            # Process user access data
            for user_data in user_access_analysis:
                user_name = user_data["user_name"]
                user_stats = user_data["access_stats"]
                query_types = user_data["query_type_distribution"]
                
                # Get user roles (default to 'unknown' if not found)
                roles = user_roles.get(user_name, ["unknown"])
                
                for role in roles:
                    stats = role_stats[role]
                    stats["user_count"] += 1
                    stats["total_queries"] += user_stats["total_queries"]
                    stats["users"].append(user_name)
                    
                    # Aggregate query types
                    for query_type, count in query_types.items():
                        stats["query_types"][query_type] += count
            
            # Calculate role analysis
            role_analysis = {}
            for role, stats in role_stats.items():
                if stats["user_count"] > 0:
                    avg_queries = stats["total_queries"] / stats["user_count"]
                    
                    # Calculate privilege usage (simplified)
                    total_role_queries = sum(stats["query_types"].values())
                    privilege_usage = {}
                    if total_role_queries > 0:
                        privilege_usage = {
                            query_type: round(count / total_role_queries, 3)
                            for query_type, count in stats["query_types"].items()
                        }
                    
                    role_analysis[role] = {
                        "user_count": stats["user_count"],
                        "users": stats["users"],
                        "total_queries": stats["total_queries"],
                        "avg_queries_per_user": round(avg_queries, 1),
                        "query_type_distribution": dict(stats["query_types"]),
                        "privilege_usage": privilege_usage,
                        "activity_level": self._classify_role_activity_level(avg_queries)
                    }
            
            return role_analysis
            
        except Exception as e:
            logger.warning(f"Failed to analyze role access patterns: {str(e)}")
            return {}
    
    async def _get_user_roles(self, connection) -> Dict[str, List[str]]:
        """Get user roles mapping"""
        try:
            # Try to get user role information
            roles_sql = """
            SELECT 
                User as user_name,
                COALESCE(Default_role, 'default') as role_name
            FROM mysql.user
            """
            
            result = await connection.execute(roles_sql)
            
            user_roles = defaultdict(list)
            if result.data:
                for row in result.data:
                    user_name = row.get("user_name", "")
                    role_name = row.get("role_name", "default")
                    if user_name:
                        user_roles[user_name].append(role_name)
            
            return dict(user_roles)
            
        except Exception as e:
            logger.warning(f"Failed to get user roles: {str(e)}")
            return {}
    
    def _classify_role_activity_level(self, avg_queries: float) -> str:
        """Classify role activity level based on average queries"""
        if avg_queries > 100:
            return "high"
        elif avg_queries > 20:
            return "medium"
        elif avg_queries > 5:
            return "low"
        else:
            return "minimal"
    
    async def _detect_security_anomalies(self, audit_data: List[Dict], user_access_analysis: List[Dict]) -> List[Dict]:
        """Detect potential security anomalies"""
        alerts = []
        
        # 1. Detect unusual access times
        for user_data in user_access_analysis:
            user_name = user_data["user_name"]
            hourly_pattern = user_data["temporal_patterns"]["hourly_distribution"]
            
            # Check for significant night-time activity
            night_queries = sum(hourly_pattern[22:24]) + sum(hourly_pattern[0:6])
            total_queries = sum(hourly_pattern)
            
            if total_queries > 0 and night_queries / total_queries > 0.3:  # >30% night activity
                alerts.append({
                    "alert_type": "unusual_access_time",
                    "severity": "medium",
                    "user": user_name,
                    "description": f"User {user_name} has {night_queries/total_queries:.1%} of queries during night hours",
                    "night_query_percentage": round(night_queries/total_queries, 3),
                    "timestamp": datetime.now().isoformat()
                })
        
        # 2. Detect users with high failure rates
        for user_data in user_access_analysis:
            user_name = user_data["user_name"]
            success_rate = user_data["access_stats"]["success_rate"]
            total_queries = user_data["access_stats"]["total_queries"]
            
            if total_queries > 10 and success_rate < 0.8:  # <80% success rate
                alerts.append({
                    "alert_type": "high_failure_rate",
                    "severity": "medium",
                    "user": user_name,
                    "description": f"User {user_name} has low query success rate ({success_rate:.1%})",
                    "success_rate": success_rate,
                    "total_queries": total_queries,
                    "timestamp": datetime.now().isoformat()
                })
        
        # 3. Detect unusual data volume access
        data_volumes = [user["access_stats"]["data_volume_read_gb"] for user in user_access_analysis]
        if data_volumes:
            avg_volume = sum(data_volumes) / len(data_volumes)
            std_dev = (sum((x - avg_volume) ** 2 for x in data_volumes) / len(data_volumes)) ** 0.5
            threshold = avg_volume + 2 * std_dev  # 2 standard deviations above mean
            
            for user_data in user_access_analysis:
                user_name = user_data["user_name"]
                volume = user_data["access_stats"]["data_volume_read_gb"]
                
                if volume > threshold and volume > 1.0:  # >1GB and above threshold
                    alerts.append({
                        "alert_type": "unusual_data_volume",
                        "severity": "high" if volume > threshold * 2 else "medium",
                        "user": user_name,
                        "description": f"User {user_name} read {volume:.2f}GB (threshold: {threshold:.2f}GB)",
                        "data_volume_gb": volume,
                        "threshold_gb": round(threshold, 2),
                        "timestamp": datetime.now().isoformat()
                    })
        
        # 4. Detect users accessing many different tables
        for user_data in user_access_analysis:
            user_name = user_data["user_name"]
            unique_tables = user_data["access_stats"]["unique_tables_accessed"]
            total_queries = user_data["access_stats"]["total_queries"]
            
            # High table diversity might indicate privilege escalation or data mining
            if unique_tables > 20 and total_queries > 50:
                alerts.append({
                    "alert_type": "broad_table_access",
                    "severity": "medium",
                    "user": user_name,
                    "description": f"User {user_name} accessed {unique_tables} different tables",
                    "unique_tables_count": unique_tables,
                    "total_queries": total_queries,
                    "timestamp": datetime.now().isoformat()
                })
        
        return sorted(alerts, key=lambda x: {"high": 3, "medium": 2, "low": 1}.get(x["severity"], 0), reverse=True)
    
    async def _generate_access_insights(self, user_access_analysis: List[Dict], role_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate access insights and patterns"""
        insights = {
            "user_behavior_patterns": {},
            "role_effectiveness": {},
            "security_posture": {}
        }
        
        # User behavior patterns
        if user_access_analysis:
            total_users = len(user_access_analysis)
            active_users = len([u for u in user_access_analysis if u["access_stats"]["total_queries"] > 10])
            power_users = len([u for u in user_access_analysis if u["access_stats"]["total_queries"] > 100])
            
            # Access pattern distribution
            pattern_distribution = Counter(
                user["access_stats"]["access_pattern"] for user in user_access_analysis
            )
            
            insights["user_behavior_patterns"] = {
                "total_users_analyzed": total_users,
                "active_users": active_users,
                "power_users": power_users,
                "access_pattern_distribution": dict(pattern_distribution),
                "avg_queries_per_user": round(
                    sum(u["access_stats"]["total_queries"] for u in user_access_analysis) / total_users, 1
                ) if total_users > 0 else 0
            }
        
        # Role effectiveness
        if role_analysis:
            most_active_role = max(role_analysis.items(), key=lambda x: x[1]["total_queries"])
            least_active_role = min(role_analysis.items(), key=lambda x: x[1]["total_queries"])
            
            insights["role_effectiveness"] = {
                "total_roles": len(role_analysis),
                "most_active_role": {
                    "role": most_active_role[0],
                    "total_queries": most_active_role[1]["total_queries"],
                    "user_count": most_active_role[1]["user_count"]
                },
                "least_active_role": {
                    "role": least_active_role[0],
                    "total_queries": least_active_role[1]["total_queries"],
                    "user_count": least_active_role[1]["user_count"]
                },
                "avg_users_per_role": round(
                    sum(role_info["user_count"] for role_info in role_analysis.values()) / len(role_analysis), 1
                )
            }
        
        # Security posture assessment
        if user_access_analysis:
            users_with_failures = len([u for u in user_access_analysis if u["access_stats"]["failed_queries"] > 0])
            users_night_access = len([
                u for u in user_access_analysis 
                if any(u["temporal_patterns"]["hourly_distribution"][hour] > 0 for hour in list(range(22, 24)) + list(range(0, 6)))
            ])
            
            insights["security_posture"] = {
                "users_with_query_failures": users_with_failures,
                "users_with_night_access": users_night_access,
                "security_score": self._calculate_security_score(user_access_analysis),
                "risk_level": self._assess_overall_risk_level(user_access_analysis)
            }
        
        return insights
    
    def _calculate_security_score(self, user_access_analysis: List[Dict]) -> float:
        """Calculate overall security score (0-1, higher is better)"""
        if not user_access_analysis:
            return 0.0
        
        total_users = len(user_access_analysis)
        
        # Factors that contribute to security score
        users_with_high_success_rate = len([u for u in user_access_analysis if u["access_stats"]["success_rate"] > 0.9])
        users_with_normal_patterns = len([u for u in user_access_analysis if u["access_stats"]["access_pattern"] == "regular_business_hours"])
        
        success_rate_score = users_with_high_success_rate / total_users
        pattern_score = users_with_normal_patterns / total_users
        
        # Combined score
        overall_score = (success_rate_score * 0.6 + pattern_score * 0.4)
        return round(overall_score, 3)
    
    def _assess_overall_risk_level(self, user_access_analysis: List[Dict]) -> str:
        """Assess overall security risk level"""
        security_score = self._calculate_security_score(user_access_analysis)
        
        if security_score > 0.8:
            return "low"
        elif security_score > 0.6:
            return "medium"
        else:
            return "high"
    
    def _generate_user_access_summary(self, user_access_analysis: List[Dict]) -> Dict[str, Any]:
        """Generate summary statistics for user access"""
        if not user_access_analysis:
            return {
                "total_users": 0,
                "active_users": 0,
                "high_activity_users": 0,
                "dormant_users": 0
            }
        
        total_users = len(user_access_analysis)
        active_users = len([u for u in user_access_analysis if u["access_stats"]["total_queries"] > 10])
        high_activity_users = len([u for u in user_access_analysis if u["access_stats"]["total_queries"] > 100])
        dormant_users = total_users - active_users
        
        return {
            "total_users": total_users,
            "active_users": active_users,
            "high_activity_users": high_activity_users,
            "dormant_users": dormant_users,
            "activity_distribution": {
                "high": high_activity_users,
                "medium": active_users - high_activity_users,
                "low": dormant_users
            }
        }
    
    def _generate_security_recommendations(self, security_alerts: List[Dict], access_insights: Dict[str, Any]) -> List[Dict]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        # Recommendations based on alerts
        if security_alerts:
            high_severity_alerts = [alert for alert in security_alerts if alert["severity"] == "high"]
            if high_severity_alerts:
                recommendations.append({
                    "type": "urgent_security_review",
                    "priority": "high",
                    "description": f"Found {len(high_severity_alerts)} high-severity security alerts",
                    "action": "Immediate review of flagged users and access patterns required",
                    "affected_users": list(set(alert["user"] for alert in high_severity_alerts if "user" in alert))
                })
            
            # Night access recommendations
            night_access_alerts = [alert for alert in security_alerts if alert["alert_type"] == "unusual_access_time"]
            if night_access_alerts:
                recommendations.append({
                    "type": "access_time_policy",
                    "priority": "medium",
                    "description": f"{len(night_access_alerts)} users have significant night-time access",
                    "action": "Review access time policies and consider time-based restrictions",
                    "affected_users": [alert["user"] for alert in night_access_alerts]
                })
        
        # Recommendations based on insights
        security_posture = access_insights.get("security_posture", {})
        risk_level = security_posture.get("risk_level", "unknown")
        
        if risk_level == "high":
            recommendations.append({
                "type": "overall_security_improvement",
                "priority": "high",
                "description": "Overall security posture indicates high risk",
                "action": "Comprehensive security audit and policy review recommended"
            })
        
        # Role-based recommendations
        role_effectiveness = access_insights.get("role_effectiveness", {})
        if role_effectiveness and role_effectiveness.get("total_roles", 0) < 3:
            recommendations.append({
                "type": "role_management",
                "priority": "medium",
                "description": "Limited role diversity detected",
                "action": "Consider implementing more granular role-based access control"
            })
        
        return recommendations 
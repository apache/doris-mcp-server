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
Data Governance Tools Module
Provides data completeness analysis, field lineage tracking, and data freshness monitoring
"""

import re
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

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


class DataGovernanceTools:
    """Data governance tools suite"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        logger.info("DataGovernanceTools initialized")
    

    
    async def trace_column_lineage(
        self, 
        table_name: str, 
        column_name: str,
        depth: int = 3,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Column-level lineage tracing
        
        Args:
            table_name: Table name
            column_name: Column name
            depth: Trace depth
            catalog_name: Catalog name
            db_name: Database name
        """
        try:
            start_time = time.time()
            
            # 🚀 PROGRESS: Initialize column lineage tracing
            logger.info("=" * 60)
            logger.info(f"🔍 Starting Column Lineage Tracing")
            logger.info(f"📊 Target: {table_name}.{column_name}")
            logger.info(f"🎯 Trace depth: {depth}")
            logger.info("=" * 60)
            
            connection = await self.connection_manager.get_connection("query")
            
            full_table_name = self._build_full_table_name(table_name, catalog_name, db_name)
            target_column = f"{full_table_name}.{column_name}"
            
            logger.info(f"📝 Full target: {target_column}")
            
            # 🚀 PROGRESS: Step 1 - Verify target column exists
            logger.info("🔍 Step 1/4: Verifying target column exists...")
            verify_start = time.time()
            if not await self._verify_column_exists(connection, full_table_name, column_name):
                logger.error(f"❌ Column {column_name} not found in table {full_table_name}")
                return {"error": f"Column {column_name} not found in table {full_table_name}"}
            
            verify_time = time.time() - verify_start
            logger.info(f"✅ Column verified in {verify_time:.2f}s")
            
            # 🚀 PROGRESS: Step 2 - Analyze SQL logs for lineage relationships
            logger.info(f"📊 Step 2/4: Analyzing SQL logs for lineage (depth={depth})...")
            lineage_start = time.time()
            source_chain = await self._analyze_sql_logs_for_lineage(
                connection, full_table_name, column_name, depth
            )
            lineage_time = time.time() - lineage_start
            logger.info(f"✅ Found {len(source_chain)} lineage relationships in {lineage_time:.2f}s")
            
            # 🚀 PROGRESS: Step 3 - Analyze downstream usage
            logger.info("⬇️ Step 3/4: Analyzing downstream column usage...")
            downstream_start = time.time()
            downstream_usage = await self._analyze_downstream_column_usage(
                connection, full_table_name, column_name
            )
            downstream_time = time.time() - downstream_start
            logger.info(f"✅ Found {len(downstream_usage)} downstream usages in {downstream_time:.2f}s")
            
            # 🚀 PROGRESS: Step 4 - Extract transformation rules
            logger.info("🔄 Step 4/4: Extracting transformation rules...")
            transform_start = time.time()
            transformation_rules = await self._extract_transformation_rules(
                connection, full_table_name, column_name
            )
            transform_time = time.time() - transform_start
            logger.info(f"✅ Found {len(transformation_rules)} transformation rules in {transform_time:.2f}s")
            
            execution_time = time.time() - start_time
            
            return {
                "target_column": target_column,
                "analysis_timestamp": datetime.now().isoformat(),
                "execution_time_seconds": round(execution_time, 3),
                "lineage_depth": depth,
                "source_chain": source_chain,
                "downstream_usage": downstream_usage,
                "transformation_rules": transformation_rules,
                "lineage_confidence": self._calculate_lineage_confidence(source_chain),
                "impact_analysis": {
                    "upstream_dependencies": len(source_chain),
                    "downstream_dependencies": len(downstream_usage),
                    "risk_level": self._assess_lineage_risk(source_chain, downstream_usage)
                }
            }
            
        except Exception as e:
            logger.error(f"Column lineage tracing failed for {table_name}.{column_name}: {str(e)}")
            return {
                "error": str(e),
                "target_column": f"{table_name}.{column_name}",
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    async def monitor_data_freshness(
        self, 
        tables: Optional[List[str]] = None,
        time_threshold_hours: int = 24,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Data freshness monitoring
        
        Args:
            tables: List of tables to monitor, empty means monitor all tables
            time_threshold_hours: Freshness threshold (hours)
            catalog_name: Catalog name
            db_name: Database name
        """
        try:
            start_time = time.time()
            connection = await self.connection_manager.get_connection("query")
            
            # 1. Get list of tables to monitor
            if not tables:
                tables = await self._get_all_tables(connection, catalog_name, db_name)
            
            # 2. Analyze freshness of each table
            table_freshness = {}
            fresh_count = 0
            stale_count = 0
            
            for table in tables:
                full_table_name = self._build_full_table_name(table, catalog_name, db_name)
                freshness_info = await self._analyze_table_freshness(
                    connection, full_table_name, time_threshold_hours
                )
                table_freshness[table] = freshness_info
                
                if freshness_info["status"] == "fresh":
                    fresh_count += 1
                else:
                    stale_count += 1
            
            # 3. Calculate overall freshness score
            total_tables = len(tables)
            overall_freshness_score = fresh_count / total_tables if total_tables > 0 else 0
            
            # 4. Identify data flow issues
            data_flow_issues = await self._identify_data_flow_issues(table_freshness)
            
            execution_time = time.time() - start_time
            
            return {
                "monitoring_timestamp": datetime.now().isoformat(),
                "execution_time_seconds": round(execution_time, 3),
                "monitoring_scope": {
                    "catalog_name": catalog_name,
                    "db_name": db_name,
                    "time_threshold_hours": time_threshold_hours
                },
                "freshness_summary": {
                    "total_tables": total_tables,
                    "fresh_tables": fresh_count,
                    "stale_tables": stale_count,
                    "overall_freshness_score": round(overall_freshness_score, 3)
                },
                "table_freshness": table_freshness,
                "data_flow_issues": data_flow_issues,
                "alerts": self._generate_freshness_alerts(table_freshness, time_threshold_hours)
            }
            
        except Exception as e:
            logger.error(f"Data freshness monitoring failed: {str(e)}")
            return {
                "error": str(e),
                "monitoring_timestamp": datetime.now().isoformat()
            }
    
    # ==================== Private Helper Methods ====================
    
    def _build_full_table_name(self, table_name: str, catalog_name: Optional[str], db_name: Optional[str]) -> str:
        """Build full table name - use three-level naming convention with security validation"""
        # SECURITY FIX: Use build_table_reference for safe identifier handling
        # Default catalog is internal for internal tables
        effective_catalog = catalog_name if catalog_name else "internal"
        
        if db_name:
            return build_table_reference(table_name, db_name, effective_catalog)
        else:
            # If db_name is not provided, need to determine current database
            return build_table_reference(table_name, catalog_name=effective_catalog)
    
    async def _get_table_basic_info(self, connection, table_name: str) -> Optional[Dict]:
        """Get table basic information"""
        try:
            # SECURITY FIX: Get auth_context for security validation
            # table_name should already be validated by _build_full_table_name
            auth_context = get_auth_context()
            
            # Try to get table row count
            count_sql = f"SELECT COUNT(*) as row_count FROM {table_name}"
            result = await connection.execute(count_sql, auth_context=auth_context)
            
            if result.data:
                return {"row_count": result.data[0]["row_count"]}
            return None
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed for table {table_name}: {str(e)}")
            return {"row_count": 0}
        except Exception as e:
            logger.warning(f"Failed to get basic info for table {table_name}: {str(e)}")
            return {"row_count": 0}
    
    async def _get_table_columns_info(self, connection, table_name: str, catalog_name: Optional[str], db_name: Optional[str]) -> List[Dict]:
        """Get table column information"""
        try:
            # SECURITY FIX: Validate identifiers and use parameterized query
            auth_context = get_auth_context()
            
            try:
                validate_identifier(table_name, "table name")
                if db_name:
                    validate_identifier(db_name, "database name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid identifier rejected: {e}")
                return []
            
            # Build parameterized query conditions
            params = [table_name]
            where_conditions = ["table_name = %s"]
            
            if db_name:
                where_conditions.append("table_schema = %s")
                params.append(db_name)
            else:
                where_conditions.append("table_schema = DATABASE()")
            
            columns_sql = f"""
            SELECT 
                column_name,
                data_type,
                is_nullable,
                column_comment,
                ordinal_position
            FROM information_schema.columns 
            WHERE {' AND '.join(where_conditions)}
            ORDER BY ordinal_position
            """
            
            result = await connection.execute(columns_sql, params=tuple(params), auth_context=auth_context)
            return result.data if result.data else []
            
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed: {str(e)}")
            return []
        except Exception as e:
            logger.warning(f"Failed to get columns info for table {table_name}: {str(e)}")
            return []
    
    async def _analyze_column_completeness(self, connection, table_name: str, columns_info: List[Dict]) -> Dict[str, Any]:
        """Analyze column completeness"""
        # SECURITY FIX: Get auth_context for security validation
        auth_context = get_auth_context()
        column_completeness = {}
        
        for column in columns_info:
            column_name = column["column_name"]
            try:
                # SECURITY FIX: Validate column name before using in SQL
                try:
                    validate_identifier(column_name, "column name")
                except SQLSecurityError as e:
                    logger.warning(f"Invalid column name rejected: {e}")
                    column_completeness[column_name] = {
                        "error": f"Invalid column name: {e}",
                        "completeness_score": 0.0
                    }
                    continue
                
                # Use quoted identifier for column name
                quoted_column = quote_identifier(column_name, "column name")
                
                # Calculate null value statistics
                null_sql = f"""
                SELECT 
                    COUNT(*) as total_count,
                    COUNT({quoted_column}) as non_null_count,
                    COUNT(*) - COUNT({quoted_column}) as null_count
                FROM {table_name}
                """
                
                result = await connection.execute(null_sql, auth_context=auth_context)
                if result.data:
                    stats = result.data[0]
                    total_count = stats["total_count"]
                    null_count = stats["null_count"]
                    null_rate = null_count / total_count if total_count > 0 else 0
                    completeness_score = 1.0 - null_rate
                    
                    column_completeness[column_name] = {
                        "data_type": column["data_type"],
                        "is_nullable": column["is_nullable"],
                        "total_count": total_count,
                        "null_count": null_count,
                        "non_null_count": stats["non_null_count"],
                        "null_rate": round(null_rate, 4),
                        "completeness_score": round(completeness_score, 4)
                    }
                    
            except SQLSecurityError as e:
                logger.warning(f"Security validation failed for column {column_name}: {str(e)}")
                column_completeness[column_name] = {
                    "error": str(e),
                    "completeness_score": 0.0
                }
            except Exception as e:
                logger.warning(f"Failed to analyze completeness for column {column_name}: {str(e)}")
                column_completeness[column_name] = {
                    "error": str(e),
                    "completeness_score": 0.0
                }
        
        return column_completeness
    
    async def _check_business_rule_compliance(self, connection, table_name: str, business_rules: List[Dict], total_rows: int) -> Dict[str, Any]:
        """Check business rule compliance"""
        compliance_results = {}
        
        for rule in business_rules:
            rule_name = rule.get("rule_name", "unknown")
            sql_condition = rule.get("sql_condition", "")
            
            if not sql_condition:
                continue
                
            try:
                # Check number of records meeting conditions
                compliance_sql = f"""
                SELECT 
                    COUNT(*) as total_count,
                    SUM(CASE WHEN {sql_condition} THEN 1 ELSE 0 END) as pass_count
                FROM {table_name}
                """
                
                auth_context = get_auth_context()
                result = await connection.execute(compliance_sql, auth_context=auth_context)
                if result.data:
                    stats = result.data[0]
                    pass_count = stats["pass_count"] or 0
                    fail_count = total_rows - pass_count
                    pass_rate = pass_count / total_rows if total_rows > 0 else 0
                    
                    compliance_results[rule_name] = {
                        "rule_condition": sql_condition,
                        "total_records": total_rows,
                        "pass_count": pass_count,
                        "fail_count": fail_count,
                        "pass_rate": round(pass_rate, 4),
                        "compliance_score": round(pass_rate, 4)
                    }
                    
            except Exception as e:
                logger.warning(f"Failed to check business rule {rule_name}: {str(e)}")
                compliance_results[rule_name] = {
                    "error": str(e),
                    "compliance_score": 0.0
                }
        
        return compliance_results
    
    async def _detect_data_integrity_issues(self, connection, table_name: str, columns_info: List[Dict]) -> List[Dict]:
        """Detect data integrity issues"""
        issues = []
        
        try:
            # Detect duplicate values in primary key fields
            primary_key_columns = [col["column_name"] for col in columns_info if "primary" in col.get("column_comment", "").lower()]
            
            for pk_col in primary_key_columns:
                duplicate_sql = f"""
                SELECT COUNT(*) as duplicate_count
                FROM (
                    SELECT {pk_col}, COUNT(*) as cnt
                    FROM {table_name}
                    WHERE {pk_col} IS NOT NULL
                    GROUP BY {pk_col}
                    HAVING COUNT(*) > 1
                ) t
                """
                
                auth_context = get_auth_context()
                result = await connection.execute(duplicate_sql, auth_context=auth_context)
                if result.data and result.data[0]["duplicate_count"] > 0:
                    issues.append({
                        "type": "duplicate_primary_keys",
                        "column": pk_col,
                        "count": result.data[0]["duplicate_count"],
                        "severity": "high",
                        "description": f"Found duplicate values in primary key column {pk_col}"
                    })
                    
        except Exception as e:
            logger.warning(f"Failed to detect integrity issues: {str(e)}")
            issues.append({
                "type": "detection_error",
                "error": str(e),
                "severity": "unknown"
            })
        
        return issues
    
    def _calculate_completeness_score(self, column_completeness: Dict, business_rule_compliance: Dict) -> float:
        """Calculate overall completeness score"""
        if not column_completeness:
            return 0.0
            
        # Calculate column completeness average score
        column_scores = [
            col_info.get("completeness_score", 0.0) 
            for col_info in column_completeness.values() 
            if isinstance(col_info, dict) and "completeness_score" in col_info
        ]
        avg_column_score = sum(column_scores) / len(column_scores) if column_scores else 0.0
        
        # Calculate business rule compliance average score
        compliance_scores = [
            rule_info.get("compliance_score", 0.0) 
            for rule_info in business_rule_compliance.values() 
            if isinstance(rule_info, dict) and "compliance_score" in rule_info
        ]
        avg_compliance_score = sum(compliance_scores) / len(compliance_scores) if compliance_scores else 1.0
        
        # Comprehensive score (column completeness weight 70%, business rules weight 30%)
        overall_score = avg_column_score * 0.7 + avg_compliance_score * 0.3
        return round(overall_score, 4)
    
    def _generate_completeness_recommendations(self, column_completeness: Dict, integrity_issues: List[Dict]) -> List[Dict]:
        """Generate completeness improvement recommendations"""
        recommendations = []
        
        # Generate recommendations based on column completeness
        for col_name, col_info in column_completeness.items():
            if isinstance(col_info, dict):
                null_rate = col_info.get("null_rate", 0)
                if null_rate > 0.1:  # Null rate exceeds 10%
                    recommendations.append({
                        "type": "high_null_rate",
                        "column": col_name,
                        "priority": "high" if null_rate > 0.5 else "medium",
                        "description": f"Column {col_name} has high null rate ({null_rate:.1%})",
                        "suggested_action": "Review data collection process or add data validation"
                    })
        
        # Generate recommendations based on integrity issues
        for issue in integrity_issues:
            if issue["type"] == "duplicate_primary_keys":
                recommendations.append({
                    "type": "data_deduplication",
                    "column": issue["column"],
                    "priority": "high",
                    "description": f"Duplicate primary key values found in {issue['column']}",
                    "suggested_action": "Implement unique constraint or data deduplication process"
                })
        
        return recommendations
    
    async def _verify_column_exists(self, connection, table_name: str, column_name: str) -> bool:
        """Verify if column exists"""
        try:
            # SECURITY FIX: Validate and quote column name
            try:
                validate_identifier(column_name, "column name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid column name rejected: {e}")
                return False
            
            safe_column = quote_identifier(column_name, "column name")
            # table_name is already safe (from _build_full_table_name)
            verify_sql = f"SELECT {safe_column} FROM {table_name} LIMIT 1"
            auth_context = get_auth_context()
            await connection.execute(verify_sql, auth_context=auth_context)
            return True
        except SQLSecurityError:
            return False
        except Exception:
            return False
    
    async def _analyze_sql_logs_for_lineage(self, connection, table_name: str, column_name: str, depth: int) -> List[Dict]:
        """Analyze SQL logs to get lineage relationships (simplified implementation)"""
        # Note: This is a simplified implementation, actual environment needs to analyze audit logs
        source_chain = []
        
        try:
            # SECURITY FIX: Validate table name and use parameterized-like approach
            table_name_part = table_name.split('.')[-1]
            try:
                validate_identifier(table_name_part, "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return []
            
            # Escape special characters for LIKE pattern
            safe_pattern = table_name_part.replace('%', r'\%').replace('_', r'\_')
            like_pattern = f"%{safe_pattern}%"
            
            # Try to find related INSERT/CREATE TABLE AS SELECT statements from audit logs (one year range)
            auth_context = get_auth_context()
            audit_sql = """
            SELECT 
                stmt as sql_statement,
                `time` as execution_time,
                `user` as user_name
            FROM internal.__internal_schema.audit_log 
            WHERE stmt LIKE %s 
                AND (stmt LIKE '%INSERT%' OR stmt LIKE '%CREATE%' OR stmt LIKE '%SELECT%')
                AND `time` >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
            ORDER BY `time` DESC 
            LIMIT 50
            """
            
            result = await connection.execute(audit_sql, params=(like_pattern,), auth_context=auth_context)
            
            if result.data:
                for i, log_entry in enumerate(result.data[:depth]):
                    # Simplified lineage analysis: extract possible source tables
                    sql_stmt = log_entry.get("sql_statement", "")
                    source_tables = self._extract_source_tables_from_sql(sql_stmt)
                    
                    if source_tables:
                        # Handle datetime serialization issue
                        execution_time = log_entry.get("execution_time")
                        if execution_time and hasattr(execution_time, 'isoformat'):
                            execution_time = execution_time.isoformat()
                        elif execution_time:
                            execution_time = str(execution_time)
                        
                        source_chain.append({
                            "level": i + 1,
                            "source_table": source_tables[0],  # Take the first as main source table
                            "source_column": column_name,  # Simplified: assume same name
                            "transformation": self._extract_transformation_from_sql(sql_stmt, column_name),
                            "confidence": 0.8 - (i * 0.1),  # Decreasing confidence
                            "execution_time": execution_time,
                            "user": log_entry.get("user_name")
                        })
                        
        except Exception as e:
            logger.warning(f"Failed to analyze SQL logs for lineage: {str(e)}")
            # If unable to get from audit logs, return basic information
            source_chain = [{
                "level": 1,
                "source_table": "unknown_source",
                "source_column": column_name,
                "transformation": "unknown",
                "confidence": 0.3,
                "note": "Limited lineage information available"
            }]
        
        return source_chain
    
    def _extract_source_tables_from_sql(self, sql: str) -> List[str]:
        """Extract source table names from SQL statement (simplified implementation)"""
        # Simplified regex to match table names in FROM clause
        from_pattern = r'\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
        join_pattern = r'\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
        
        tables = []
        
        # Find tables in FROM clause
        from_matches = re.findall(from_pattern, sql, re.IGNORECASE)
        tables.extend(from_matches)
        
        # Find tables in JOIN clause
        join_matches = re.findall(join_pattern, sql, re.IGNORECASE)
        tables.extend(join_matches)
        
        return list(set(tables))  # Remove duplicates
    
    def _extract_transformation_from_sql(self, sql: str, column_name: str) -> str:
        """Extract field transformation rules from SQL statement (simplified implementation)"""
        # Simplified implementation: find expressions containing target field
        lines = sql.split('\n')
        for line in lines:
            if column_name in line and ('SELECT' in line.upper() or '=' in line):
                return line.strip()
        
        return "direct_copy"
    
    async def _analyze_downstream_column_usage(self, connection, table_name: str, column_name: str) -> List[Dict]:
        """Analyze downstream usage of field (simplified implementation)"""
        downstream_usage = []
        
        try:
            # SECURITY FIX: Validate inputs and use parameterized-like approach
            table_name_part = table_name.split('.')[-1]
            try:
                validate_identifier(table_name_part, "table name")
                validate_identifier(column_name, "column name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid identifier rejected: {e}")
                return []
            
            # Escape special characters for LIKE pattern
            safe_table_pattern = f"%{table_name_part.replace('%', r'\\%').replace('_', r'\\_')}%"
            safe_column_pattern = f"%{column_name.replace('%', r'\\%').replace('_', r'\\_')}%"
            
            # Find other tables that might use this field (through audit logs, one year range)
            auth_context = get_auth_context()
            usage_sql = """
            SELECT DISTINCT
                stmt as sql_statement
            FROM internal.__internal_schema.audit_log 
            WHERE stmt LIKE %s 
                AND stmt LIKE %s
                AND stmt LIKE '%SELECT%'
                AND `time` >= DATE_SUB(NOW(), INTERVAL 1 YEAR)
            LIMIT 20
            """
            
            result = await connection.execute(usage_sql, params=(safe_table_pattern, safe_column_pattern), auth_context=auth_context)
            
            if result.data:
                for entry in result.data:
                    sql_stmt = entry.get("sql_statement", "")
                    target_tables = self._extract_target_tables_from_sql(sql_stmt)
                    
                    for target_table in target_tables:
                        if target_table != table_name.split('.')[-1]:  # Not the source table itself
                            downstream_usage.append({
                                "table": target_table,
                                "column": column_name,  # Simplified: assume same name
                                "usage_type": "select_reference",
                                "confidence": 0.7
                            })
                            
        except Exception as e:
            logger.warning(f"Failed to analyze downstream usage: {str(e)}")
        
        return downstream_usage
    
    def _extract_target_tables_from_sql(self, sql: str) -> List[str]:
        """Extract target table names from SQL statement"""
        # Find target tables in INSERT INTO or CREATE TABLE statements
        insert_pattern = r'\bINSERT\s+INTO\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
        create_pattern = r'\bCREATE\s+TABLE\s+([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)'
        
        tables = []
        
        insert_matches = re.findall(insert_pattern, sql, re.IGNORECASE)
        tables.extend(insert_matches)
        
        create_matches = re.findall(create_pattern, sql, re.IGNORECASE)
        tables.extend(create_matches)
        
        return list(set(tables))
    
    async def _extract_transformation_rules(self, connection, table_name: str, column_name: str) -> List[Dict]:
        """Extract field transformation rules"""
        # Simplified implementation: return basic transformation information
        return [{
            "transformation_type": "unknown",
            "description": "Transformation rules analysis requires detailed ETL metadata",
            "confidence": 0.5
        }]
    
    def _calculate_lineage_confidence(self, source_chain: List[Dict]) -> float:
        """Calculate overall confidence of lineage tracing"""
        if not source_chain:
            return 0.0
        
        confidences = [item.get("confidence", 0.0) for item in source_chain]
        return round(sum(confidences) / len(confidences), 3)
    
    def _assess_lineage_risk(self, source_chain: List[Dict], downstream_usage: List[Dict]) -> str:
        """Assess lineage risk level"""
        if len(downstream_usage) > 10:
            return "high"
        elif len(downstream_usage) > 5:
            return "medium"
        else:
            return "low"
    
    async def _get_all_tables(self, connection, catalog_name: Optional[str], db_name: Optional[str]) -> List[str]:
        """Get list of all tables"""
        try:
            auth_context = get_auth_context()
            params = []
            
            # SECURITY FIX: Use parameterized query
            if db_name:
                try:
                    validate_identifier(db_name, "database name")
                except SQLSecurityError as e:
                    logger.warning(f"Invalid database name rejected: {e}")
                    return []
                where_clause = "table_schema = %s"
                params.append(db_name)
            else:
                where_clause = "table_schema = DATABASE()"
            
            tables_sql = f"""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE {where_clause}
                AND table_type = 'BASE TABLE'
            ORDER BY table_name
            """
            
            result = await connection.execute(tables_sql, params=tuple(params) if params else None, auth_context=auth_context)
            return [row["table_name"] for row in result.data] if result.data else []
            
        except Exception as e:
            logger.warning(f"Failed to get table list: {str(e)}")
            return []
    
    async def _analyze_table_freshness(self, connection, table_name: str, threshold_hours: int) -> Dict[str, Any]:
        """Analyze freshness of single table"""
        try:
            # Try multiple methods to get table's last update time
            freshness_methods = [
                self._get_freshness_from_partition_info,
                self._get_freshness_from_max_timestamp,
                self._get_freshness_from_table_metadata
            ]
            
            last_update = None
            method_used = "unknown"
            
            for method in freshness_methods:
                try:
                    result = await method(connection, table_name)
                    if result:
                        last_update = result["last_update"]
                        method_used = result["method"]
                        break
                except Exception as e:
                    continue
            
            if not last_update:
                return {
                    "last_update": None,
                    "staleness_hours": None,
                    "freshness_score": 0.0,
                    "status": "unknown",
                    "method_used": "none",
                    "error": "Unable to determine last update time"
                }
            
            # Calculate data staleness
            now = datetime.now()
            if isinstance(last_update, str):
                last_update = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
            
            staleness_hours = (now - last_update).total_seconds() / 3600
            
            # Calculate freshness score and status
            if staleness_hours <= threshold_hours:
                status = "fresh"
                freshness_score = max(0.0, 1.0 - (staleness_hours / threshold_hours))
            else:
                status = "stale"
                freshness_score = max(0.0, 1.0 - (staleness_hours / (threshold_hours * 2)))
            
            return {
                "last_update": last_update.isoformat() if hasattr(last_update, 'isoformat') else str(last_update),
                "staleness_hours": round(staleness_hours, 2),
                "freshness_score": round(freshness_score, 3),
                "status": status,
                "method_used": method_used,
                "threshold_hours": threshold_hours
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze freshness for table {table_name}: {str(e)}")
            return {
                "last_update": None,
                "staleness_hours": None,
                "freshness_score": 0.0,
                "status": "error",
                "error": str(e)
            }
    
    async def _get_freshness_from_partition_info(self, connection, table_name: str) -> Optional[Dict]:
        """Get freshness from partition information"""
        try:
            # SECURITY FIX: Validate and use parameterized query
            table_name_part = table_name.split('.')[-1]
            try:
                validate_identifier(table_name_part, "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return None
            
            auth_context = get_auth_context()
            partition_sql = """
            SELECT MAX(CREATE_TIME) as last_update
            FROM information_schema.partitions 
            WHERE table_name = %s
                AND CREATE_TIME IS NOT NULL
            """
            
            result = await connection.execute(partition_sql, params=(table_name_part,), auth_context=auth_context)
            if result.data and result.data[0]["last_update"]:
                return {
                    "last_update": result.data[0]["last_update"],
                    "method": "partition_info"
                }
            return None
            
        except Exception:
            return None
    
    async def _get_freshness_from_max_timestamp(self, connection, table_name: str) -> Optional[Dict]:
        """Get freshness from timestamp fields"""
        try:
            # Find possible timestamp fields
            timestamp_columns = await self._find_timestamp_columns(connection, table_name)
            
            if timestamp_columns:
                max_time_sql = f"""
                SELECT MAX({timestamp_columns[0]}) as last_update
                FROM {table_name}
                """
                
                auth_context = get_auth_context()
                result = await connection.execute(max_time_sql, auth_context=auth_context)
                if result.data and result.data[0]["last_update"]:
                    return {
                        "last_update": result.data[0]["last_update"],
                        "method": f"max_timestamp({timestamp_columns[0]})"
                    }
            return None
            
        except Exception:
            return None
    
    async def _get_freshness_from_table_metadata(self, connection, table_name: str) -> Optional[Dict]:
        """Get freshness from table metadata"""
        try:
            # SECURITY FIX: Validate and use parameterized query
            table_name_part = table_name.split('.')[-1]
            try:
                validate_identifier(table_name_part, "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return None
            
            auth_context = get_auth_context()
            metadata_sql = """
            SELECT UPDATE_TIME as last_update
            FROM information_schema.tables 
            WHERE table_name = %s
                AND UPDATE_TIME IS NOT NULL
            """
            
            result = await connection.execute(metadata_sql, params=(table_name_part,), auth_context=auth_context)
            if result.data and result.data[0]["last_update"]:
                return {
                    "last_update": result.data[0]["last_update"],
                    "method": "table_metadata"
                }
            return None
            
        except Exception:
            return None
    
    async def _find_timestamp_columns(self, connection, table_name: str) -> List[str]:
        """Find possible timestamp fields"""
        try:
            # SECURITY FIX: Validate and use parameterized query
            table_name_part = table_name.split('.')[-1]
            try:
                validate_identifier(table_name_part, "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return []
            
            auth_context = get_auth_context()
            timestamp_sql = """
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = %s
                AND (
                    data_type IN ('datetime', 'timestamp', 'date') 
                    OR column_name LIKE '%time%' 
                    OR column_name LIKE '%date%'
                    OR column_name LIKE '%created%'
                    OR column_name LIKE '%updated%'
                )
            ORDER BY 
                CASE 
                    WHEN column_name LIKE '%updated%' THEN 1
                    WHEN column_name LIKE '%created%' THEN 2
                    WHEN column_name LIKE '%time%' THEN 3
                    ELSE 4
                END
            """
            
            result = await connection.execute(timestamp_sql, params=(table_name_part,), auth_context=auth_context)
            return [row["column_name"] for row in result.data] if result.data else []
            
        except Exception:
            return []
    
    async def _identify_data_flow_issues(self, table_freshness: Dict[str, Any]) -> List[Dict]:
        """Identify data flow issues"""
        issues = []
        
        # Identify consecutively stale tables (may indicate ETL process issues)
        stale_tables = [
            table_name for table_name, info in table_freshness.items() 
            if info.get("status") == "stale"
        ]
        
        if len(stale_tables) > len(table_freshness) * 0.3:  # More than 30% of tables are stale
            issues.append({
                "issue_type": "widespread_staleness",
                "severity": "high",
                "affected_tables": len(stale_tables),
                "total_tables": len(table_freshness),
                "description": f"High percentage of stale tables ({len(stale_tables)}/{len(table_freshness)})",
                "possible_causes": ["ETL pipeline failure", "Data source issues", "Processing delays"]
            })
        
        # Identify particularly stale tables
        very_stale_tables = [
            (table_name, info.get("staleness_hours", 0)) 
            for table_name, info in table_freshness.items() 
            if info.get("staleness_hours", 0) > 72  # More than 3 days
        ]
        
        if very_stale_tables:
            issues.append({
                "issue_type": "very_stale_data",
                "severity": "medium",
                "affected_tables": [table for table, _ in very_stale_tables],
                "max_staleness_hours": max(hours for _, hours in very_stale_tables),
                "description": "Some tables have very stale data (>72 hours)",
                "recommendation": "Check data ingestion processes for affected tables"
            })
        
        return issues
    
    def _generate_freshness_alerts(self, table_freshness: Dict[str, Any], threshold_hours: int) -> List[Dict]:
        """Generate freshness alerts"""
        alerts = []
        
        for table_name, info in table_freshness.items():
            staleness_hours = info.get("staleness_hours")
            status = info.get("status")
            
            if status == "stale" and staleness_hours:
                if staleness_hours > threshold_hours * 2:  # Exceeds threshold by 2x
                    alert_level = "critical"
                elif staleness_hours > threshold_hours * 1.5:  # Exceeds threshold by 1.5x
                    alert_level = "warning"
                else:
                    alert_level = "info"
                
                alerts.append({
                    "alert_level": alert_level,
                    "table_name": table_name,
                    "staleness_hours": staleness_hours,
                    "threshold_hours": threshold_hours,
                    "message": f"Table {table_name} is stale ({staleness_hours:.1f} hours old, threshold: {threshold_hours}h)",
                    "timestamp": datetime.now().isoformat()
                })
            
            elif status == "error":
                alerts.append({
                    "alert_level": "error",
                    "table_name": table_name,
                    "message": f"Unable to determine freshness for table {table_name}",
                    "error": info.get("error"),
                    "timestamp": datetime.now().isoformat()
                })
        
        return alerts 
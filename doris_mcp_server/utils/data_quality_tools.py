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
Atomic Data Quality Tools Module
Provides atomic data quality analysis tools for flexible composition
"""

import asyncio
import re
import time
import math
import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, cast
from collections import Counter, defaultdict

from .db import DorisConnectionManager
from .logger import get_logger
from .config import DorisConfig
from .sql_security_utils import (
    SQLSecurityError,
    validate_identifier,
    validate_integer,
    quote_identifier,
    build_table_reference,
    get_auth_context
)

logger = get_logger(__name__)


class DataQualityTools:
    """Atomic data quality analysis tools"""
    
    def __init__(self, connection_manager: DorisConnectionManager, config: DorisConfig = None):
        self.connection_manager = connection_manager
        self.config = config or DorisConfig.from_env()
        logger.info("DataQualityTools initialized with atomic tools")
    
    async def get_table_basic_info(
        self, 
        table_name: str,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get basic table information
        
        Args:
            table_name: Table name
            catalog_name: Catalog name (optional)
            db_name: Database name (optional)
        
        Returns:
            Dictionary containing basic table information:
            - table_name: Full table name
            - row_count: Number of rows
            - column_count: Number of columns
            - columns_info: List of column information
            - partitions_info: Partition information (if any)
            - table_size: Table size information
        """
        try:
            start_time = time.time()
            logger.info(f"🔍 Getting basic info for table: {table_name}")
            
            async with self.connection_manager.get_connection_context("query") as connection:
                # Build full table name
                full_table_name = self._build_full_table_name(table_name, catalog_name, db_name)
                logger.info(f"📝 Full table name: {full_table_name}")
                
                # Get basic table information
                table_info = await self._get_table_basic_info(connection, full_table_name)
                if not table_info:
                    return {"error": f"Table {full_table_name} not found"}
                
                # Get column information
                columns_info = await self._get_table_columns_info(connection, table_name, catalog_name, db_name)
                
                # Get partition information
                partitions_info = await self._get_table_partitions(connection, table_name, db_name)
                
                # Get table size information
                size_info = await self._get_table_size_info(connection, full_table_name)
                
                execution_time = time.time() - start_time
                
                result = {
                    "table_name": full_table_name,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "row_count": table_info["row_count"],
                    "column_count": len(columns_info),
                    "columns_info": columns_info,
                    "partitions_info": {
                        "partition_count": len(partitions_info),
                        "partitions": partitions_info
                    },
                    "table_size": size_info,
                    "execution_time_seconds": round(execution_time, 3)
                }
                
                logger.info(f"✅ Table info retrieved - Rows: {table_info['row_count']:,}, Columns: {len(columns_info)}, Partitions: {len(partitions_info)}")
                return result
                
        except Exception as e:
            logger.error(f"❌ Failed to get table basic info: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_columns(
        self, 
        table_name: str,
        columns: List[str],
        analysis_types: List[str] = ["both"],
        sample_size: int = 100000,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None,
        detailed_response: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze completeness and distribution of specified columns
        
        Args:
            table_name: Table name
            columns: List of column names to analyze
            analysis_types: List of analysis types, options: ["completeness", "distribution", "both"]
            sample_size: Sample size
            catalog_name: Catalog name (optional)
            db_name: Database name (optional)
            detailed_response: Whether to return detailed response
        
        Returns:
            Dictionary containing column analysis results:
            - table_name: Table name
            - columns_analyzed: Number of columns analyzed
            - completeness_analysis: Completeness analysis results (if requested)
            - distribution_analysis: Distribution analysis results (if requested)
            - sampling_info: Sampling information
        """
        try:
            start_time = time.time()
            sample_size = validate_integer(
                sample_size,
                "sample size",
                minimum=0,
                maximum=10_000_000,
            )
            logger.info(f"🔍 Analyzing columns for table: {table_name}")
            logger.info(f"📊 Columns to analyze: {columns}")
            logger.info(f"🎯 Analysis types: {analysis_types}")
            logger.info(f"📏 Sample size: {sample_size:,}")
            
            async with self.connection_manager.get_connection_context("query") as connection:
                # Build full table name
                full_table_name = self._build_full_table_name(table_name, catalog_name, db_name)
                
                # Get basic table information
                table_info = await self._get_table_basic_info(connection, full_table_name)
                if not table_info:
                    return {"error": f"Table {full_table_name} not found"}
                
                # Get column information
                all_columns_info = await self._get_table_columns_info(connection, table_name, catalog_name, db_name)
                
                # Filter specified columns
                target_columns_info = [col for col in all_columns_info if col["column_name"] in columns]
                if not target_columns_info:
                    return {"error": f"None of the specified columns found in table {full_table_name}"}
                
                # Check column count limit
                max_columns = self.config.data_quality.max_columns_per_batch
                if len(target_columns_info) > max_columns:
                    logger.warning(f"⚠️ Column count ({len(target_columns_info)}) exceeds batch limit ({max_columns}), processing first {max_columns} columns")
                    target_columns_info = target_columns_info[:max_columns]
                
                # Determine sampling strategy (optimized version)
                sampling_info = await self._determine_optimized_sampling_strategy(
                    connection, full_table_name, table_info["row_count"], sample_size
                )
                
                logger.info(f"📊 Using {sampling_info['sampling_method']} sampling: {sampling_info['sample_size']:,} rows")
                
                result = {
                    "table_name": full_table_name,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "columns_analyzed": len(target_columns_info),
                    "analysis_types": analysis_types,
                    "sampling_info": sampling_info
                }
                
                # Batch analysis (optimized version)
                if self.config.data_quality.enable_batch_analysis:
                    logger.info("🚀 Using batch analysis for improved performance...")
                    batch_results = await self._analyze_columns_batch(
                        connection, full_table_name, target_columns_info, sampling_info, analysis_types, detailed_response
                    )
                    result.update(batch_results)
                else:
                    # Execute completeness analysis
                    if "completeness" in analysis_types or "both" in analysis_types:
                        logger.info("🧩 Executing completeness analysis...")
                        completeness_start = time.time()
                        result["completeness_analysis"] = await self._analyze_completeness(
                            connection, full_table_name, target_columns_info, sampling_info
                        )
                        completeness_time = time.time() - completeness_start
                        logger.info(f"✅ Completeness analysis completed in {completeness_time:.2f}s")
                    
                    # Execute distribution analysis
                    if "distribution" in analysis_types or "both" in analysis_types:
                        logger.info("📈 Executing distribution analysis...")
                        distribution_start = time.time()
                        result["distribution_analysis"] = await self._analyze_distribution(
                            connection, full_table_name, target_columns_info, sampling_info, detailed_response
                        )
                        distribution_time = time.time() - distribution_start
                        logger.info(f"✅ Distribution analysis completed in {distribution_time:.2f}s")
                
                execution_time = time.time() - start_time
                result["execution_time_seconds"] = round(execution_time, 3)
                
                logger.info(f"🎉 Column analysis completed in {execution_time:.2f}s")
                return result
                
        except Exception as e:
            logger.error(f"❌ Failed to analyze columns: {str(e)}")
            return {"error": str(e)}
    
    async def analyze_table_storage(
        self, 
        table_name: str,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None,
        detailed_response: bool = False
    ) -> Dict[str, Any]:
        """
        Analyze table's physical distribution and storage information
        
        Args:
            table_name: Table name
            catalog_name: Catalog name (optional)
            db_name: Database name (optional)
            detailed_response: Whether to return detailed response
        
        Returns:
            Dictionary containing physical distribution and storage information:
            - table_name: Table name
            - physical_distribution: Physical distribution information
            - storage_info: Storage information
            - partition_distribution: Partition distribution information
        """
        try:
            start_time = time.time()
            logger.info(f"🔍 Analyzing storage for table: {table_name}")
            
            async with self.connection_manager.get_connection_context("query") as connection:
                # Build full table name
                full_table_name = self._build_full_table_name(table_name, catalog_name, db_name)
                
                # Get basic table information
                table_info = await self._get_table_basic_info(connection, full_table_name)
                if not table_info:
                    return {"error": f"Table {full_table_name} not found"}
                
                result = {
                    "table_name": full_table_name,
                    "analysis_timestamp": datetime.now().isoformat()
                }
                
                # Analyze physical distribution
                logger.info("🏗️ Analyzing physical distribution...")
                physical_start = time.time()
                result["physical_distribution"] = await self._analyze_physical_distribution(
                    connection, table_name, catalog_name, db_name, detailed_response
                )
                physical_time = time.time() - physical_start
                logger.info(f"✅ Physical distribution analysis completed in {physical_time:.2f}s")
                
                # Analyze storage information
                logger.info("💾 Analyzing storage information...")
                storage_start = time.time()
                result["storage_info"] = await self._analyze_storage_info(
                    connection, full_table_name, detailed_response
                )
                storage_time = time.time() - storage_start
                logger.info(f"✅ Storage analysis completed in {storage_time:.2f}s")
                
                execution_time = time.time() - start_time
                result["execution_time_seconds"] = round(execution_time, 3)
                
                logger.info(f"🎉 Storage analysis completed in {execution_time:.2f}s")
                return result
                
        except Exception as e:
            logger.error(f"❌ Failed to analyze table storage: {str(e)}")
            return {"error": str(e)}
    
    # ===========================================
    # Internal helper methods
    # ===========================================
    
    def _build_full_table_name(self, table_name: str, catalog_name: Optional[str], db_name: Optional[str]) -> str:
        """Build full table name with security validation"""
        # SECURITY FIX: Use build_table_reference for safe identifier handling
        return build_table_reference(table_name, db_name, catalog_name)
    
    async def _get_table_basic_info(self, connection, table_name: str) -> Optional[Dict]:
        """Get basic table information"""
        try:
            # SECURITY FIX: table_name should already be validated by _build_full_table_name
            # But we add auth_context for security validation
            auth_context = get_auth_context()
            
            # Try to get row count
            # SQL sink audit: table_name is produced by build_table_reference
            # before this private helper reaches DorisConnection.execute.
            count_sql = f"SELECT COUNT(*) as row_count FROM {table_name}"  # nosec B608
            result = await connection.execute(count_sql, auth_context=auth_context)
            if result.data:
                return {"row_count": result.data[0]["row_count"]}
            return None
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed: {str(e)}")
            return None
        except Exception as e:
            logger.warning(f"Failed to get table basic info: {str(e)}")
            return None
    
    async def _get_table_columns_info(self, connection, table_name: str, catalog_name: Optional[str], db_name: Optional[str]) -> List[Dict]:
        """Get table column information"""
        try:
            # SECURITY FIX: Build safe table reference and pass auth_context
            auth_context = get_auth_context()
            
            # Build DESCRIBE query with safe table reference
            safe_table_ref = self._build_full_table_name(table_name, catalog_name, db_name)
            describe_sql = f"DESCRIBE {safe_table_ref}"
            result = await connection.execute(describe_sql, auth_context=auth_context)
            
            columns_info = []
            if result.data:
                for row in result.data:
                    columns_info.append({
                        "column_name": row["Field"],
                        "data_type": row["Type"],
                        "nullable": row["Null"] == "YES",
                        "default_value": row["Default"],
                        "column_comment": row.get("Comment", "")
                    })
            
            return columns_info
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed: {str(e)}")
            return []
        except Exception as e:
            logger.warning(f"Failed to get table columns info: {str(e)}")
            return []
    
    async def _get_table_partitions(self, connection, table_name: str, db_name: Optional[str] = None) -> List[Dict]:
        """Get table partition information"""
        try:
            # SECURITY FIX: Validate identifiers and use parameterized query
            auth_context = get_auth_context()
            
            # Validate table_name
            try:
                validate_identifier(table_name, "table name")
                if db_name:
                    validate_identifier(db_name, "database name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid identifier rejected: {e}")
                return []
            
            # Build parameterized query
            params = []
            where_conditions = []
            
            if db_name:
                where_conditions.append("TABLE_SCHEMA = %s")
                params.append(db_name)
            else:
                where_conditions.append("TABLE_SCHEMA = ''")
            
            where_conditions.append("TABLE_NAME = %s")
            params.append(table_name)
            where_conditions.append("PARTITION_NAME IS NOT NULL")
            
            # SQL sink audit: WHERE fragments are fixed locally and all values
            # are bound through params before DorisConnection.execute.
            partition_sql = f"""
            SELECT 
                PARTITION_NAME,
                PARTITION_DESCRIPTION,
                TABLE_ROWS,
                DATA_LENGTH,
                INDEX_LENGTH
            FROM information_schema.PARTITIONS 
            WHERE {' AND '.join(where_conditions)}
            """  # nosec B608
            
            result = await connection.execute(partition_sql, params=tuple(params), auth_context=auth_context)
            partitions = []
            if result.data:
                for row in result.data:
                    partitions.append({
                        "partition_name": row["PARTITION_NAME"],
                        "partition_description": row["PARTITION_DESCRIPTION"],
                        "table_rows": row["TABLE_ROWS"],
                        "data_length": row["DATA_LENGTH"],
                        "index_length": row["INDEX_LENGTH"]
                    })
            
            return partitions
        except SQLSecurityError as e:
            logger.warning(f"Security validation failed: {str(e)}")
            return []
        except Exception as e:
            logger.warning(f"Failed to get table partitions: {str(e)}")
            return []

    async def _get_table_bucket_info(self, connection, table_name: str, db_name: Optional[str] = None) -> Optional[Dict]:
        """Get table buckets information"""
        try:
            # Query bucket information
            ddl_statement = await self._get_table_ddl(connection, table_name, db_name)
            if not ddl_statement:
                logger.error(f"Could not retrieve DDL for table {table_name}.")
                return None

            pattern = r"DISTRIBUTED BY (HASH\(([^)]+)\)|RANDOM) BUCKETS (\d+|AUTO)"
            matches = re.findall(pattern, cast(str, ddl_statement))

            if matches:
                dist_type, columns, buckets = matches[0]
                column_list = [col.strip().strip("`") for col in columns.split(",")]
                if dist_type.startswith('HASH'):
                    return {
                        "type": "HASH",
                        "columns": column_list,
                        "bucket_num": buckets,
                    }
                else:
                    return {
                        "type": "RANDOM",
                        "bucket_num": buckets,
                    }
        except Exception as e:
            logger.warning(f"Failed to get table buckets: {str(e)}")
            return None

    async def _get_table_ddl(
        self, connection, table_name: str, db_name: Optional[str]
    ) -> Optional[str]:
        """Get table DDL statement"""
        try:
            safe_table_ref = build_table_reference(table_name, db_name)
            query = f"SHOW CREATE TABLE {safe_table_ref}"
            auth_context = get_auth_context()
            result = await connection.execute(query, auth_context=auth_context)
            if result.data:
                return result.data[0].get("Create Table")
            return None
        except Exception as e:
            logger.error(f"Error getting DDL for table {table_name}: {e}")
            return None
    
    async def _get_table_size_info(self, connection, table_name: str) -> Dict[str, Any]:
        """Get table size information"""
        try:
            # SECURITY FIX: Validate and use parameterized query
            table_name_part = table_name.split('.')[-1]
            try:
                validate_identifier(table_name_part, "table name")
            except SQLSecurityError as e:
                logger.warning(f"Invalid table name rejected: {e}")
                return {"engine": "Unknown", "estimated_rows": 0, "data_length": 0, "index_length": 0, "total_size": 0}
            
            auth_context = get_auth_context()
            size_sql = """
            SELECT 
                table_name,
                engine,
                table_rows,
                data_length,
                index_length,
                (data_length + index_length) as total_size
            FROM information_schema.tables 
            WHERE table_name = %s
            """
            
            result = await connection.execute(size_sql, params=(table_name_part,), auth_context=auth_context)
            if result.data and result.data[0]:
                row = result.data[0]
                return {
                    "engine": row.get("engine", "Unknown"),
                    "estimated_rows": row.get("table_rows", 0),
                    "data_length": row.get("data_length", 0),
                    "index_length": row.get("index_length", 0),
                    "total_size": row.get("total_size", 0)
                }
            
            return {"engine": "Unknown", "estimated_rows": 0, "data_length": 0, "index_length": 0, "total_size": 0}
        except Exception as e:
            logger.warning(f"Failed to get table size info: {str(e)}")
            return {"engine": "Unknown", "estimated_rows": 0, "data_length": 0, "index_length": 0, "total_size": 0}
    
    async def _determine_sampling_strategy(self, connection, table_name: str, total_rows: int, sample_size: int) -> Dict[str, Any]:
        """Determine sampling strategy (compatibility version)"""
        return await self._determine_optimized_sampling_strategy(connection, table_name, total_rows, sample_size)
    
    async def _determine_optimized_sampling_strategy(self, connection, table_name: str, total_rows: int, sample_size: int) -> Dict[str, Any]:
        """Determine optimized sampling strategy"""
        safe_sample_size = validate_integer(
            sample_size,
            "sample size",
            minimum=0,
            maximum=10_000_000,
        )
        # Use thresholds from configuration
        small_threshold = self.config.data_quality.small_table_threshold
        medium_threshold = self.config.data_quality.medium_table_threshold
        
        if total_rows <= safe_sample_size or safe_sample_size <= 0:
            return {
                "sample_size": total_rows,
                "sample_rate": 1.0,
                "sample_table_expression": table_name,
                "sampling_method": "full_table",
                "total_rows": total_rows
            }
        
        sample_rate = safe_sample_size / total_rows
        
        # Stratified sampling strategy
        if total_rows <= small_threshold:
            # Small table: analyze full table directly
            return {
                "sample_size": total_rows,
                "sample_rate": 1.0,
                "sample_table_expression": table_name,
                "sampling_method": "full_table_small",
                "total_rows": total_rows
            }
        elif total_rows <= medium_threshold:
            # Medium table: simple LIMIT sampling (avoid ORDER BY RAND())
            # SQL sink audit: table -> build_table_reference; sample size ->
            # bounded integer; expression remains internal until execute.
            sample_table_expr = (
                f"(SELECT * FROM {table_name} LIMIT {safe_sample_size}) AS sample_table"  # nosec B608
            )
            return {
                "sample_size": safe_sample_size,
                "sample_rate": sample_rate,
                "sample_table_expression": sample_table_expr,
                "sampling_method": "limit_sampling",
                "total_rows": total_rows
            }
        else:
            # Large table: use simpler sampling strategy
            # For very large tables, still use LIMIT but increase sample size to improve representativeness
            adjusted_sample_size = min(
                safe_sample_size * 2,
                total_rows // 100,
            )  # At most 1% sampling
            # SQL sink audit: table -> build_table_reference; adjusted sample
            # size is derived from a bounded integer and DB row count before
            # the expression reaches DorisConnection.execute.
            sample_table_expr = (
                f"(SELECT * FROM {table_name} LIMIT {adjusted_sample_size}) AS sample_table"  # nosec B608
            )
            return {
                "sample_size": adjusted_sample_size,
                "sample_rate": adjusted_sample_size / total_rows,
                "sample_table_expression": sample_table_expr,
                "sampling_method": "enhanced_limit_sampling",
                "total_rows": total_rows,
                "original_sample_size": safe_sample_size
            }
    
    async def _analyze_columns_batch(self, connection, table_name: str, columns_info: List[Dict], 
                                   sampling_info: Dict, analysis_types: List[str], detailed_response: bool) -> Dict[str, Any]:
        """Batch analyze multiple columns (optimized version)"""
        result = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        try:
            # Build batch SQL queries
            if "completeness" in analysis_types or "both" in analysis_types:
                logger.info("🧩 Executing batch completeness analysis...")
                completeness_start = time.time()
                result["completeness_analysis"] = await self._analyze_completeness_batch(
                    connection, table_expr, columns_info
                )
                completeness_time = time.time() - completeness_start
                logger.info(f"✅ Batch completeness analysis completed in {completeness_time:.2f}s")
            
            if "distribution" in analysis_types or "both" in analysis_types:
                logger.info("📈 Executing batch distribution analysis...")
                distribution_start = time.time()
                result["distribution_analysis"] = await self._analyze_distribution_batch(
                    connection, table_expr, columns_info, detailed_response
                )
                distribution_time = time.time() - distribution_start
                logger.info(f"✅ Batch distribution analysis completed in {distribution_time:.2f}s")
            
            return result
            
        except Exception as e:
            logger.error(f"❌ Batch analysis failed: {str(e)}")
            # Fallback to sequential analysis
            logger.info("🔄 Falling back to sequential analysis...")
            return await self._analyze_columns_sequential(connection, table_name, columns_info, sampling_info, analysis_types, detailed_response)
    
    async def _analyze_columns_sequential(self, connection, table_name: str, columns_info: List[Dict], 
                                        sampling_info: Dict, analysis_types: List[str], detailed_response: bool) -> Dict[str, Any]:
        """Sequential column analysis (fallback solution)"""
        result = {}
        
        if "completeness" in analysis_types or "both" in analysis_types:
            result["completeness_analysis"] = await self._analyze_completeness(
                connection, table_name, columns_info, sampling_info
            )
        
        if "distribution" in analysis_types or "both" in analysis_types:
            result["distribution_analysis"] = await self._analyze_distribution(
                connection, table_name, columns_info, sampling_info, detailed_response
            )
        
        return result
    
    async def _analyze_completeness_batch(self, connection, table_expr: str, columns_info: List[Dict]) -> Dict[str, Any]:
        """Batch completeness analysis"""
        try:
            # Build batch completeness query
            select_clauses = []
            column_aliases = {}
            
            # First get total row count
            select_clauses.append("COUNT(*) as total_rows")
            
            # Then add statistics for each column
            for index, col in enumerate(columns_info):
                col_name = col["column_name"]
                safe_column = quote_identifier(col_name, "column name")
                non_null_alias = f"column_{index}_non_null"
                distinct_alias = f"column_{index}_distinct"
                column_aliases[col_name] = (non_null_alias, distinct_alias)
                select_clauses.extend([
                    f"COUNT({safe_column}) as {non_null_alias}",
                    f"COUNT(DISTINCT {safe_column}) as {distinct_alias}"
                ])
            
            # SQL sink audit: metadata columns -> quote_identifier; aliases are
            # index-derived; table_expr originates from a safe table/sampler
            # before DorisConnection.execute.
            batch_sql = (
                f"SELECT {', '.join(select_clauses)} FROM {table_expr}"  # nosec B608
            )
            
            auth_context = get_auth_context()
            result = await connection.execute(batch_sql, auth_context=auth_context)
            if not result.data:
                return {"error": "No data returned from batch completeness query"}
            
            row = result.data[0]
            completeness_results = {}
            total_rows = row["total_rows"]
            
            for col in columns_info:
                col_name = col["column_name"]
                non_null_alias, distinct_alias = column_aliases[col_name]
                non_null = row[non_null_alias]
                distinct = row[distinct_alias]
                
                null_count = total_rows - non_null
                null_rate = null_count / total_rows if total_rows > 0 else 0
                completeness_score = 1 - null_rate
                
                completeness_results[col_name] = {
                    "total_rows": total_rows,
                    "non_null_count": non_null,
                    "null_count": null_count,
                    "null_rate": round(null_rate, 4),
                    "completeness_score": round(completeness_score, 4),
                    "distinct_count": distinct,
                    "uniqueness_ratio": round(distinct / non_null, 4) if non_null > 0 else 0
                }
            
            return completeness_results
            
        except Exception as e:
            logger.error(f"❌ Batch completeness analysis failed: {str(e)}")
            raise
    
    async def _analyze_distribution_batch(self, connection, table_expr: str, columns_info: List[Dict], detailed_response: bool) -> Dict[str, Any]:
        """Batch distribution analysis"""
        try:
            # Classify columns
            numeric_columns = [col for col in columns_info if self._is_numeric_type(col["data_type"])]
            categorical_columns = [col for col in columns_info if self._is_categorical_type(col["data_type"])]
            temporal_columns = [col for col in columns_info if self._is_temporal_type(col["data_type"])]
            
            distribution_results = {}
            
            # Batch numeric analysis
            if numeric_columns:
                logger.info(f"📊 Batch analyzing {len(numeric_columns)} numeric columns...")
                numeric_results = await self._analyze_numeric_distributions_batch(connection, table_expr, numeric_columns)
                distribution_results.update(numeric_results)
            
            # Batch categorical analysis
            if categorical_columns:
                logger.info(f"📊 Batch analyzing {len(categorical_columns)} categorical columns...")
                categorical_results = await self._analyze_categorical_distributions_batch(connection, table_expr, categorical_columns)
                distribution_results.update(categorical_results)
            
            # Batch temporal analysis
            if temporal_columns:
                logger.info(f"📊 Batch analyzing {len(temporal_columns)} temporal columns...")
                temporal_results = await self._analyze_temporal_distributions_batch(connection, table_expr, temporal_columns)
                distribution_results.update(temporal_results)
            
            return distribution_results
            
        except Exception as e:
            logger.error(f"❌ Batch distribution analysis failed: {str(e)}")
            raise
    
    async def _analyze_numeric_distributions_batch(self, connection, table_expr: str, numeric_columns: List[Dict]) -> Dict[str, Any]:
        """Batch numeric distribution analysis"""
        try:
            select_clauses = []
            column_aliases = {}
            for index, col in enumerate(numeric_columns):
                col_name = col["column_name"]
                safe_column = quote_identifier(col_name, "column name")
                aliases = {
                    "min": f"column_{index}_min",
                    "max": f"column_{index}_max",
                    "avg": f"column_{index}_avg",
                    "stddev": f"column_{index}_stddev",
                }
                column_aliases[col_name] = aliases
                select_clauses.extend([
                    f"MIN({safe_column}) as {aliases['min']}",
                    f"MAX({safe_column}) as {aliases['max']}",
                    f"AVG({safe_column}) as {aliases['avg']}",
                    f"STDDEV({safe_column}) as {aliases['stddev']}"
                ])
            
            # SQL sink audit: metadata columns -> quote_identifier; aliases are
            # index-derived; table_expr originates from a safe table/sampler
            # before DorisConnection.execute.
            batch_sql = (
                f"SELECT {', '.join(select_clauses)} FROM {table_expr}"  # nosec B608
            )
            
            auth_context = get_auth_context()
            result = await connection.execute(batch_sql, auth_context=auth_context)
            if not result.data:
                return {}
            
            row = result.data[0]
            numeric_results = {}
            
            for col in numeric_columns:
                col_name = col["column_name"]
                aliases = column_aliases[col_name]
                numeric_results[col_name] = {
                    "data_type": "numeric",
                    "min_value": row[aliases["min"]],
                    "max_value": row[aliases["max"]],
                    "mean": round(float(row[aliases["avg"]]), 4)
                    if row[aliases["avg"]] is not None
                    else None,
                    "std_dev": round(float(row[aliases["stddev"]]), 4)
                    if row[aliases["stddev"]] is not None
                    else None,
                }
            
            return numeric_results
            
        except Exception as e:
            logger.error(f"❌ Batch numeric analysis failed: {str(e)}")
            return {}
    
    async def _analyze_categorical_distributions_batch(self, connection, table_expr: str, categorical_columns: List[Dict]) -> Dict[str, Any]:
        """Batch categorical distribution analysis"""
        categorical_results = {}
        
        # For categorical data, need to analyze column by column to get frequency distribution
        for col in categorical_columns:
            col_name = col["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # Get top 10 most frequent values
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                freq_sql = f"""
                SELECT {safe_column}, COUNT(*) as frequency
                FROM {table_expr}
                WHERE {safe_column} IS NOT NULL
                GROUP BY {safe_column}
                ORDER BY frequency DESC
                LIMIT 10
                """  # nosec B608
                
                auth_context = get_auth_context()
                result = await connection.execute(freq_sql, auth_context=auth_context)
                frequencies = result.data if result.data else []
                
                categorical_results[col_name] = {
                    "data_type": "categorical",
                    "top_values": frequencies
                }
                
            except Exception as e:
                logger.warning(f"Failed to analyze categorical column {col_name}: {str(e)}")
                categorical_results[col_name] = {
                    "data_type": "categorical",
                    "error": str(e)
                }
        
        return categorical_results
    
    async def _analyze_temporal_distributions_batch(self, connection, table_expr: str, temporal_columns: List[Dict]) -> Dict[str, Any]:
        """Batch temporal distribution analysis"""
        try:
            select_clauses = []
            column_aliases = {}
            for index, col in enumerate(temporal_columns):
                col_name = col["column_name"]
                safe_column = quote_identifier(col_name, "column name")
                aliases = {
                    "min": f"column_{index}_min",
                    "max": f"column_{index}_max",
                }
                column_aliases[col_name] = aliases
                select_clauses.extend([
                    f"MIN({safe_column}) as {aliases['min']}",
                    f"MAX({safe_column}) as {aliases['max']}",
                ])
            
            if not select_clauses:
                return {}
            
            # SQL sink audit: metadata columns -> quote_identifier; aliases are
            # index-derived; table_expr originates from a safe table/sampler
            # before DorisConnection.execute.
            batch_sql = (
                f"SELECT {', '.join(select_clauses)} FROM {table_expr}"  # nosec B608
            )
            
            auth_context = get_auth_context()
            result = await connection.execute(batch_sql, auth_context=auth_context)
            if not result.data:
                return {}
            
            row = result.data[0]
            temporal_results = {}
            
            for col in temporal_columns:
                col_name = col["column_name"]
                aliases = column_aliases[col_name]
                temporal_results[col_name] = {
                    "data_type": "temporal",
                    "min_value": row[aliases["min"]],
                    "max_value": row[aliases["max"]],
                }
            
            return temporal_results
            
        except Exception as e:
            logger.error(f"❌ Batch temporal analysis failed: {str(e)}")
            return {}
    
    async def _analyze_completeness(self, connection, table_name: str, columns_info: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Analyze column completeness"""
        logger.info(f"🔍 Analyzing completeness for {len(columns_info)} columns")
        
        completeness_results = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for i, column in enumerate(columns_info, 1):
            col_name = column["column_name"]
            logger.info(f"  📊 [{i}/{len(columns_info)}] Analyzing column: {col_name}")
            
            try:
                safe_column = quote_identifier(col_name, "column name")
                # Completeness analysis SQL
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                completeness_sql = f"""
                SELECT 
                    COUNT(*) as total_count,
                    COUNT({safe_column}) as non_null_count,
                    COUNT(*) - COUNT({safe_column}) as null_count
                FROM {table_expr}
                """  # nosec B608
                
                auth_context = get_auth_context()
                result = await connection.execute(completeness_sql, auth_context=auth_context)
                if result.data:
                    stats = result.data[0]
                    total_count = stats["total_count"]
                    non_null_count = stats["non_null_count"]
                    null_count = stats["null_count"]
                    
                    null_rate = null_count / total_count if total_count > 0 else 0
                    completeness_score = 1 - null_rate
                    
                    completeness_results[col_name] = {
                        "data_type": column["data_type"],
                        "total_count": total_count,
                        "non_null_count": non_null_count,
                        "null_count": null_count,
                        "null_rate": round(null_rate, 4),
                        "completeness_score": round(completeness_score, 4)
                    }
                    
                    if null_rate > 0.1:  # More than 10% null rate
                        logger.info(f"    ⚠️  High null rate: {null_rate:.1%}")
                    else:
                        logger.info(f"    ✅ Good completeness: {completeness_score:.1%}")
                        
            except Exception as e:
                logger.warning(f"Failed to analyze completeness for column {col_name}: {str(e)}")
                completeness_results[col_name] = {"error": str(e)}
        
        # Calculate overall completeness score
        valid_scores = [
            result["completeness_score"] 
            for result in completeness_results.values() 
            if isinstance(result, dict) and "completeness_score" in result
        ]
        overall_score = sum(valid_scores) / len(valid_scores) if valid_scores else 0
        
        return {
            "column_completeness": completeness_results,
            "overall_completeness_score": round(overall_score, 4),
            "summary": {
                "total_columns": len(columns_info),
                "analyzed_columns": len([r for r in completeness_results.values() if "error" not in r]),
                "perfect_completeness_columns": len([r for r in completeness_results.values() 
                                                   if isinstance(r, dict) and r.get("completeness_score") == 1.0])
            }
        }
    
    async def _analyze_distribution(self, connection, table_name: str, columns_info: List[Dict], sampling_info: Dict, detailed_response: bool) -> Dict[str, Any]:
        """Analyze column distribution"""
        logger.info(f"🔍 Analyzing distribution for {len(columns_info)} columns")
        
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        # Classify columns by type
        numeric_columns = [col for col in columns_info if self._is_numeric_type(col["data_type"])]
        categorical_columns = [col for col in columns_info if self._is_categorical_type(col["data_type"])]
        temporal_columns = [col for col in columns_info if self._is_temporal_type(col["data_type"])]
        
        logger.info(f"  📊 Column types - Numeric: {len(numeric_columns)}, Categorical: {len(categorical_columns)}, Temporal: {len(temporal_columns)}")
        
        distribution_results = {}
        
        # Analyze numeric columns
        if numeric_columns:
            logger.info("  📈 Analyzing numeric distributions...")
            distribution_results["numeric"] = await self._analyze_numeric_distributions(
                connection, table_expr, numeric_columns, detailed_response
            )
        
        # Analyze categorical columns
        if categorical_columns:
            logger.info("  📊 Analyzing categorical distributions...")
            distribution_results["categorical"] = await self._analyze_categorical_distributions(
                connection, table_expr, categorical_columns, detailed_response
            )
        
        # Analyze temporal columns
        if temporal_columns:
            logger.info("  📅 Analyzing temporal distributions...")
            distribution_results["temporal"] = await self._analyze_temporal_distributions(
                connection, table_expr, temporal_columns, detailed_response
            )
        
        return {
            "distribution_by_type": distribution_results,
            "summary": {
                "total_columns": len(columns_info),
                "numeric_columns": len(numeric_columns),
                "categorical_columns": len(categorical_columns),
                "temporal_columns": len(temporal_columns)
            }
        }
    
    def _is_numeric_type(self, data_type: str) -> bool:
        """Check if data type is numeric"""
        numeric_types = ["int", "bigint", "smallint", "tinyint", "float", "double", "decimal", "numeric"]
        return any(nt in data_type.lower() for nt in numeric_types)
    
    def _is_categorical_type(self, data_type: str) -> bool:
        """Check if data type is categorical"""
        categorical_types = ["varchar", "char", "string", "text", "enum"]
        return any(ct in data_type.lower() for ct in categorical_types)
    
    def _is_temporal_type(self, data_type: str) -> bool:
        """Check if data type is temporal"""
        temporal_types = ["date", "datetime", "timestamp", "time"]
        return any(tt in data_type.lower() for tt in temporal_types)
    
    async def _analyze_numeric_distributions(self, connection, table_expr: str, numeric_columns: List[Dict], detailed_response: bool) -> Dict[str, Any]:
        """Analyze numeric column distributions"""
        numeric_analysis = {}
        
        for column in numeric_columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                stats_sql = f"""
                SELECT 
                    COUNT({safe_column}) as non_null_count,
                    MIN({safe_column}) as min_value,
                    MAX({safe_column}) as max_value,
                    AVG({safe_column}) as mean_value,
                    STDDEV({safe_column}) as std_dev
                FROM {table_expr}
                WHERE {safe_column} IS NOT NULL
                """  # nosec B608
                
                auth_context = get_auth_context()
                result = await connection.execute(stats_sql, auth_context=auth_context)
                if result.data and result.data[0]["non_null_count"] > 0:
                    stats = result.data[0]
                    numeric_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "non_null_count": stats["non_null_count"],
                        "min_value": stats["min_value"],
                        "max_value": stats["max_value"],
                        "mean_value": round(float(stats["mean_value"]), 4) if stats["mean_value"] else None,
                        "std_dev": round(float(stats["std_dev"]), 4) if stats["std_dev"] else None
                    }
                    
                    # If detailed response is needed, add more statistical information
                    if detailed_response:
                        # Can add percentiles, skewness, kurtosis, etc.
                        pass
                        
            except Exception as e:
                logger.warning(f"Failed to analyze numeric column {col_name}: {str(e)}")
                numeric_analysis[col_name] = {"error": str(e)}
        
        return numeric_analysis
    
    async def _analyze_categorical_distributions(self, connection, table_expr: str, categorical_columns: List[Dict], detailed_response: bool) -> Dict[str, Any]:
        """Analyze categorical column distributions"""
        categorical_analysis = {}
        
        for column in categorical_columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # Basic statistics
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                cardinality_sql = f"""
                SELECT 
                    COUNT(DISTINCT {safe_column}) as cardinality,
                    COUNT({safe_column}) as non_null_count
                FROM {table_expr}
                WHERE {safe_column} IS NOT NULL
                """  # nosec B608
                
                auth_context = get_auth_context()
                cardinality_result = await connection.execute(cardinality_sql, auth_context=auth_context)
                
                if cardinality_result.data:
                    stats = cardinality_result.data[0]
                    cardinality = stats["cardinality"]
                    non_null_count = stats["non_null_count"]
                    
                    categorical_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "cardinality": cardinality,
                        "non_null_count": non_null_count
                    }
                    
                    # If cardinality is not too large, get distribution of top values
                    if cardinality <= 50 and detailed_response:
                        # SQL sink audit: metadata column -> quote_identifier;
                        # table_expr originates from a safe table/sampler before
                        # DorisConnection.execute.
                        top_values_sql = f"""
                        SELECT {safe_column}, COUNT(*) as count
                        FROM {table_expr}
                        WHERE {safe_column} IS NOT NULL
                        GROUP BY {safe_column}
                        ORDER BY COUNT(*) DESC
                        LIMIT 10
                        """  # nosec B608
                        
                        top_values_result = await connection.execute(top_values_sql, auth_context=auth_context)
                        if top_values_result.data:
                            categorical_analysis[col_name]["top_values"] = [
                                {"value": row[col_name], "count": row["count"]}
                                for row in top_values_result.data
                            ]
                        
            except Exception as e:
                logger.warning(f"Failed to analyze categorical column {col_name}: {str(e)}")
                categorical_analysis[col_name] = {"error": str(e)}
        
        return categorical_analysis
    
    async def _analyze_temporal_distributions(self, connection, table_expr: str, temporal_columns: List[Dict], detailed_response: bool) -> Dict[str, Any]:
        """Analyze temporal column distributions"""
        temporal_analysis = {}
        
        for column in temporal_columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                stats_sql = f"""
                SELECT 
                    COUNT({safe_column}) as non_null_count,
                    MIN({safe_column}) as min_date,
                    MAX({safe_column}) as max_date
                FROM {table_expr}
                WHERE {safe_column} IS NOT NULL
                """  # nosec B608
                
                auth_context = get_auth_context()
                result = await connection.execute(stats_sql, auth_context=auth_context)
                if result.data and result.data[0]["non_null_count"] > 0:
                    stats = result.data[0]
                    temporal_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "non_null_count": stats["non_null_count"],
                        "min_date": str(stats["min_date"]) if stats["min_date"] else None,
                        "max_date": str(stats["max_date"]) if stats["max_date"] else None
                    }
                    
                    # Calculate time span
                    if stats["min_date"] and stats["max_date"]:
                        try:
                            min_date = stats["min_date"]
                            max_date = stats["max_date"]
                            if hasattr(min_date, 'date') and hasattr(max_date, 'date'):
                                time_span = (max_date - min_date).days
                                temporal_analysis[col_name]["time_span_days"] = time_span
                        except:
                            pass
                        
            except Exception as e:
                logger.warning(f"Failed to analyze temporal column {col_name}: {str(e)}")
                temporal_analysis[col_name] = {"error": str(e)}
        
        return temporal_analysis
    
    async def _analyze_physical_distribution(self, connection, table_name: str, catalog_name: Optional[str], db_name: Optional[str], detailed_response: bool) -> Dict[str, Any]:
        """Analyze physical distribution"""
        try:
            # Get partition information
            partitions = await self._get_table_partitions(connection, table_name, db_name)
            
            # Analyze partition distribution
            partition_analysis = {
                "partition_count": len(partitions),
                "total_rows": sum(p.get("table_rows", 0) for p in partitions),
                "total_data_size": sum(p.get("data_length", 0) for p in partitions),
                "partitions": partitions if detailed_response else partitions[:5]  # Limit return count
            }
            
            # Calculate partition balance
            if len(partitions) > 1:
                row_counts = [p.get("table_rows", 0) for p in partitions if p.get("table_rows", 0) > 0]
                if len(row_counts) > 1:  # Need at least 2 non-zero values to calculate standard deviation
                    try:
                        avg_rows = sum(row_counts) / len(row_counts)
                        if avg_rows > 0:
                            std_dev = statistics.stdev(row_counts)
                            balance_score = 1 - (std_dev / avg_rows)
                            partition_analysis["balance_score"] = round(max(0, min(1, balance_score)), 4)
                        else:
                            partition_analysis["balance_score"] = 0.0
                    except statistics.StatisticsError:
                        partition_analysis["balance_score"] = 0.0
                else:
                    partition_analysis["balance_score"] = 1.0 if len(row_counts) == 1 else 0.0

            # Get bucket information
            bucket_info = await self._get_table_bucket_info(connection, table_name, db_name)
            
            return {
                "partition_analysis": partition_analysis,
                "bucket_analysis": bucket_info
            }
            
        except Exception as e:
            logger.warning(f"Failed to analyze physical distribution: {str(e)}")
            return {"error": str(e)}
    
    async def _analyze_storage_info(self, connection, table_name: str, detailed_response: bool) -> Dict[str, Any]:
        """Analyze storage information"""
        try:
            # Get storage information
            storage_info = await self._get_table_size_info(connection, table_name)
            
            # Calculate compression ratio and other information
            data_length = storage_info.get("data_length", 0)
            estimated_rows = storage_info.get("estimated_rows", 0)
            
            if data_length is not None and estimated_rows is not None and data_length > 0 and estimated_rows > 0:
                avg_row_size = data_length / estimated_rows
                storage_info["avg_row_size_bytes"] = round(avg_row_size, 2)
            
            # Storage efficiency analysis
            total_size = storage_info.get("total_size", 0)
            data_size = storage_info.get("data_length", 0)
            index_size = storage_info.get("index_length", 0)
            
            # Handle None values
            if total_size is None:
                total_size = 0
            if data_size is None:
                data_size = 0
            if index_size is None:
                index_size = 0
            
            if total_size > 0:
                storage_info["data_ratio"] = round(data_size / total_size, 4)
                storage_info["index_ratio"] = round(index_size / total_size, 4)
            else:
                # If no total_size, try to calculate from data_length and index_length
                if data_size > 0 or index_size > 0:
                    calculated_total = data_size + index_size
                    if calculated_total > 0:
                        storage_info["data_ratio"] = round(data_size / calculated_total, 4)
                        storage_info["index_ratio"] = round(index_size / calculated_total, 4)
                        storage_info["calculated_total_size"] = calculated_total
            
            return storage_info
            
        except Exception as e:
            logger.warning(f"Failed to analyze storage info: {str(e)}")
            return {"error": str(e)} 

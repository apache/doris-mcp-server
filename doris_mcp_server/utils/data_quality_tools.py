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
Unified Data Quality Tools Module
Provides comprehensive data quality analysis combining completeness and distribution analysis
"""

import asyncio
import re
import time
import math
import statistics
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import Counter, defaultdict

from .db import DorisConnectionManager
from .logger import get_logger

logger = get_logger(__name__)


class DataQualityTools:
    """Unified data quality analysis tools"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        logger.info("DataQualityTools initialized")
    
    async def analyze_data_quality(
        self, 
        table_name: str,
        analysis_scope: str = "comprehensive",
        sample_size: int = 100000,
        include_all_columns: bool = False,
        business_rules: Optional[List[Dict]] = None,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None,
        detailed_response: bool = False
    ) -> Dict[str, Any]:
        """
        Unified data quality analysis tool
        
        Args:
            table_name: Table name
            analysis_scope: Analysis scope ("completeness", "distribution", "comprehensive")
            sample_size: Sample size
            include_all_columns: Whether to analyze all columns
            business_rules: Business rules list
            catalog_name: Catalog name
            db_name: Database name
            detailed_response: Whether to return detailed response (default: False for optimized response)
        
        Returns:
            Unified data quality analysis result
        """
        try:
            start_time = time.time()
            connection = await self.connection_manager.get_connection("query")
            
            # Build full table name
            full_table_name = self._build_full_table_name(table_name, catalog_name, db_name)
            
            # Get table basic info
            table_info = await self._get_table_basic_info(connection, full_table_name)
            if not table_info:
                return {"error": f"Table {full_table_name} not found"}
            
            # Get column info
            columns_info = await self._get_table_columns_info(connection, table_name, catalog_name, db_name)
            
            # Determine sampling strategy
            sampling_info = await self._determine_sampling_strategy(
                connection, full_table_name, table_info["row_count"], sample_size
            )
            
            # Select analysis columns
            target_columns = self._select_analysis_columns(columns_info, include_all_columns)
            
            # Execute analysis
            results = {
                "table_name": full_table_name,
                "analysis_timestamp": datetime.now().isoformat(),
                "analysis_scope": analysis_scope,
                "table_summary": {
                    "total_rows": table_info["row_count"],
                    "total_columns": len(columns_info),
                    "columns_analyzed": len(target_columns),
                    "sample_info": sampling_info
                }
            }
            
            # Execute analysis tasks in parallel
            tasks = []
            
            if analysis_scope in ["completeness", "comprehensive"]:
                tasks.append(self._analyze_completeness_enhanced(
                    connection, full_table_name, target_columns, business_rules or [], sampling_info
                ))
            
            if analysis_scope in ["distribution", "comprehensive"]:
                tasks.append(self._analyze_distribution_enhanced(
                    connection, full_table_name, target_columns, sampling_info, table_name, catalog_name, db_name, detailed_response
                ))
            
            # Wait for all tasks to complete
            analysis_results = await asyncio.gather(*tasks)
            
            # Assemble results
            if analysis_scope in ["completeness", "comprehensive"]:
                completeness_idx = 0 if analysis_scope == "completeness" else 0
                results["completeness_analysis"] = analysis_results[completeness_idx]
            
            if analysis_scope in ["distribution", "comprehensive"]:
                distribution_idx = 0 if analysis_scope == "distribution" else (1 if analysis_scope == "comprehensive" else 0)
                results["distribution_analysis"] = analysis_results[distribution_idx]
            
            # Generate unified insights
            if analysis_scope == "comprehensive":
                results["unified_insights"] = await self._generate_unified_insights(
                    results.get("completeness_analysis", {}),
                    results.get("distribution_analysis", {})
                )
            
            execution_time = time.time() - start_time
            results["execution_time_seconds"] = round(execution_time, 3)
            
            return results
            
        except Exception as e:
            logger.error(f"Data quality analysis failed for {table_name}: {str(e)}")
            return {
                "error": str(e),
                "table_name": table_name,
                "analysis_timestamp": datetime.now().isoformat()
            }
    
    # ==== Backward Compatible Methods ====
    
    async def analyze_data_completeness(
        self, 
        table_name: str, 
        business_rules: Optional[List[Dict]] = None,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Backward compatible: data completeness analysis"""
        return await self.analyze_data_quality(
            table_name=table_name,
            analysis_scope="completeness",
            business_rules=business_rules,
            catalog_name=catalog_name,
            db_name=db_name
        )
    
    async def analyze_table_distribution(
        self, 
        table_name: str,
        sample_size: int = 100000,
        include_all_columns: bool = False,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Backward compatible: table distribution analysis"""
        return await self.analyze_data_quality(
            table_name=table_name,
            analysis_scope="distribution",
            sample_size=sample_size,
            include_all_columns=include_all_columns,
            catalog_name=catalog_name,
            db_name=db_name
        )
    
    # ==== Core Analysis Methods ====
    
    async def _analyze_completeness_enhanced(
        self, 
        connection, 
        table_name: str, 
        columns_info: List[Dict], 
        business_rules: List[Dict],
        sampling_info: Dict
    ) -> Dict[str, Any]:
        """Enhanced completeness analysis"""
        try:
            # Analyze column completeness
            column_completeness = await self._analyze_column_completeness_unified(
                connection, table_name, columns_info, sampling_info
            )
            
            # Business rule compliance check
            business_rule_compliance = {}
            if business_rules:
                business_rule_compliance = await self._check_business_rule_compliance(
                    connection, table_name, business_rules, sampling_info
                )
            
            # Data integrity issue detection
            integrity_issues = await self._detect_data_integrity_issues(
                connection, table_name, columns_info, sampling_info
            )
            
            # Calculate overall completeness score
            overall_score = self._calculate_completeness_score(column_completeness, business_rule_compliance)
            
            return {
                "overall_completeness_score": overall_score,
                "column_completeness": column_completeness,
                "business_rule_compliance": business_rule_compliance,
                "integrity_issues": integrity_issues,
                "recommendations": self._generate_completeness_recommendations(column_completeness, integrity_issues)
            }
            
        except Exception as e:
            logger.error(f"Completeness analysis failed: {str(e)}")
            return {"error": str(e)}
    
    async def _analyze_distribution_enhanced(
        self, 
        connection, 
        table_name: str, 
        columns_info: List[Dict], 
        sampling_info: Dict,
        base_table_name: str,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None,
        detailed_response: bool = False
    ) -> Dict[str, Any]:
        """Enhanced distribution analysis including physical data distribution"""
        try:
            start_time = time.time()
            
            # === 1. Statistical Data Distribution Analysis ===
            statistical_analysis = await self._analyze_statistical_distribution(
                connection, table_name, columns_info, sampling_info
            )
            
            # === 2. Physical Data Distribution Analysis ===
            physical_analysis = await self._analyze_physical_distribution(
                connection, base_table_name, catalog_name, db_name, detailed_response
            )
            
            # === 3. Storage Distribution Analysis ===
            storage_analysis = await self._analyze_storage_distribution(
                connection, table_name, sampling_info
            )
            
            # === 4. Generate comprehensive insights ===
            distribution_insights = await self._generate_distribution_insights(
                statistical_analysis, physical_analysis, storage_analysis
            )
            
            execution_time = time.time() - start_time
            
            return {
                "statistical_distribution": statistical_analysis,
                "physical_distribution": physical_analysis,
                "storage_distribution": storage_analysis,
                "distribution_insights": distribution_insights,
                "analysis_summary": {
                    "execution_time_seconds": round(execution_time, 3),
                    "analysis_timestamp": datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Distribution analysis failed: {str(e)}")
            return {"error": str(e)}
    
    async def _generate_unified_insights(
        self, 
        completeness_analysis: Dict, 
        distribution_analysis: Dict
    ) -> Dict[str, Any]:
        """Generate unified data quality insights"""
        try:
            # Comprehensive data quality scoring
            completeness_score = completeness_analysis.get("overall_completeness_score", 0.0)
            distribution_quality_score = distribution_analysis.get("quality_insights", {}).get("overall_distribution_quality_score", 0.0)
            
            # Weighted comprehensive score
            overall_data_quality_score = (completeness_score * 0.6 + distribution_quality_score * 0.4)
            
            # Collect all issues
            critical_issues = []
            
            # Completeness critical issues
            completeness_issues = completeness_analysis.get("integrity_issues", [])
            for issue in completeness_issues:
                if issue.get("severity") == "high":
                    critical_issues.append({
                        "category": "completeness",
                        "type": issue["type"],
                        "description": issue["description"],
                        "severity": issue["severity"]
                    })
            
            # Distribution quality critical issues
            distribution_issues = distribution_analysis.get("quality_insights", {}).get("quality_issues", [])
            for issue in distribution_issues:
                if issue.get("severity") in ["high", "critical"]:
                    critical_issues.append({
                        "category": "distribution",
                        "type": issue["issue_type"],
                        "description": issue["description"],
                        "severity": issue["severity"]
                    })
            
            # Generate unified recommendations
            unified_recommendations = self._generate_unified_recommendations(
                completeness_analysis, distribution_analysis, overall_data_quality_score
            )
            
            # Quality grade assessment
            quality_grade = self._assess_quality_grade(overall_data_quality_score)
            
            return {
                "overall_data_quality_score": round(overall_data_quality_score, 3),
                "quality_grade": quality_grade,
                "component_scores": {
                    "completeness_score": completeness_score,
                    "distribution_quality_score": distribution_quality_score
                },
                "critical_issues": critical_issues,
                "quality_recommendations": unified_recommendations,
                "analysis_summary": {
                    "total_issues_found": len(critical_issues),
                    "completeness_issues": len([i for i in critical_issues if i["category"] == "completeness"]),
                    "distribution_issues": len([i for i in critical_issues if i["category"] == "distribution"]),
                    "recommendations_count": len(unified_recommendations)
                }
            }
            
        except Exception as e:
            logger.error(f"Failed to generate unified insights: {str(e)}")
            return {"error": str(e)}
    
    # ==== Physical Distribution Analysis Methods ====
    
    async def _analyze_physical_distribution(
        self, 
        connection, 
        table_name: str,
        catalog_name: Optional[str] = None,
        db_name: Optional[str] = None,
        detailed_response: bool = False
    ) -> Dict[str, Any]:
        """Analyze physical data distribution across cluster nodes - returns aggregated metrics only"""
        try:
            # Get partition information
            partitions_info = await self._get_table_partitions(connection, table_name, db_name)
            
            if not partitions_info:
                return {
                    "analysis_type": "physical_distribution",
                    "partition_count": 0,
                    "error": "No partition information available"
                }
            
            # Aggregate all tablet information
            all_tablets = []
            total_partitions = len(partitions_info)
            partition_summary = self._summarize_partitions(partitions_info)
            
            # Collect tablet data from all partitions
            for partition in partitions_info:
                partition_name = partition["PartitionName"]
                tablets = await self._get_partition_tablets(connection, table_name, partition_name, db_name)
                all_tablets.extend(tablets)
            
            if not all_tablets:
                return {
                    "analysis_type": "physical_distribution",
                    "partition_count": total_partitions,
                    "partition_summary": partition_summary,
                    "tablet_count": 0,
                    "error": "No tablet information available"
                }
            
            # Aggregate node distribution metrics only (no raw data)
            node_distribution = defaultdict(lambda: {"tablet_count": 0, "data_size": 0, "partition_count": 0})
            backend_to_partitions = defaultdict(set)
            
            for tablet in all_tablets:
                backend_id = tablet.get("BackendId", "unknown")
                data_size = int(tablet.get("DataSize", 0))
                partition_name = tablet.get("PartitionName", "default")
                
                node_distribution[backend_id]["tablet_count"] += 1
                node_distribution[backend_id]["data_size"] += data_size
                backend_to_partitions[backend_id].add(partition_name)
            
            # Add partition count per backend
            for backend_id in node_distribution:
                node_distribution[backend_id]["partition_count"] = len(backend_to_partitions[backend_id])
            
            # Calculate aggregated distribution metrics
            distribution_metrics = self._calculate_distribution_metrics_aggregated(dict(node_distribution))
            balance_analysis = self._analyze_data_balance(node_distribution)
            
            # Base response (always included)
            result = {
                "analysis_type": "physical_distribution",
                "partition_count": total_partitions,
                "tablet_count": len(all_tablets),
                "backend_node_count": len(node_distribution),
                "distribution_summary": {
                    "backends": list(node_distribution.keys()),
                    "tablet_balance_score": distribution_metrics["tablet_balance_score"],
                    "data_balance_score": distribution_metrics["data_balance_score"],
                    "overall_balance_score": distribution_metrics["overall_balance_score"],
                    "total_data_size_bytes": distribution_metrics["total_data_size"],
                    "avg_tablets_per_backend": distribution_metrics["avg_tablets_per_backend"],
                    "max_tablets_per_backend": distribution_metrics["max_tablets_per_backend"],
                    "min_tablets_per_backend": distribution_metrics["min_tablets_per_backend"]
                },
                "balance_status": balance_analysis["status"],
                "risk_level": self._assess_distribution_risk(distribution_metrics),
                "recommendations": balance_analysis["recommendations"][:3]  # Limit to top 3 recommendations
            }
            
            # Add detailed information only if requested
            if detailed_response:
                result.update({
                    "partition_details": partitions_info,  # Full partition information
                    "tablet_details": all_tablets,  # Full tablet information
                    "node_distribution_details": dict(node_distribution),  # Detailed node distribution
                    "partition_summary": partition_summary,  # Extended partition summary
                    "full_balance_analysis": balance_analysis,  # Complete balance analysis
                    "full_recommendations": balance_analysis["recommendations"]  # All recommendations
                })
            else:
                # Only include summary information for optimized response
                result["partition_summary"] = partition_summary
            
            return result
            
        except Exception as e:
            logger.error(f"Physical distribution analysis failed: {str(e)}")
            return {
                "analysis_type": "physical_distribution",
                "error": f"Analysis failed: {str(e)}"
            }
    
    async def _get_table_partitions(self, connection, table_name: str, db_name: Optional[str] = None) -> List[Dict]:
        """Get table partition information using SHOW PARTITIONS"""
        try:
            if db_name:
                sql = f"SHOW PARTITIONS FROM `{db_name}`.`{table_name}`"
            else:
                sql = f"SHOW PARTITIONS FROM `{table_name}`"
            
            result = await connection.execute(sql)
            return result.data if result.data else []
            
        except Exception as e:
            logger.warning(f"Failed to get partitions for {table_name}: {str(e)}")
            return []
    
    async def _get_partition_tablets(self, connection, table_name: str, partition_name: str, db_name: Optional[str] = None) -> List[Dict]:
        """Get tablet information for a specific partition using SHOW TABLETS"""
        try:
            # First try with partition specification (for partitioned tables)
            if db_name:
                sql = f"SHOW TABLETS FROM `{db_name}`.`{table_name}` PARTITION(`{partition_name}`)"
            else:
                sql = f"SHOW TABLETS FROM `{table_name}` PARTITION(`{partition_name}`)"
            
            result = await connection.execute(sql)
            return result.data if result.data else []
            
        except Exception as e:
            logger.warning(f"Failed to get tablets for {table_name}.{partition_name}: {str(e)}")
            # Try alternative approach for non-partitioned tables
            try:
                if db_name:
                    sql = f"SHOW TABLETS FROM `{db_name}`.`{table_name}`"
                else:
                    sql = f"SHOW TABLETS FROM `{table_name}`"
                
                result = await connection.execute(sql)
                return result.data if result.data else []
            except Exception as e2:
                logger.warning(f"Alternative tablet query also failed: {str(e2)}")
                return []
    
    def _analyze_tablets_backend_distribution(self, tablets: List[Dict]) -> Dict[str, Any]:
        """Analyze how tablets are distributed across backend nodes"""
        backend_distribution = defaultdict(int)
        total_tablets = len(tablets)
        
        for tablet in tablets:
            backend_id = tablet.get("BackendId", "unknown")
            backend_distribution[backend_id] += 1
        
        if total_tablets == 0:
            return {"backend_count": 0, "distribution": {}, "balance_score": 1.0}
        
        # Calculate balance score (1.0 = perfect balance, 0.0 = completely unbalanced)
        if len(backend_distribution) <= 1:
            balance_score = 1.0
        else:
            tablet_counts = list(backend_distribution.values())
            avg_tablets = statistics.mean(tablet_counts)
            variance = statistics.variance(tablet_counts) if len(tablet_counts) > 1 else 0
            balance_score = max(0.0, 1.0 - (variance / (avg_tablets ** 2)))
        
        return {
            "backend_count": len(backend_distribution),
            "distribution": dict(backend_distribution),
            "balance_score": round(balance_score, 3),
            "total_tablets": total_tablets
        }
    
    def _calculate_distribution_metrics(self, node_distribution: Dict, tablet_distribution: Dict) -> Dict[str, Any]:
        """Calculate overall distribution metrics (legacy method for compatibility)"""
        if not node_distribution:
            return {"total_nodes": 0, "balance_score": 1.0}
        
        total_tablets = sum(node["tablet_count"] for node in node_distribution.values())
        total_data_size = sum(node["data_size"] for node in node_distribution.values())
        
        # Calculate tablet balance
        tablet_counts = [node["tablet_count"] for node in node_distribution.values()]
        tablet_balance_score = self._calculate_balance_score(tablet_counts)
        
        # Calculate data size balance
        data_sizes = [node["data_size"] for node in node_distribution.values()]
        data_balance_score = self._calculate_balance_score(data_sizes)
        
        return {
            "total_nodes": len(node_distribution),
            "total_tablets": total_tablets,
            "total_data_size": total_data_size,
            "tablet_balance_score": tablet_balance_score,
            "data_balance_score": data_balance_score,
            "overall_balance_score": round((tablet_balance_score + data_balance_score) / 2, 3)
        }
    
    def _calculate_distribution_metrics_aggregated(self, node_distribution: Dict) -> Dict[str, Any]:
        """Calculate aggregated distribution metrics for optimized response"""
        if not node_distribution:
            return {
                "total_nodes": 0,
                "tablet_balance_score": 1.0,
                "data_balance_score": 1.0,
                "overall_balance_score": 1.0,
                "total_data_size": 0,
                "avg_tablets_per_backend": 0,
                "max_tablets_per_backend": 0,
                "min_tablets_per_backend": 0
            }
        
        # Extract metrics
        tablet_counts = [node["tablet_count"] for node in node_distribution.values()]
        data_sizes = [node["data_size"] for node in node_distribution.values()]
        
        # Calculate balance scores
        tablet_balance_score = self._calculate_balance_score(tablet_counts)
        data_balance_score = self._calculate_balance_score(data_sizes)
        overall_balance_score = round((tablet_balance_score + data_balance_score) / 2, 3)
        
        # Aggregated statistics
        total_tablets = sum(tablet_counts)
        total_data_size = sum(data_sizes)
        avg_tablets_per_backend = round(total_tablets / len(node_distribution), 1)
        max_tablets_per_backend = max(tablet_counts) if tablet_counts else 0
        min_tablets_per_backend = min(tablet_counts) if tablet_counts else 0
        
        return {
            "total_nodes": len(node_distribution),
            "tablet_balance_score": tablet_balance_score,
            "data_balance_score": data_balance_score,
            "overall_balance_score": overall_balance_score,
            "total_data_size": total_data_size,
            "avg_tablets_per_backend": avg_tablets_per_backend,
            "max_tablets_per_backend": max_tablets_per_backend,
            "min_tablets_per_backend": min_tablets_per_backend
        }
    
    def _calculate_balance_score(self, values: List[float]) -> float:
        """Calculate balance score for a list of values"""
        if not values or len(values) <= 1:
            return 1.0
        
        avg_value = statistics.mean(values)
        if avg_value == 0:
            return 1.0
        
        variance = statistics.variance(values)
        balance_score = max(0.0, 1.0 - (variance / (avg_value ** 2)))
        return round(balance_score, 3)
    
    def _analyze_data_balance(self, node_distribution: Dict) -> Dict[str, Any]:
        """Analyze data balance across nodes and provide recommendations"""
        if not node_distribution:
            return {"status": "no_data", "recommendations": []}
        
        tablet_counts = [node["tablet_count"] for node in node_distribution.values()]
        data_sizes = [node["data_size"] for node in node_distribution.values()]
        
        tablet_balance = self._calculate_balance_score(tablet_counts)
        data_balance = self._calculate_balance_score(data_sizes)
        
        recommendations = []
        issues = []
        
        if tablet_balance < 0.8:
            issues.append("uneven_tablet_distribution")
            recommendations.append({
                "type": "rebalance_tablets",
                "priority": "medium",
                "description": "Tablet distribution is uneven across nodes",
                "action": "Consider rebalancing tablets or adjusting bucketing strategy"
            })
        
        if data_balance < 0.7:
            issues.append("uneven_data_distribution")
            recommendations.append({
                "type": "rebalance_data",
                "priority": "high",
                "description": "Data size distribution is significantly uneven",
                "action": "Review partitioning strategy and consider data rebalancing"
            })
        
        # Check for hot spots (nodes with significantly more data)
        if data_sizes:
            max_data = max(data_sizes)
            avg_data = statistics.mean(data_sizes)
            if max_data > avg_data * 2:
                issues.append("data_hotspot")
                recommendations.append({
                    "type": "hotspot_mitigation",
                    "priority": "high",
                    "description": "Detected potential data hotspots",
                    "action": "Investigate nodes with excessive data and redistribute load"
                })
        
        return {
            "tablet_balance_score": tablet_balance,
            "data_balance_score": data_balance,
            "issues": issues,
            "recommendations": recommendations,
            "status": "balanced" if tablet_balance > 0.8 and data_balance > 0.8 else "unbalanced"
        }
    
    def _summarize_partitions(self, partitions: List[Dict]) -> Dict[str, Any]:
        """Summarize partition information without returning full details"""
        if not partitions:
            return {"partition_count": 0}
        
        # Extract key metrics only
        partition_types = set()
        storage_mediums = set()
        total_data_size = 0
        bucket_counts = []
        
        for partition in partitions:
            # Get partition type (Range, List, etc.)
            partition_type = partition.get("Type", "Unknown")
            partition_types.add(partition_type)
            
            # Get storage medium
            storage_medium = partition.get("StorageMedium", "Unknown")
            storage_mediums.add(storage_medium)
            
            # Get data size (if available)
            data_size = partition.get("DataSize", 0)
            if isinstance(data_size, (int, float)):
                total_data_size += data_size
            
            # Get bucket count
            buckets = partition.get("Buckets", 0)
            if isinstance(buckets, int):
                bucket_counts.append(buckets)
        
        return {
            "partition_count": len(partitions),
            "partition_types": list(partition_types),
            "storage_mediums": list(storage_mediums),
            "total_data_size_bytes": total_data_size,
            "bucket_config": {
                "unique_bucket_counts": list(set(bucket_counts)) if bucket_counts else [],
                "avg_buckets": round(statistics.mean(bucket_counts), 1) if bucket_counts else 0
            }
        }
    
    def _assess_distribution_risk(self, distribution_metrics: Dict) -> str:
        """Assess distribution risk level based on balance scores"""
        tablet_balance = distribution_metrics.get("tablet_balance_score", 1.0)
        data_balance = distribution_metrics.get("data_balance_score", 1.0)
        overall_balance = distribution_metrics.get("overall_balance_score", 1.0)
        
        if overall_balance >= 0.9:
            return "low"
        elif overall_balance >= 0.7:
            return "medium"
        else:
            return "high"
    
    # ==== Statistical Distribution Analysis Methods ====
    
    async def _analyze_statistical_distribution(
        self, 
        connection, 
        table_name: str, 
        columns_info: List[Dict], 
        sampling_info: Dict
    ) -> Dict[str, Any]:
        """Analyze statistical data distribution patterns"""
        try:
            analysis_results = {}
            
            # Analyze numeric columns
            numeric_columns = [col for col in columns_info if self._is_numeric_type(col["data_type"])]
            if numeric_columns:
                analysis_results["numeric_columns"] = await self._analyze_numeric_distributions(
                    connection, table_name, numeric_columns, sampling_info
                )
            
            # Analyze categorical columns
            categorical_columns = [col for col in columns_info if self._is_categorical_type(col["data_type"])]
            if categorical_columns:
                analysis_results["categorical_columns"] = await self._analyze_categorical_distributions(
                    connection, table_name, categorical_columns, sampling_info
                )
            
            # Analyze temporal columns
            temporal_columns = [col for col in columns_info if self._is_temporal_type(col["data_type"])]
            if temporal_columns:
                analysis_results["temporal_columns"] = await self._analyze_temporal_distributions(
                    connection, table_name, temporal_columns, sampling_info
                )
            
            # Generate quality insights
            analysis_results["quality_insights"] = await self._generate_data_quality_insights(
                connection, table_name, columns_info, sampling_info
            )
            
            return analysis_results
            
        except Exception as e:
            logger.error(f"Statistical distribution analysis failed: {str(e)}")
            return {"error": str(e)}

    # ==== Storage Distribution Analysis Methods ====
    
    async def _analyze_storage_distribution(self, connection, table_name: str, sampling_info: Dict) -> Dict[str, Any]:
        """Analyze storage-level data distribution"""
        try:
            # Get storage medium information
            storage_info = await self._get_storage_information(connection, table_name)
            
            # Get data size distribution
            size_distribution = await self._get_data_size_distribution(connection, table_name)
            
            return {
                "storage_media": storage_info,
                "size_distribution": size_distribution,
                "compression_analysis": await self._analyze_compression_efficiency(connection, table_name)
            }
            
        except Exception as e:
            logger.error(f"Storage distribution analysis failed: {str(e)}")
            return {"error": str(e)}
    
    async def _get_storage_information(self, connection, table_name: str) -> Dict[str, Any]:
        """Get storage medium and policy information"""
        try:
            # This would typically come from SHOW PARTITIONS or system tables
            # For now, we'll return a placeholder structure
            return {
                "primary_medium": "HDD",
                "cold_storage_policy": None,
                "compression_type": "LZ4"
            }
        except Exception as e:
            logger.warning(f"Failed to get storage info: {str(e)}")
            return {}
    
    async def _get_data_size_distribution(self, connection, table_name: str) -> Dict[str, Any]:
        """Get data size distribution across partitions/tablets"""
        try:
            # Placeholder for data size analysis
            return {
                "total_size_bytes": 0,
                "avg_partition_size": 0,
                "size_variance": 0
            }
        except Exception as e:
            logger.warning(f"Failed to get size distribution: {str(e)}")
            return {}
    
    async def _analyze_compression_efficiency(self, connection, table_name: str) -> Dict[str, Any]:
        """Analyze data compression efficiency"""
        try:
            # Placeholder for compression analysis
            return {
                "compression_ratio": 1.0,
                "efficiency_score": 0.8
            }
        except Exception as e:
            logger.warning(f"Failed to analyze compression: {str(e)}")
            return {}
    
    # ==== Distribution Insights Generation ====
    
    async def _generate_distribution_insights(
        self, 
        statistical_analysis: Dict, 
        physical_analysis: Dict, 
        storage_analysis: Dict
    ) -> Dict[str, Any]:
        """Generate comprehensive distribution insights"""
        insights = {
            "overall_distribution_health": "good",
            "key_findings": [],
            "recommendations": [],
            "risk_assessment": "low"
        }
        
        # Analyze physical distribution health
        if "distribution_metrics" in physical_analysis:
            balance_score = physical_analysis["distribution_metrics"].get("overall_balance_score", 1.0)
            if balance_score < 0.7:
                insights["overall_distribution_health"] = "poor"
                insights["risk_assessment"] = "high"
                insights["key_findings"].append("Significant data imbalance detected across cluster nodes")
                insights["recommendations"].append({
                    "type": "cluster_rebalancing",
                    "priority": "high",
                    "description": "Implement data rebalancing to improve cluster performance"
                })
            elif balance_score < 0.9:
                insights["overall_distribution_health"] = "fair"
                insights["risk_assessment"] = "medium"
        
        # Analyze statistical distribution patterns
        if "quality_insights" in statistical_analysis:
            quality_score = statistical_analysis["quality_insights"].get("overall_distribution_quality_score", 1.0)
            if quality_score < 0.8:
                insights["key_findings"].append("Data quality issues detected in statistical distribution")
        
        return insights

    # ==== Utility Methods ====
    
    def _build_full_table_name(self, table_name: str, catalog_name: Optional[str], db_name: Optional[str]) -> str:
        """Build full table name"""
        if catalog_name and db_name:
            return f"{catalog_name}.{db_name}.{table_name}"
        elif db_name:
            return f"internal.{db_name}.{table_name}"
        else:
            # Default to internal as catalog
            return f"internal.information_schema.{table_name}" if "." not in table_name else table_name
    
    async def _get_table_basic_info(self, connection, table_name: str) -> Optional[Dict]:
        """Get table basic information"""
        try:
            parts = table_name.split('.')
            if len(parts) >= 3:
                catalog, db, tbl = parts[0], parts[1], parts[2]
                sql = f"SELECT COUNT(*) as row_count FROM {table_name}"
            else:
                sql = f"SELECT COUNT(*) as row_count FROM {table_name}"
            
            result = await connection.execute(sql)
            if result.data:
                return {"row_count": result.data[0]["row_count"]}
            return None
        except Exception as e:
            logger.warning(f"Failed to get table basic info: {str(e)}")
            return None
    
    async def _get_table_columns_info(self, connection, table_name: str, catalog_name: Optional[str], db_name: Optional[str]) -> List[Dict]:
        """Get table column information"""
        try:
            # Use DESCRIBE statement to get column information
            describe_sql = f"DESCRIBE {self._build_full_table_name(table_name, catalog_name, db_name)}"
            result = await connection.execute(describe_sql)
            
            columns = []
            if result.data:
                for row in result.data:
                    columns.append({
                        "column_name": row["Field"],
                        "data_type": row["Type"],
                        "is_nullable": row["Null"] == "YES"
                    })
            
            return columns
        except Exception as e:
            logger.warning(f"Failed to get table columns info: {str(e)}")
            return []

    async def _determine_sampling_strategy(self, connection, table_name: str, total_rows: int, sample_size: int) -> Dict[str, Any]:
        """Determine sampling strategy"""
        if total_rows <= sample_size:
            return {
                "is_sampled": False,
                "sample_size": total_rows,
                "sample_rate": 1.0,
                "sample_table_expression": table_name,
                "sample_query_suffix": ""
            }
        else:
            sample_rate = sample_size / total_rows
            return {
                "is_sampled": True,
                "sample_size": sample_size,
                "sample_rate": round(sample_rate, 4),
                "sample_table_expression": f"(SELECT * FROM {table_name} ORDER BY RAND() LIMIT {sample_size}) AS sampled_table",
                "sample_query_suffix": f"ORDER BY RAND() LIMIT {sample_size}"
            }
    
    def _select_analysis_columns(self, columns_info: List[Dict], include_all: bool) -> List[Dict]:
        """Select columns to analyze"""
        if include_all:
            return columns_info
        
        # Select key column types
        key_columns = []
        for col in columns_info:
            col_name = col["column_name"].lower()
            data_type = col["data_type"].lower()
            
            # Skip system columns and binary columns
            if col_name.startswith('__') or 'binary' in data_type or 'blob' in data_type:
                continue
            
            key_columns.append(col)
        
        return key_columns[:20]  # Limit to max 20 columns
    
    def _is_numeric_type(self, data_type: str) -> bool:
        """Determine if it's a numeric type"""
        numeric_types = ['int', 'bigint', 'smallint', 'tinyint', 'decimal', 'float', 'double']
        return any(t in data_type.lower() for t in numeric_types)
    
    def _is_categorical_type(self, data_type: str) -> bool:
        """Determine if it's a categorical type"""
        return not self._is_numeric_type(data_type) and not self._is_temporal_type(data_type)
    
    def _is_temporal_type(self, data_type: str) -> bool:
        """Determine if it's a temporal type"""
        temporal_types = ['date', 'datetime', 'timestamp', 'time']
        return any(t in data_type.lower() for t in temporal_types)
    
    async def _analyze_column_completeness_unified(self, connection, table_name: str, columns_info: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Unified column completeness analysis"""
        column_completeness = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for column in columns_info:
            column_name = column["column_name"]
            try:
                null_sql = f"""
                SELECT 
                    COUNT(*) as total_count,
                    COUNT({column_name}) as non_null_count,
                    COUNT(*) - COUNT({column_name}) as null_count
                FROM {table_expr}
                """
                
                result = await connection.execute(null_sql)
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
                    
            except Exception as e:
                logger.warning(f"Failed to analyze completeness for column {column_name}: {str(e)}")
                column_completeness[column_name] = {
                    "error": str(e),
                    "completeness_score": 0.0
                }
        
        return column_completeness
    
    async def _check_business_rule_compliance(self, connection, table_name: str, business_rules: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Check business rule compliance"""
        compliance_results = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for rule in business_rules:
            rule_name = rule.get("rule_name", "unknown")
            sql_condition = rule.get("sql_condition", "")
            
            if not sql_condition:
                continue
                
            try:
                compliance_sql = f"""
                SELECT 
                    COUNT(*) as total_count,
                    SUM(CASE WHEN {sql_condition} THEN 1 ELSE 0 END) as pass_count
                FROM {table_expr}
                """
                
                result = await connection.execute(compliance_sql)
                if result.data:
                    stats = result.data[0]
                    total_count = stats["total_count"]
                    pass_count = stats["pass_count"] or 0
                    fail_count = total_count - pass_count
                    pass_rate = pass_count / total_count if total_count > 0 else 0
                    
                    compliance_results[rule_name] = {
                        "rule_condition": sql_condition,
                        "total_records": total_count,
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
    
    async def _detect_data_integrity_issues(self, connection, table_name: str, columns_info: List[Dict], sampling_info: Dict) -> List[Dict]:
        """Detect data integrity issues"""
        issues = []
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        try:
            # Detect duplicate values in primary key fields
            primary_key_columns = [col["column_name"] for col in columns_info if "primary" in col.get("column_comment", "").lower()]
            
            for pk_col in primary_key_columns:
                duplicate_sql = f"""
                SELECT COUNT(*) as duplicate_count
                FROM (
                    SELECT {pk_col}, COUNT(*) as cnt
                    FROM {table_expr}
                    WHERE {pk_col} IS NOT NULL
                    GROUP BY {pk_col}
                    HAVING COUNT(*) > 1
                ) t
                """
                
                result = await connection.execute(duplicate_sql)
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
    
    # For simplicity, only add key distribution analysis methods here
    async def _analyze_numeric_distributions(self, connection, table_name: str, numeric_columns: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Analyze numeric column distributions"""
        numeric_analysis = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for column in numeric_columns:
            col_name = column["column_name"]
            try:
                stats_sql = f"""
                SELECT 
                    COUNT({col_name}) as non_null_count,
                    MIN({col_name}) as min_value,
                    MAX({col_name}) as max_value,
                    AVG({col_name}) as mean_value,
                    STDDEV({col_name}) as std_dev
                FROM {table_expr}
                WHERE {col_name} IS NOT NULL
                """
                
                result = await connection.execute(stats_sql)
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
                    
            except Exception as e:
                logger.warning(f"Failed to analyze numeric column {col_name}: {str(e)}")
                numeric_analysis[col_name] = {"error": str(e)}
        
        return numeric_analysis
    
    async def _analyze_categorical_distributions(self, connection, table_name: str, categorical_columns: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Analyze categorical column distributions"""
        categorical_analysis = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for column in categorical_columns:
            col_name = column["column_name"]
            try:
                cardinality_sql = f"""
                SELECT 
                    COUNT(DISTINCT {col_name}) as cardinality,
                    COUNT({col_name}) as non_null_count
                FROM {table_expr}
                WHERE {col_name} IS NOT NULL
                """
                
                cardinality_result = await connection.execute(cardinality_sql)
                
                if cardinality_result.data:
                    cardinality_data = cardinality_result.data[0]
                    cardinality = cardinality_data["cardinality"]
                    non_null_count = cardinality_data["non_null_count"]
                    
                    categorical_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "cardinality": cardinality,
                        "non_null_count": non_null_count,
                        "diversity_score": round(cardinality / non_null_count, 4) if non_null_count > 0 else 0
                    }
                    
            except Exception as e:
                logger.warning(f"Failed to analyze categorical column {col_name}: {str(e)}")
                categorical_analysis[col_name] = {"error": str(e)}
        
        return categorical_analysis
    
    async def _analyze_temporal_distributions(self, connection, table_name: str, temporal_columns: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Analyze temporal column distributions"""
        temporal_analysis = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for column in temporal_columns:
            col_name = column["column_name"]
            try:
                range_sql = f"""
                SELECT 
                    COUNT({col_name}) as non_null_count,
                    MIN({col_name}) as earliest,
                    MAX({col_name}) as latest
                FROM {table_expr}
                WHERE {col_name} IS NOT NULL
                """
                
                range_result = await connection.execute(range_sql)
                
                if range_result.data and range_result.data[0]["non_null_count"] > 0:
                    range_data = range_result.data[0]
                    earliest = range_data["earliest"]
                    latest = range_data["latest"]
                    
                    temporal_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "non_null_count": range_data["non_null_count"],
                        "date_range": {
                            "earliest": str(earliest),
                            "latest": str(latest)
                        }
                    }
                    
            except Exception as e:
                logger.warning(f"Failed to analyze temporal column {col_name}: {str(e)}")
                temporal_analysis[col_name] = {"error": str(e)}
        
        return temporal_analysis
    
    async def _generate_data_quality_insights(self, connection, table_name: str, columns_info: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Generate data quality insights"""
        try:
            total_columns = len(columns_info)
            
            # Calculate null rate statistics
            null_analysis = await self._analyze_overall_null_rates(connection, table_name, columns_info, sampling_info)
            
            # Identify potential data quality issues
            quality_issues = []
            
            # High null rate columns
            high_null_columns = [col for col, rate in null_analysis["column_null_rates"].items() if rate > 0.2]
            if high_null_columns:
                quality_issues.append({
                    "issue_type": "high_null_rates",
                    "severity": "medium",
                    "affected_columns": high_null_columns,
                    "description": f"{len(high_null_columns)} columns have null rates > 20%"
                })
            
            # Calculate overall distribution quality score
            avg_null_rate = sum(null_analysis["column_null_rates"].values()) / len(null_analysis["column_null_rates"]) if null_analysis["column_null_rates"] else 0
            overall_distribution_quality_score = max(0, 1 - avg_null_rate)
            
            return {
                "total_columns_analyzed": total_columns,
                "null_analysis": null_analysis,
                "overall_distribution_quality_score": round(overall_distribution_quality_score, 3),
                "quality_issues": quality_issues
            }
            
        except Exception as e:
            logger.warning(f"Failed to generate data quality insights: {str(e)}")
            return {"overall_distribution_quality_score": 0.0, "error": str(e)}
    
    async def _analyze_overall_null_rates(self, connection, table_name: str, columns: List[Dict], sampling_info: Dict) -> Dict[str, Any]:
        """Analyze overall null rates"""
        column_null_rates = {}
        table_expr = sampling_info.get("sample_table_expression", table_name)
        
        for column in columns:
            col_name = column["column_name"]
            try:
                null_sql = f"""
                SELECT 
                    COUNT(*) as total_count,
                    COUNT({col_name}) as non_null_count
                FROM {table_expr}
                """
                
                result = await connection.execute(null_sql)
                if result.data:
                    data = result.data[0]
                    total_count = data["total_count"]
                    non_null_count = data["non_null_count"]
                    null_count = total_count - non_null_count
                    null_rate = null_count / total_count if total_count > 0 else 0
                    
                    column_null_rates[col_name] = round(null_rate, 4)
                    
            except Exception as e:
                logger.warning(f"Failed to analyze null rate for {col_name}: {str(e)}")
                column_null_rates[col_name] = 1.0  # Assume worst case
        
        return {"column_null_rates": column_null_rates}
    
    def _assess_quality_grade(self, score: float) -> str:
        """Assess quality grade"""
        if score >= 0.95:
            return "A+"
        elif score >= 0.90:
            return "A"
        elif score >= 0.80:
            return "B"
        elif score >= 0.70:
            return "C"
        elif score >= 0.60:
            return "D"
        else:
            return "F" 
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
Data Exploration Tools Module
Provides table data distribution analysis and exploration capabilities
"""

import math
from datetime import datetime
from typing import Any

from .db import DorisConnection, DorisConnectionManager
from .logger import get_logger
from .sql_security_utils import (
    SQLSecurityError,
    build_table_reference,
    get_auth_context,
    quote_identifier,
    validate_identifier,
    validate_integer,
)

logger = get_logger(__name__)


class DataExplorationTools:
    """Data exploration tools for table distribution analysis"""

    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
        logger.info("DataExplorationTools initialized")



    # ==================== Private Helper Methods ====================

    def _build_full_table_name(self, table_name: str, catalog_name: str | None, db_name: str | None) -> str:
        """Build full table name with catalog and database using three-part naming convention"""
        # SECURITY FIX: Use build_table_reference for safe identifier handling
        effective_catalog = catalog_name if catalog_name else "internal"

        if db_name:
            return build_table_reference(table_name, db_name, effective_catalog)
        else:
            return build_table_reference(table_name, catalog_name=effective_catalog)

    async def _get_table_basic_info(
        self,
        connection: DorisConnection,
        table_name: str,
    ) -> dict[str, Any] | None:
        """Get basic table information including row count"""
        try:
            # SECURITY FIX: Get auth_context for security validation
            # table_name should already be validated by _build_full_table_name
            auth_context = get_auth_context()

            # SQL sink audit: table_name is produced by build_table_reference
            # before this private helper reaches DorisConnection.execute.
            count_sql = f"SELECT COUNT(*) as row_count FROM {table_name}"  # nosec B608
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

    async def _get_table_columns_info(
        self,
        connection: DorisConnection,
        table_name: str,
        catalog_name: str | None,
        db_name: str | None,
    ) -> list[dict[str, Any]]:
        """Get detailed column information"""
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

            # Build parameterized query
            params: list[str] = [table_name]
            where_conditions = ["table_name = %s"]

            if db_name:
                where_conditions.append("table_schema = %s")
                params.append(db_name)
            else:
                where_conditions.append("table_schema = DATABASE()")

            # SQL sink audit: WHERE fragments are fixed locally and all values
            # are bound through params before DorisConnection.execute.
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
            """  # nosec B608

            result = await connection.execute(columns_sql, params=tuple(params), auth_context=auth_context)
            return result.data if result.data else []

        except SQLSecurityError as e:
            logger.warning(f"Security validation failed: {str(e)}")
            return []
        except Exception as e:
            logger.warning(f"Failed to get columns info for table {table_name}: {str(e)}")
            return []

    async def _determine_sampling_strategy(
        self,
        connection: DorisConnection,
        table_name: str,
        total_rows: int,
        sample_size: int,
    ) -> dict[str, Any]:
        """Determine optimal sampling strategy based on table size"""
        safe_sample_size = validate_integer(
            sample_size,
            "sample size",
            minimum=0,
            maximum=10_000_000,
        )
        if total_rows <= safe_sample_size:
            # Use all data if table is small enough
            return {
                "total_rows": total_rows,
                "sample_size": total_rows,
                "sampling_method": "full_scan",
                "sampling_ratio": 1.0,
                "use_sampling": False,
                "sample_table_expression": table_name
            }
        else:
            # Use random sampling for large tables
            sampling_ratio = safe_sample_size / total_rows
            return {
                "total_rows": total_rows,
                "sample_size": safe_sample_size,
                "sampling_method": "random_sample",
                "sampling_ratio": round(sampling_ratio, 4),
                "use_sampling": True,
                # SQL sink audit: table -> build_table_reference; sample size ->
                # bounded integer; expression remains internal until execute.
                "sample_table_expression": (
                    f"(SELECT * FROM {table_name} ORDER BY RAND() "
                    f"LIMIT {safe_sample_size}) as sample_table"  # nosec B608
                ),
            }

    def _select_analysis_columns(self, columns_info: list[dict], include_all: bool) -> list[dict]:
        """Select columns for analysis based on strategy"""
        if include_all:
            return columns_info

        # If not analyzing all columns, prioritize key columns
        priority_keywords = ['id', 'key', 'code', 'status', 'type', 'amount', 'count', 'date', 'time']

        priority_columns = []
        other_columns = []

        for col in columns_info:
            col_name_lower = col["column_name"].lower()
            if any(keyword in col_name_lower for keyword in priority_keywords):
                priority_columns.append(col)
            else:
                other_columns.append(col)

        # Return priority columns plus first 10 other columns
        return priority_columns + other_columns[:10]

    def _is_numeric_type(self, data_type: str) -> bool:
        """Check if column type is numeric"""
        numeric_types = [
            'tinyint', 'smallint', 'int', 'bigint', 'largeint',
            'float', 'double', 'decimal', 'numeric'
        ]
        return any(num_type in data_type.lower() for num_type in numeric_types)

    def _is_categorical_type(self, data_type: str) -> bool:
        """Check if column type is categorical"""
        categorical_types = ['varchar', 'char', 'string', 'text', 'enum']
        return any(cat_type in data_type.lower() for cat_type in categorical_types)

    def _is_temporal_type(self, data_type: str) -> bool:
        """Check if column type is temporal"""
        temporal_types = ['date', 'datetime', 'timestamp', 'time']
        return any(temp_type in data_type.lower() for temp_type in temporal_types)

    async def _analyze_numeric_distributions(
        self,
        connection: DorisConnection,
        table_name: str,
        numeric_columns: list[dict[str, Any]],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze distribution patterns for numeric columns"""
        numeric_analysis = {}

        for column in numeric_columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # Basic statistics
                table_expr = sampling_info.get("sample_table_expression", table_name)
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                stats_sql = f"""
                SELECT
                    COUNT({safe_column}) as count,
                    MIN({safe_column}) as min_value,
                    MAX({safe_column}) as max_value,
                    AVG({safe_column}) as mean_value,
                    STDDEV({safe_column}) as std_dev
                FROM {table_expr}
                WHERE {safe_column} IS NOT NULL
                """  # nosec B608

                auth_context = get_auth_context()
                stats_result = await connection.execute(stats_sql, auth_context=auth_context)

                if stats_result.data and stats_result.data[0]["count"] > 0:
                    stats = stats_result.data[0]

                    # Percentiles calculation
                    percentiles = await self._calculate_percentiles(connection, table_name, col_name, sampling_info)

                    # Outlier detection
                    outliers = await self._detect_numeric_outliers(connection, table_name, col_name, percentiles, sampling_info)

                    # Distribution shape analysis
                    distribution_shape = await self._analyze_distribution_shape(
                        connection, table_name, col_name, stats, percentiles, sampling_info
                    )

                    numeric_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "statistics": {
                            "count": stats["count"],
                            "mean": round(float(stats["mean_value"]), 4) if stats["mean_value"] else None,
                            "std": round(float(stats["std_dev"]), 4) if stats["std_dev"] else None,
                            "min": float(stats["min_value"]) if stats["min_value"] else None,
                            "max": float(stats["max_value"]) if stats["max_value"] else None,
                            **percentiles
                        },
                        "distribution_shape": distribution_shape,
                        "outliers": outliers
                    }

            except Exception as e:
                logger.warning(f"Failed to analyze numeric column {col_name}: {str(e)}")
                numeric_analysis[col_name] = {"error": str(e)}

        return numeric_analysis

    async def _calculate_percentiles(
        self,
        connection: DorisConnection,
        table_name: str,
        col_name: str,
        sampling_info: dict[str, Any],
    ) -> dict[str, float | None]:
        """Calculate percentiles for numeric column"""
        try:
            safe_column = quote_identifier(col_name, "column name")
            table_expr = sampling_info.get("sample_table_expression", table_name)
            # SQL sink audit: metadata column -> quote_identifier; table_expr
            # originates from a safe table/sampler before
            # DorisConnection.execute.
            percentile_sql = f"""
            SELECT
                PERCENTILE({safe_column}, 0.25) as p25,
                PERCENTILE({safe_column}, 0.50) as p50,
                PERCENTILE({safe_column}, 0.75) as p75,
                PERCENTILE({safe_column}, 0.90) as p90,
                PERCENTILE({safe_column}, 0.95) as p95,
                PERCENTILE({safe_column}, 0.99) as p99
            FROM {table_expr}
            WHERE {safe_column} IS NOT NULL
            """  # nosec B608

            auth_context = get_auth_context()
            result = await connection.execute(percentile_sql, auth_context=auth_context)

            if result.data:
                data = result.data[0]
                return {
                    "25%": round(float(data["p25"]), 4) if data["p25"] else None,
                    "50%": round(float(data["p50"]), 4) if data["p50"] else None,
                    "75%": round(float(data["p75"]), 4) if data["p75"] else None,
                    "90%": round(float(data["p90"]), 4) if data["p90"] else None,
                    "95%": round(float(data["p95"]), 4) if data["p95"] else None,
                    "99%": round(float(data["p99"]), 4) if data["p99"] else None
                }
        except Exception as e:
            logger.warning(f"Failed to calculate percentiles for {col_name}: {str(e)}")

        return {}

    async def _detect_numeric_outliers(
        self,
        connection: DorisConnection,
        table_name: str,
        col_name: str,
        percentiles: dict[str, float | None],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Detect outliers using IQR method"""
        try:
            q1_value = percentiles.get("25%")
            q3_value = percentiles.get("75%")
            if q1_value is None or q3_value is None:
                return {"outlier_count": 0, "outlier_rate": 0.0}

            q1 = float(q1_value)
            q3 = float(q3_value)
            iqr = q3 - q1

            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr

            safe_column = quote_identifier(col_name, "column name")
            table_expr = sampling_info.get("sample_table_expression", table_name)
            # SQL sink audit: metadata column -> quote_identifier; numeric
            # thresholds -> bound params; table_expr -> safe table/sampler.
            outlier_sql = f"""
            SELECT
                COUNT(*) as total_count,
                SUM(CASE WHEN {safe_column} < %s OR {safe_column} > %s
                    THEN 1 ELSE 0 END) as outlier_count
            FROM {table_expr}
            WHERE {safe_column} IS NOT NULL
            """  # nosec B608

            auth_context = get_auth_context()
            result = await connection.execute(
                outlier_sql,
                params=(lower_bound, upper_bound),
                auth_context=auth_context,
            )

            if result.data:
                data = result.data[0]
                total_count = data["total_count"]
                outlier_count = data["outlier_count"]
                outlier_rate = outlier_count / total_count if total_count > 0 else 0

                return {
                    "outlier_count": outlier_count,
                    "outlier_rate": round(outlier_rate, 4),
                    "outlier_threshold_lower": round(lower_bound, 4),
                    "outlier_threshold_upper": round(upper_bound, 4),
                    "iqr": round(iqr, 4)
                }

        except Exception as e:
            logger.warning(f"Failed to detect outliers for {col_name}: {str(e)}")

        return {"outlier_count": 0, "outlier_rate": 0.0}

    async def _analyze_distribution_shape(
        self,
        connection: DorisConnection,
        table_name: str,
        col_name: str,
        stats: dict[str, Any],
        percentiles: dict[str, float | None],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze the shape of data distribution"""
        try:
            mean = stats.get("mean_value", 0)
            median = percentiles.get("50%", 0)

            if mean is None or median is None:
                return {"distribution_type": "unknown"}

            # Calculate skewness indicator
            if abs(mean - median) < 0.01:
                skew_indicator = "symmetric"
            elif mean > median:
                skew_indicator = "right_skewed"
            else:
                skew_indicator = "left_skewed"

            # Estimate kurtosis based on percentile spread
            q25 = percentiles.get("25%")
            q75 = percentiles.get("75%")
            if q25 is not None and q75 is not None:
                iqr = q75 - q25
                q90 = percentiles.get("90%")
                q10 = percentiles.get("10%")
                range_90 = (
                    q90 if q90 is not None else q75
                ) - (
                    q10 if q10 is not None else q25
                )

                if iqr > 0:
                    kurtosis_indicator = "normal" if 2.5 <= range_90/iqr <= 3.5 else ("heavy_tailed" if range_90/iqr > 3.5 else "light_tailed")
                else:
                    kurtosis_indicator = "unknown"
            else:
                kurtosis_indicator = "unknown"

            return {
                "skewness_indicator": skew_indicator,
                "kurtosis_indicator": kurtosis_indicator,
                "distribution_type": self._classify_distribution_type(skew_indicator, kurtosis_indicator),
                "mean_median_ratio": round(mean / median, 4) if median != 0 else None
            }

        except Exception as e:
            logger.warning(f"Failed to analyze distribution shape for {col_name}: {str(e)}")
            return {"distribution_type": "unknown"}

    def _classify_distribution_type(self, skew: str, kurtosis: str) -> str:
        """Classify distribution type based on skewness and kurtosis"""
        if skew == "symmetric" and kurtosis == "normal":
            return "approximately_normal"
        elif skew == "right_skewed":
            return "right_skewed"
        elif skew == "left_skewed":
            return "left_skewed"
        elif kurtosis == "heavy_tailed":
            return "heavy_tailed"
        else:
            return "non_normal"

    async def _analyze_categorical_distributions(
        self,
        connection: DorisConnection,
        table_name: str,
        categorical_columns: list[dict[str, Any]],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze distribution patterns for categorical columns"""
        categorical_analysis = {}

        for column in categorical_columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # Basic cardinality and distribution
                # SQL sink audit: metadata column -> quote_identifier; table ->
                # build_table_reference -> DorisConnection.execute.
                cardinality_sql = f"""
                SELECT
                    COUNT(DISTINCT {safe_column}) as cardinality,
                    COUNT({safe_column}) as non_null_count
                FROM {table_name}
                WHERE {safe_column} IS NOT NULL
                """  # nosec B608

                auth_context = get_auth_context()
                cardinality_result = await connection.execute(cardinality_sql, auth_context=auth_context)

                if cardinality_result.data:
                    cardinality_data = cardinality_result.data[0]
                    cardinality = cardinality_data["cardinality"]
                    non_null_count = cardinality_data["non_null_count"]

                    # Value distribution (top values)
                    value_distribution = await self._get_categorical_value_distribution(
                        connection, table_name, col_name, sampling_info, non_null_count
                    )

                    # Calculate entropy and concentration
                    entropy = self._calculate_entropy(value_distribution)
                    concentration_ratio = value_distribution[0]["percentage"] if value_distribution else 0

                    categorical_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "cardinality": cardinality,
                        "non_null_count": non_null_count,
                        "value_distribution": value_distribution,
                        "entropy": round(entropy, 3),
                        "concentration_ratio": round(concentration_ratio, 4),
                        "diversity_score": round(cardinality / non_null_count, 4) if non_null_count > 0 else 0
                    }

            except Exception as e:
                logger.warning(f"Failed to analyze categorical column {col_name}: {str(e)}")
                categorical_analysis[col_name] = {"error": str(e)}

        return categorical_analysis

    async def _get_categorical_value_distribution(
        self,
        connection: DorisConnection,
        table_name: str,
        col_name: str,
        sampling_info: dict[str, Any],
        total_count: int,
    ) -> list[dict[str, Any]]:
        """Get value distribution for categorical column"""
        try:
            # Use sample table expression if sampling is enabled
            table_expr = sampling_info.get("sample_table_expression", table_name)
            safe_column = quote_identifier(col_name, "column name")

            # SQL sink audit: metadata column -> quote_identifier; table_expr
            # originates from a safe table/sampler before
            # DorisConnection.execute.
            distribution_sql = f"""
            SELECT
                {safe_column} as value,
                COUNT(*) as count
            FROM {table_expr}
            WHERE {safe_column} IS NOT NULL
            GROUP BY {safe_column}
            ORDER BY COUNT(*) DESC
            LIMIT 20
            """  # nosec B608

            auth_context = get_auth_context()
            result = await connection.execute(distribution_sql, auth_context=auth_context)

            if result.data:
                distribution = []
                for row in result.data:
                    count = row["count"]
                    percentage = count / total_count if total_count > 0 else 0
                    distribution.append({
                        "value": str(row["value"]),
                        "count": count,
                        "percentage": round(percentage, 4)
                    })
                return distribution

        except Exception as e:
            logger.warning(f"Failed to get value distribution for {col_name}: {str(e)}")

        return []

    def _calculate_entropy(self, value_distribution: list[dict]) -> float:
        """Calculate Shannon entropy for categorical distribution"""
        if not value_distribution:
            return 0.0

        entropy = 0.0
        for item in value_distribution:
            p = item["percentage"]
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    async def _analyze_temporal_distributions(
        self,
        connection: DorisConnection,
        table_name: str,
        temporal_columns: list[dict[str, Any]],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze distribution patterns for temporal columns"""
        temporal_analysis = {}

        for column in temporal_columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                # Date range analysis
                table_expr = sampling_info.get("sample_table_expression", table_name)
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                range_sql = f"""
                SELECT
                    MIN({safe_column}) as earliest,
                    MAX({safe_column}) as latest,
                    COUNT({safe_column}) as non_null_count
                FROM {table_expr}
                WHERE {safe_column} IS NOT NULL
                """  # nosec B608

                auth_context = get_auth_context()
                range_result = await connection.execute(range_sql, auth_context=auth_context)

                if range_result.data and range_result.data[0]["non_null_count"] > 0:
                    range_data = range_result.data[0]
                    earliest = range_data["earliest"]
                    latest = range_data["latest"]

                    # Calculate span
                    date_span_info = self._calculate_date_span(earliest, latest)

                    # Temporal patterns analysis
                    temporal_patterns = await self._analyze_temporal_patterns(
                        connection, table_name, col_name, sampling_info
                    )

                    temporal_analysis[col_name] = {
                        "data_type": column["data_type"],
                        "non_null_count": range_data["non_null_count"],
                        "date_range": {
                            "earliest": str(earliest),
                            "latest": str(latest),
                            **date_span_info
                        },
                        "temporal_patterns": temporal_patterns
                    }

            except Exception as e:
                logger.warning(f"Failed to analyze temporal column {col_name}: {str(e)}")
                temporal_analysis[col_name] = {"error": str(e)}

        return temporal_analysis

    def _calculate_date_span(
        self,
        earliest: datetime | str,
        latest: datetime | str,
    ) -> dict[str, Any]:
        """Calculate date span information"""
        try:
            if isinstance(earliest, str):
                earliest = datetime.fromisoformat(earliest.replace('Z', '+00:00'))
            if isinstance(latest, str):
                latest = datetime.fromisoformat(latest.replace('Z', '+00:00'))

            span = latest - earliest
            span_days = span.days

            return {
                "span_days": span_days,
                "span_years": round(span_days / 365.25, 2),
                "span_description": self._describe_time_span(span_days)
            }

        except Exception as e:
            logger.warning(f"Failed to calculate date span: {str(e)}")
            return {"span_days": 0}

    def _describe_time_span(self, days: int) -> str:
        """Describe time span in human readable format"""
        if days < 1:
            return "less_than_day"
        elif days < 7:
            return "days"
        elif days < 30:
            return "weeks"
        elif days < 365:
            return "months"
        else:
            return "years"

    async def _analyze_temporal_patterns(
        self,
        connection: DorisConnection,
        table_name: str,
        col_name: str,
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze temporal patterns like seasonality and trends"""
        try:
            table_expr = sampling_info.get("sample_table_expression", table_name)
            safe_column = quote_identifier(col_name, "column name")
            # Weekly pattern analysis
            # SQL sink audit: metadata column -> quote_identifier; table_expr
            # originates from a safe table/sampler before
            # DorisConnection.execute.
            weekly_pattern_sql = f"""
            SELECT
                DAYOFWEEK({safe_column}) as day_of_week,
                COUNT(*) as count
            FROM {table_expr}
            WHERE {safe_column} IS NOT NULL
            GROUP BY DAYOFWEEK({safe_column})
            ORDER BY day_of_week
            """  # nosec B608

            auth_context = get_auth_context()
            weekly_result = await connection.execute(weekly_pattern_sql, auth_context=auth_context)

            weekly_pattern = []
            if weekly_result.data:
                total_records = sum(row["count"] for row in weekly_result.data)
                for row in weekly_result.data:
                    percentage = row["count"] / total_records if total_records > 0 else 0
                    weekly_pattern.append(round(percentage, 3))

            # Monthly trend analysis (simplified)
            # SQL sink audit: same quote_identifier result and safe table_expr
            # flow into DorisConnection.execute.
            monthly_trend_sql = f"""
            SELECT
                YEAR({safe_column}) as year,
                MONTH({safe_column}) as month,
                COUNT(*) as count
            FROM {table_expr}
            WHERE {safe_column} IS NOT NULL
            GROUP BY YEAR({safe_column}), MONTH({safe_column})
            ORDER BY year, month
            LIMIT 12
            """  # nosec B608

            monthly_result = await connection.execute(monthly_trend_sql, auth_context=auth_context)
            monthly_trend = "stable"  # Simplified trend analysis

            if monthly_result.data and len(monthly_result.data) > 3:
                counts = [row["count"] for row in monthly_result.data]
                if len(counts) > 1:
                    trend_direction = "increasing" if counts[-1] > counts[0] else "decreasing"
                    monthly_trend = trend_direction

            return {
                "weekly_pattern": weekly_pattern,
                "monthly_trend": monthly_trend,
                "seasonal_component": self._estimate_seasonality(weekly_pattern)
            }

        except Exception as e:
            logger.warning(f"Failed to analyze temporal patterns for {col_name}: {str(e)}")
            return {"weekly_pattern": [], "monthly_trend": "unknown"}

    def _estimate_seasonality(self, weekly_pattern: list[float]) -> float:
        """Estimate seasonality strength based on weekly pattern variance"""
        if len(weekly_pattern) < 7:
            return 0.0

        mean_percentage = sum(weekly_pattern) / len(weekly_pattern)
        variance = sum((x - mean_percentage) ** 2 for x in weekly_pattern) / len(weekly_pattern)

        # Normalize variance to 0-1 scale as seasonality indicator
        seasonality = min(variance * 10, 1.0)  # Scaling factor
        return round(seasonality, 3)

    async def _generate_data_quality_insights(
        self,
        connection: DorisConnection,
        table_name: str,
        columns: list[dict[str, Any]],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Generate overall data quality insights"""
        try:
            total_columns = len(columns)

            # Calculate null rates across all columns
            null_analysis = await self._analyze_overall_null_rates(connection, table_name, columns, sampling_info)

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

            # Calculate overall data quality score
            avg_null_rate = sum(null_analysis["column_null_rates"].values()) / len(null_analysis["column_null_rates"]) if null_analysis["column_null_rates"] else 0
            data_quality_score = max(0, 1 - avg_null_rate)

            return {
                "total_columns_analyzed": total_columns,
                "null_analysis": null_analysis,
                "data_quality_score": round(data_quality_score, 3),
                "quality_issues": quality_issues,
                "recommendations": self._generate_quality_recommendations(quality_issues, null_analysis)
            }

        except Exception as e:
            logger.warning(f"Failed to generate data quality insights: {str(e)}")
            return {"data_quality_score": 0.0, "error": str(e)}

    async def _analyze_overall_null_rates(
        self,
        connection: DorisConnection,
        table_name: str,
        columns: list[dict[str, Any]],
        sampling_info: dict[str, Any],
    ) -> dict[str, Any]:
        """Analyze null rates across all columns"""
        column_null_rates = {}
        total_null_count = 0
        total_cell_count = 0

        for column in columns:
            col_name = column["column_name"]
            try:
                safe_column = quote_identifier(col_name, "column name")
                table_expr = sampling_info.get("sample_table_expression", table_name)
                # SQL sink audit: metadata column -> quote_identifier;
                # table_expr originates from a safe table/sampler before
                # DorisConnection.execute.
                null_sql = f"""
                SELECT
                    COUNT(*) as total_count,
                    COUNT({safe_column}) as non_null_count
                FROM {table_expr}
                """  # nosec B608

                auth_context = get_auth_context()
                result = await connection.execute(null_sql, auth_context=auth_context)
                if result.data:
                    data = result.data[0]
                    total_count = data["total_count"]
                    non_null_count = data["non_null_count"]
                    null_count = total_count - non_null_count
                    null_rate = null_count / total_count if total_count > 0 else 0

                    column_null_rates[col_name] = round(null_rate, 4)
                    total_null_count += null_count
                    total_cell_count += total_count

            except Exception as e:
                logger.warning(f"Failed to analyze null rate for column {col_name}: {str(e)}")
                column_null_rates[col_name] = 0.0

        overall_null_rate = total_null_count / total_cell_count if total_cell_count > 0 else 0

        return {
            "column_null_rates": column_null_rates,
            "overall_null_rate": round(overall_null_rate, 4),
            "columns_with_nulls": len([rate for rate in column_null_rates.values() if rate > 0])
        }

    def _generate_quality_recommendations(self, quality_issues: list[dict], null_analysis: dict) -> list[dict]:
        """Generate data quality improvement recommendations"""
        recommendations = []

        # Recommendations based on null analysis
        overall_null_rate = null_analysis.get("overall_null_rate", 0)
        if overall_null_rate > 0.1:
            recommendations.append({
                "type": "data_completeness",
                "priority": "high" if overall_null_rate > 0.3 else "medium",
                "description": f"Overall null rate is {overall_null_rate:.1%}",
                "action": "Review data collection and validation processes"
            })

        # Recommendations based on quality issues
        for issue in quality_issues:
            if issue["issue_type"] == "high_null_rates":
                recommendations.append({
                    "type": "column_completeness",
                    "priority": issue["severity"],
                    "description": issue["description"],
                    "action": f"Focus on improving data completeness for: {', '.join(issue['affected_columns'][:3])}"
                })

        return recommendations

    def _generate_analysis_summary(self, distribution_analysis: dict[str, Any]) -> dict[str, Any]:
        """Generate high-level summary of distribution analysis"""
        summary: dict[str, Any] = {
            "numeric_columns_count": len(distribution_analysis.get("numeric_columns", {})),
            "categorical_columns_count": len(distribution_analysis.get("categorical_columns", {})),
            "temporal_columns_count": len(distribution_analysis.get("temporal_columns", {}))
        }

        # Identify interesting patterns
        patterns = []

        # Check for highly skewed numeric columns
        numeric_cols = distribution_analysis.get("numeric_columns", {})
        skewed_cols = [
            col for col, info in numeric_cols.items()
            if isinstance(info, dict) and
            info.get("distribution_shape", {}).get("skewness_indicator") in ["right_skewed", "left_skewed"]
        ]

        if skewed_cols:
            patterns.append(f"Found {len(skewed_cols)} skewed numeric columns")

        # Check for high cardinality categorical columns
        categorical_cols = distribution_analysis.get("categorical_columns", {})
        high_cardinality_cols = [
            col for col, info in categorical_cols.items()
            if isinstance(info, dict) and info.get("cardinality", 0) > 1000
        ]

        if high_cardinality_cols:
            patterns.append(f"Found {len(high_cardinality_cols)} high cardinality categorical columns")

        summary["notable_patterns"] = patterns

        return summary

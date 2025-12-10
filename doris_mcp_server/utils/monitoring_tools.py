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
Doris Monitoring Tools Module
Provides monitoring and metrics collection functions for FE and BE nodes
"""

import re
import aiohttp
import asyncio
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from .db import DorisConnectionManager
from .logger import get_logger
from .sql_security_utils import get_auth_context

logger = get_logger(__name__)


class P0MetricInfo:
    """P0级监控项信息类"""
    
    def __init__(self, name: str, meaning: str, description: str, unit: str = ""):
        self.name = name
        self.meaning = meaning
        self.description = description
        self.unit = unit
    
    def to_dict(self) -> Dict[str, str]:
        return {
            "name": self.name,
            "meaning": self.meaning,
            "description": self.description,
            "unit": self.unit
        }


class P0Metrics:
    """P0 level monitoring metrics enumeration mapping class"""
    
    # Core Essential Metrics (10-12 items) - Default output for production environments
    # These metrics cover the most critical aspects: CPU, Memory, IO, Network, Connections, Compaction
    CORE_METRICS = {
        # FE Core Metrics (4 items)
        "doris_fe_connection_total": P0MetricInfo(
            "doris_fe_connection_total",
            "Current FE MySQL port connection count",
            "Used to monitor query connection count. If connection count exceeds limit, new connections cannot be accepted",
            "Num"
        ),
        "doris_fe_query_total": P0MetricInfo(
            "doris_fe_query_total",
            "Cumulative count of total query requests",
            "QPS can be obtained by calculating slope",
            "Num"
        ),
        "doris_fe_cpu": P0MetricInfo(
            "doris_fe_cpu",
            "CPU usage metrics",
            "Monitor CPU utilization of FE node",
            "Percentage"
        ),
        "jvm_heap_size_bytes": P0MetricInfo(
            "jvm_heap_size_bytes",
            "JVM heap memory size",
            "Monitor JVM heap memory usage to prevent OOM",
            "Bytes"
        ),
        
        # BE Core Metrics (8 items)
        "doris_be_tablet_base_max_compaction_score": P0MetricInfo(
            "doris_be_tablet_base_max_compaction_score",
            "Maximum base compaction score among tablets",
            "Monitor base compaction status",
            "Num"
        ),
        "doris_be_tablet_cumulative_max_compaction_score": P0MetricInfo(
            "doris_be_tablet_cumulative_max_compaction_score", 
            "Maximum cumulative compaction score among tablets",
            "Monitor cumulative compaction status",
            "Num"
        ),
        "doris_be_cpu": P0MetricInfo(
            "doris_be_cpu",
            "CPU usage metrics",
            "Monitor CPU utilization of BE node",
            "Percentage"
        ),
        "doris_be_memory_allocated_bytes": P0MetricInfo(
            "doris_be_memory_allocated_bytes",
            "Memory allocated by BE process",
            "Used to monitor BE process memory usage",
            "Bytes"
        ),
        "doris_be_disk_io_util": P0MetricInfo(
            "doris_be_disk_io_util",
            "Disk IO utilization percentage",
            "Monitor disk IO utilization from /proc/diskstats",
            "Percentage"
        ),
        "doris_be_network_receive_bytes": P0MetricInfo(
            "doris_be_network_receive_bytes",
            "Network receive bytes cumulative value",
            "Monitor network receive volume from /proc/net/dev",
            "Bytes"
        ),
        "doris_be_network_send_bytes": P0MetricInfo(
            "doris_be_network_send_bytes",
            "Network send bytes cumulative value",
            "Monitor network send volume from /proc/net/dev",
            "Bytes"
        ),
        "doris_be_query_scan_bytes": P0MetricInfo(
            "doris_be_query_scan_bytes",
            "Bytes scanned by queries",
            "Monitor query data scanning volume",
            "Bytes"
        ),
    }
    
    # FE Process Monitoring P0 Metrics
    FE_PROCESS_METRICS = {
        "doris_fe_connection_total": P0MetricInfo(
            "doris_fe_connection_total",
            "Current FE MySQL port connection count",
            "Used to monitor query connection count. If connection count exceeds limit, new connections cannot be accepted",
            "Num"
        ),
        "doris_fe_edit_log_clean": P0MetricInfo(
            "doris_fe_edit_log_clean",
            "Number of failures to clean historical metadata logs",
            "Should not fail, if failed, manual intervention is required",
            "Num"
        ),
        "doris_fe_edit_log": P0MetricInfo(
            "doris_fe_edit_log",
            "Metadata log related metrics",
            "Write rate can be obtained by calculating slope to observe whether metadata writing has delay",
            "Bytes/Num"
        ),
        "doris_fe_image_clean": P0MetricInfo(
            "doris_fe_image_clean",
            "Number of failures to clean historical metadata image files",
            "Should not fail, if failed, manual intervention is required",
            "Num"
        ),
        "doris_fe_image_write": P0MetricInfo(
            "doris_fe_image_write",
            "Number of failures to generate metadata image files",
            "Should not fail, if failed, manual intervention is required",
            "Num"
        ),
        "doris_fe_max_journal_id": P0MetricInfo(
            "doris_fe_max_journal_id",
            "Current maximum metadata log id",
            "Used to monitor whether metadata logs are progressing normally",
            "Num"
        ),
        "doris_fe_max_tablet_compaction_score": P0MetricInfo(
            "doris_fe_max_tablet_compaction_score",
            "Maximum compaction score among all BE nodes",
            "If score is too high, it indicates compaction has delay",
            "Num"
        ),
        "doris_fe_query_err": P0MetricInfo(
            "doris_fe_query_err",
            "Cumulative count of query errors",
            "Query error rate can be obtained by calculating slope",
            "Num"
        ),
        "doris_fe_query_total": P0MetricInfo(
            "doris_fe_query_total",
            "Cumulative count of total query requests",
            "QPS can be obtained by calculating slope",
            "Num"
        ),
        "doris_fe_report_queue_size": P0MetricInfo(
            "doris_fe_report_queue_size",
            "Queue length of BE report tasks",
            "If queue length is consistently large, it indicates FE has delay in processing report tasks",
            "Num"
        ),
        "doris_fe_scheduled_tablet_num": P0MetricInfo(
            "doris_fe_scheduled_tablet_num",
            "Number of tablets waiting to be scheduled",
            "If number is consistently large, it indicates many tablets are waiting to be scheduled",
            "Num"
        ),
        "doris_fe_txn_status": P0MetricInfo(
            "doris_fe_txn_status",
            "Number of transactions in various states",
            "Monitor transaction status distribution",
            "Num"
        ),
        # Additional P0 metrics from official documentation
        "doris_fe_meta_log_count": P0MetricInfo(
            "doris_fe_meta_log_count",
            "Current number of metadata logs",
            "Used to monitor editlog count. If count exceeds limit, manual intervention is required",
            "Num"
        ),
        "doris_fe_checkpoint_push_per_second": P0MetricInfo(
            "doris_fe_checkpoint_push_per_second",
            "Checkpoint push rate per second",
            "Monitor checkpoint push frequency to other FE nodes",
            "Num/Second"
        ),
        "doris_fe_routine_load_error_rows": P0MetricInfo(
            "doris_fe_routine_load_error_rows",
            "Number of error rows in routine load",
            "Monitor routine load data quality",
            "Num"
        ),
        "doris_fe_routine_load_receive_bytes": P0MetricInfo(
            "doris_fe_routine_load_receive_bytes",
            "Bytes received by routine load",
            "Monitor routine load data volume",
            "Bytes"
        ),
        "doris_fe_routine_load_rows": P0MetricInfo(
            "doris_fe_routine_load_rows",
            "Number of rows processed by routine load",
            "Monitor routine load processing volume",
            "Num"
        ),
        "doris_fe_stream_load": P0MetricInfo(
            "doris_fe_stream_load",
            "Stream load related metrics",
            "Monitor stream load operations",
            "Num"
        ),
        "doris_fe_stream_load_pipe": P0MetricInfo(
            "doris_fe_stream_load_pipe",
            "Stream load pipe metrics",
            "Monitor stream load pipe operations",
            "Num"
        ),
        "doris_fe_tablet_num": P0MetricInfo(
            "doris_fe_tablet_num",
            "Total number of tablets",
            "Monitor tablet count in the cluster",
            "Num"
        ),
        "doris_fe_tablet_max_compaction_score": P0MetricInfo(
            "doris_fe_tablet_max_compaction_score",
            "Maximum tablet compaction score",
            "Monitor tablet compaction status",
            "Num"
        )
    }
    
    # FE JVM Monitoring P0 Metrics
    FE_JVM_METRICS = {
        "jvm_heap_size_bytes": P0MetricInfo(
            "jvm_heap_size_bytes",
            "JVM heap memory size",
            "Monitor JVM heap memory usage to prevent OOM",
            "Bytes"
        ),
        "jvm_non_heap_size_bytes": P0MetricInfo(
            "jvm_non_heap_size_bytes", 
            "JVM non-heap memory size",
            "Monitor JVM non-heap memory usage",
            "Bytes"
        ),
        "jvm_old_size_bytes": P0MetricInfo(
            "jvm_old_size_bytes",
            "JVM old generation memory size", 
            "Monitor old generation memory usage",
            "Bytes"
        ),
        "jvm_young_size_bytes": P0MetricInfo(
            "jvm_young_size_bytes",
            "JVM young generation memory size",
            "Monitor young generation memory usage", 
            "Bytes"
        ),
        "jvm_gc_g1_old_generation": P0MetricInfo(
            "jvm_gc_g1_old_generation",
            "G1 old generation GC metrics",
            "Monitor G1 old generation garbage collection",
            "Num"
        ),
        "jvm_gc_g1_young_generation": P0MetricInfo(
            "jvm_gc_g1_young_generation",
            "G1 young generation GC metrics", 
            "Monitor G1 young generation garbage collection",
            "Num"
        )
    }
    
    # FE Machine Monitoring P0 Metrics  
    FE_MACHINE_METRICS = {
        "doris_fe_cpu": P0MetricInfo(
            "doris_fe_cpu",
            "CPU usage metrics",
            "Monitor CPU utilization of FE node",
            "Percentage"
        ),
        "doris_fe_memory": P0MetricInfo(
            "doris_fe_memory",
            "Memory usage metrics",
            "Monitor memory utilization of FE node", 
            "Bytes"
        ),
        "doris_fe_fd_num_limit": P0MetricInfo(
            "doris_fe_fd_num_limit",
            "File descriptor limit",
            "Monitor system file descriptor limit",
            "Num"
        ),
        "doris_fe_fd_num_used": P0MetricInfo(
            "doris_fe_fd_num_used",
            "File descriptors used",
            "Monitor system file descriptor usage",
            "Num"
        )
    }
    
    # BE Process Monitoring P0 Metrics
    BE_PROCESS_METRICS = {
        "doris_be_base_compaction_deltas": P0MetricInfo(
            "doris_be_base_compaction_deltas",
            "Number of deltas in base compaction",
            "If number is consistently large, it indicates base compaction has delay",
            "Num"
        ),
        "doris_be_compaction_used_permits": P0MetricInfo(
            "doris_be_compaction_used_permits",
            "Number of permits used by compaction",
            "Used to monitor compaction concurrency",
            "Num"
        ),
        "doris_be_cumulative_compaction_deltas": P0MetricInfo(
            "doris_be_cumulative_compaction_deltas",
            "Number of deltas in cumulative compaction",
            "If number is consistently large, it indicates cumulative compaction has delay",
            "Num"
        ),

        # Additional P0 metrics from official documentation
        "doris_be_fragment_thread_pool": P0MetricInfo(
            "doris_be_fragment_thread_pool",
            "Fragment execution thread pool metrics",
            "Monitor query fragment execution thread pool status",
            "Num"
        ),
        "doris_be_scanner_thread_pool": P0MetricInfo(
            "doris_be_scanner_thread_pool", 
            "Scanner thread pool metrics",
            "Monitor data scanning thread pool status",
            "Num"
        ),
        "doris_be_etl_thread_pool": P0MetricInfo(
            "doris_be_etl_thread_pool",
            "ETL thread pool metrics", 
            "Monitor ETL processing thread pool status",
            "Num"
        ),
        "doris_be_load_channel_count": P0MetricInfo(
            "doris_be_load_channel_count",
            "Number of active load channels",
            "Monitor data loading channel count",
            "Num"
        ),
        "doris_be_load_rpc_thread_pool": P0MetricInfo(
            "doris_be_load_rpc_thread_pool",
            "Load RPC thread pool metrics",
            "Monitor load RPC thread pool status", 
            "Num"
        ),
        "doris_be_heavy_work_thread_pool": P0MetricInfo(
            "doris_be_heavy_work_thread_pool",
            "Heavy work thread pool metrics",
            "Monitor heavy work thread pool status",
            "Num"
        ),
        "doris_be_light_work_thread_pool": P0MetricInfo(
            "doris_be_light_work_thread_pool", 
            "Light work thread pool metrics",
            "Monitor light work thread pool status",
            "Num"
        ),
        "doris_be_flush_thread_pool": P0MetricInfo(
            "doris_be_flush_thread_pool",
            "Flush thread pool metrics",
            "Monitor data flush thread pool status",
            "Num"
        ),
        "doris_be_memtable_flush_total": P0MetricInfo(
            "doris_be_memtable_flush_total",
            "Total number of memtable flushes",
            "Monitor memtable flush frequency",
            "Num"
        ),
        "doris_be_memtable_flush_duration_us": P0MetricInfo(
            "doris_be_memtable_flush_duration_us",
            "Memtable flush duration in microseconds",
            "Monitor memtable flush performance",
            "Microseconds"
        ),
        "doris_be_query_scan_bytes": P0MetricInfo(
            "doris_be_query_scan_bytes",
            "Bytes scanned by queries",
            "Monitor query data scanning volume",
            "Bytes"
        ),
        "doris_be_query_scan_rows": P0MetricInfo(
            "doris_be_query_scan_rows", 
            "Rows scanned by queries",
            "Monitor query data scanning row count",
            "Num"
        ),
        "doris_be_max_tablet_rowset_num": P0MetricInfo(
            "doris_be_max_tablet_rowset_num",
            "Maximum number of rowsets in tablets",
            "Monitor tablet rowset count, high values may indicate compaction issues",
            "Num"
        ),
        # Additional BE process P0 metrics
        "doris_be_engine_requests_total": P0MetricInfo(
            "doris_be_engine_requests_total",
            "Total number of engine requests",
            "Monitor storage engine request count",
            "Num"
        ),
        "doris_be_process_fd_num_limit": P0MetricInfo(
            "doris_be_process_fd_num_limit",
            "Process file descriptor limit",
            "Monitor process file descriptor limit",
            "Num"
        ),
        "doris_be_process_fd_num_used": P0MetricInfo(
            "doris_be_process_fd_num_used",
            "Process file descriptors used",
            "Monitor process file descriptor usage",
            "Num"
        ),
        "doris_be_process_thread_num": P0MetricInfo(
            "doris_be_process_thread_num",
            "Number of process threads",
            "Monitor process thread count",
            "Num"
        ),
        "doris_be_tablet_base_max_compaction_score": P0MetricInfo(
            "doris_be_tablet_base_max_compaction_score",
            "Maximum base compaction score among tablets",
            "Monitor base compaction status",
            "Num"
        ),
        "doris_be_tablet_cumulative_max_compaction_score": P0MetricInfo(
            "doris_be_tablet_cumulative_max_compaction_score", 
            "Maximum cumulative compaction score among tablets",
            "Monitor cumulative compaction status",
            "Num"
        ),
        "doris_be_tablet_version_num": P0MetricInfo(
            "doris_be_tablet_version_num",
            "Number of tablet versions",
            "Monitor tablet version count",
            "Num"
        ),
        "doris_be_thrift_used_clients": P0MetricInfo(
            "doris_be_thrift_used_clients",
            "Number of used Thrift clients",
            "Monitor Thrift client pool usage",
            "Num"
        ),
        "doris_be_unused_rowsets_count": P0MetricInfo(
            "doris_be_unused_rowsets_count",
            "Number of unused rowsets",
            "Monitor unused rowset count for cleanup",
            "Num"
        ),
        # Memory related P0 metrics
        "doris_be_memory_pool": P0MetricInfo(
            "doris_be_memory_pool",
            "Memory pool usage metrics",
            "Monitor memory pool allocation and usage",
            "Bytes"
        ),
        "doris_be_memory_jemalloc": P0MetricInfo(
            "doris_be_memory_jemalloc",
            "Jemalloc memory metrics",
            "Monitor jemalloc memory allocation",
            "Bytes"
        ),
        # Storage related P0 metrics  
        "doris_be_storage_migrate_v2": P0MetricInfo(
            "doris_be_storage_migrate_v2",
            "Storage migration v2 metrics",
            "Monitor storage migration operations",
            "Num"
        ),
        "doris_be_all_rowsets_num": P0MetricInfo(
            "doris_be_all_rowsets_num",
            "Total number of rowsets",
            "Monitor total rowset count in storage",
            "Num"
        ),
        "doris_be_all_segments_num": P0MetricInfo(
            "doris_be_all_segments_num",
            "Total number of segments", 
            "Monitor total segment count in storage",
            "Num"
        )
    }
    
    # BE Machine Monitoring P0 Metrics
    BE_MACHINE_METRICS = {
        "doris_be_cpu": P0MetricInfo(
            "doris_be_cpu",
            "CPU usage metrics",
            "Monitor CPU utilization of BE node",
            "Percentage"
        ),
        "doris_be_memory": P0MetricInfo(
            "doris_be_memory",
            "Memory usage metrics", 
            "Monitor memory utilization of BE node",
            "Bytes"
        ),
        "doris_be_disk_io_time_ms": P0MetricInfo(
            "doris_be_disk_io_time_ms",
            "Disk IO time",
            "Can be used to calculate IO Util",
            "Milliseconds"
        ),
        "doris_be_load_average": P0MetricInfo(
            "doris_be_load_average",
            "Machine Load Average metric monitoring",
            "Observe overall machine load",
            "Num"
        ),
        "doris_be_max_disk_io_util_percent": P0MetricInfo(
            "doris_be_max_disk_io_util_percent",
            "Maximum IO UTIL among all disks",
            "Monitor disk IO utilization",
            "Percentage"
        ),
        "doris_be_max_network_receive_bytes_rate": P0MetricInfo(
            "doris_be_max_network_receive_bytes_rate",
            "Maximum receive rate among all network interfaces",
            "Monitor network receive rate",
            "Bytes/Second"
        ),
        "doris_be_max_network_send_bytes_rate": P0MetricInfo(
            "doris_be_max_network_send_bytes_rate",
            "Maximum send rate among all network interfaces",
            "Monitor network send rate",
            "Bytes/Second"
        ),
        "doris_be_memory_allocated_bytes": P0MetricInfo(
            "doris_be_memory_allocated_bytes",
            "Memory allocated by BE process",
            "Used to monitor BE process memory usage",
            "Bytes"
        ),
        "doris_be_proc": P0MetricInfo(
            "doris_be_proc",
            "Cumulative count of CPU context switches",
            "Observe whether there are abnormal context switches",
            "Num"
        ),
        "doris_be_snmp_tcp_in_errs": P0MetricInfo(
            "doris_be_snmp_tcp_in_errs",
            "Number of TCP packet receive errors",
            "Can observe network errors such as retransmission, packet loss, etc.",
            "Num"
        ),
        "doris_be_fd_num_limit": P0MetricInfo(
            "doris_be_fd_num_limit",
            "System file descriptor limit",
            "Monitor system file descriptor limit",
            "Num"
        ),
        "doris_be_fd_num_used": P0MetricInfo(
            "doris_be_fd_num_used",
            "System file descriptors used",
            "Monitor system file descriptor usage",
            "Num"
        ),
        "doris_be_disk_bytes_read": P0MetricInfo(
            "doris_be_disk_bytes_read",
            "Disk bytes read cumulative value",
            "Monitor disk read volume from /proc/diskstats",
            "Bytes"
        ),
        "doris_be_disk_bytes_written": P0MetricInfo(
            "doris_be_disk_bytes_written",
            "Disk bytes written cumulative value",
            "Monitor disk write volume from /proc/diskstats",
            "Bytes"
        ),
        "doris_be_network_receive_bytes": P0MetricInfo(
            "doris_be_network_receive_bytes",
            "Network receive bytes cumulative value",
            "Monitor network receive volume from /proc/net/dev",
            "Bytes"
        ),
        "doris_be_network_send_bytes": P0MetricInfo(
            "doris_be_network_send_bytes",
            "Network send bytes cumulative value",
            "Monitor network send volume from /proc/net/dev",
            "Bytes"
        )
    }
    
    @classmethod
    def get_all_p0_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get all P0 level monitoring metrics"""
        all_metrics = {}
        all_metrics.update(cls.FE_PROCESS_METRICS)
        all_metrics.update(cls.FE_JVM_METRICS)
        all_metrics.update(cls.FE_MACHINE_METRICS)
        all_metrics.update(cls.BE_PROCESS_METRICS)
        all_metrics.update(cls.BE_MACHINE_METRICS)
        return all_metrics
    
    @classmethod
    def get_fe_p0_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get FE P0 level monitoring metrics"""
        fe_metrics = {}
        fe_metrics.update(cls.FE_PROCESS_METRICS)
        fe_metrics.update(cls.FE_JVM_METRICS)
        fe_metrics.update(cls.FE_MACHINE_METRICS)
        return fe_metrics
    
    @classmethod
    def get_be_p0_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get BE P0 level monitoring metrics"""
        be_metrics = {}
        be_metrics.update(cls.BE_PROCESS_METRICS)
        be_metrics.update(cls.BE_MACHINE_METRICS)
        return be_metrics
    
    @classmethod
    def get_fe_process_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get FE process monitoring metrics"""
        return cls.FE_PROCESS_METRICS.copy()
    
    @classmethod
    def get_fe_jvm_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get FE JVM monitoring metrics"""
        return cls.FE_JVM_METRICS.copy()
    
    @classmethod
    def get_fe_machine_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get FE machine monitoring metrics"""
        return cls.FE_MACHINE_METRICS.copy()
    
    @classmethod
    def get_be_process_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get BE process monitoring metrics"""
        return cls.BE_PROCESS_METRICS.copy()
    
    @classmethod
    def get_be_machine_metrics(cls) -> Dict[str, P0MetricInfo]:
        """Get BE machine monitoring metrics"""
        return cls.BE_MACHINE_METRICS.copy()


class DorisMonitoringTools:
    """Doris monitoring tools class"""
    
    def __init__(self, connection_manager: DorisConnectionManager):
        self.connection_manager = connection_manager
    
    async def get_be_nodes(self) -> List[Dict[str, Any]]:
        """Get BE node information, prioritize configured be_hosts, fallback to SHOW BACKENDS"""
        try:
            # Get database configuration
            db_config = self.connection_manager.config.database
            
            # Check if BE hosts are configured
            if db_config.be_hosts:
                logger.info(f"Using configured BE hosts: {db_config.be_hosts}")
                be_nodes = []
                for i, host in enumerate(db_config.be_hosts):
                    be_info = {
                        "backend_id": f"configured_{i}",
                        "host": host,
                        "heartbeat_port": None,
                        "be_port": None,
                        "http_port": db_config.be_webserver_port,  # Use configured webserver port
                        "brpc_port": None,
                        "alive": "true",  # Assume configured hosts are alive
                        "system_decommissioned": "false",
                        "cluster_id": None,
                        "version": None,
                        "source": "configured"
                    }
                    be_nodes.append(be_info)
                
                logger.info(f"Found {len(be_nodes)} configured BE nodes")
                return be_nodes
            
            # Fallback to SHOW BACKENDS if no BE hosts configured
            logger.info("No BE hosts configured, using SHOW BACKENDS to discover BE nodes")
            connection = await self.connection_manager.get_connection("query")
            auth_context = get_auth_context()
            result = await connection.execute("SHOW BACKENDS", auth_context=auth_context)
            
            be_nodes = []
            for row in result.data:
                # SHOW BACKENDS returns columns including: BackendId, Host, HeartbeatPort, BePort, HttpPort, BrpcPort, etc.
                be_info = {
                    "backend_id": row.get("BackendId"),
                    "host": row.get("Host"),
                    "heartbeat_port": row.get("HeartbeatPort"),
                    "be_port": row.get("BePort"),
                    "http_port": row.get("HttpPort"),  # This is webserver_port
                    "brpc_port": row.get("BrpcPort"),
                    "alive": row.get("Alive"),
                    "system_decommissioned": row.get("SystemDecommissioned"),
                    "cluster_id": row.get("ClusterId"),
                    "version": row.get("Version"),
                    "source": "show_backends"
                }
                be_nodes.append(be_info)
            
            logger.info(f"Found {len(be_nodes)} BE nodes from SHOW BACKENDS")
            return be_nodes
            
        except Exception as e:
            logger.error(f"Failed to get BE nodes: {str(e)}")
            return []
    
    async def fetch_metrics_from_url(self, url: str, node_type: str, node_info: Dict[str, Any]) -> Dict[str, Any]:
        """Fetch monitoring metrics from specified URL"""
        try:
            # Get database configuration for authentication
            db_config = self.connection_manager.config.database
            auth = aiohttp.BasicAuth(db_config.user, db_config.password)
            
            logger.info(f"Fetching metrics from {node_type} node: {url}")
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, auth=auth, timeout=30) as response:
                    if response.status == 200:
                        # Parse Prometheus format
                        metrics_text = await response.text()
                        metrics_data = self._parse_prometheus_metrics(metrics_text)
                        
                        return {
                            "success": True,
                            "node_type": node_type,
                            "node_info": node_info,
                            "metrics": metrics_data,
                            "url": url,
                            "timestamp": datetime.now().isoformat()
                        }
                    else:
                        logger.error(f"HTTP request failed with status {response.status} for {url}")
                        return {
                            "success": False,
                            "error": f"HTTP {response.status}",
                            "node_type": node_type,
                            "node_info": node_info,
                            "url": url
                        }
                        
        except Exception as e:
            logger.error(f"Failed to fetch metrics from {url}: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "node_type": node_type,
                "node_info": node_info,
                "url": url
            }
    
    def _parse_prometheus_metrics(self, metrics_text: str) -> Dict[str, Any]:
        """Parse Prometheus format monitoring metrics"""
        metrics = {}
        
        for line in metrics_text.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Parse format: metric_name{labels} value
            try:
                if '{' in line:
                    # Metrics with labels
                    metric_part, value_part = line.rsplit(' ', 1)
                    metric_name = metric_part.split('{')[0]
                    labels_part = metric_part[metric_part.find('{'):metric_part.rfind('}')+1]
                    
                    # Parse labels
                    labels = {}
                    labels_content = labels_part[1:-1]  # Remove {}
                    if labels_content:
                        for label_pair in labels_content.split(','):
                            if '=' in label_pair:
                                key, value = label_pair.split('=', 1)
                                labels[key.strip()] = value.strip().strip('"')
                    
                    # Store metrics
                    if metric_name not in metrics:
                        metrics[metric_name] = []
                    elif not isinstance(metrics[metric_name], list):
                        # Convert existing single value to list format
                        old_value = metrics[metric_name]
                        metrics[metric_name] = [{"labels": {}, "value": old_value}]
                    
                    metrics[metric_name].append({
                        "labels": labels,
                        "value": float(value_part) if '.' in value_part else int(value_part)
                    })
                else:
                    # Metrics without labels
                    metric_name, value_part = line.rsplit(' ', 1)
                    value = float(value_part) if '.' in value_part else int(value_part)
                    
                    # Check if this metric already exists as a list (with labels)
                    if metric_name in metrics and isinstance(metrics[metric_name], list):
                        # Add as an entry with empty labels
                        metrics[metric_name].append({"labels": {}, "value": value})
                    else:
                        # Store as simple value
                        metrics[metric_name] = value
                    
            except Exception as e:
                logger.warning(f"Failed to parse metric line: {line}, error: {e}")
                continue
        
        return metrics
    
    async def get_monitoring_metrics(
        self,
        role: str = "all",  # "fe", "be", "all"
        monitor_type: str = "all",  # "process", "jvm", "machine", "all"
        priority: str = "p0",  # "p0", "all"
        info_only: bool = False,  # 只返回监控项信息，不返回实际值
        include_raw_metrics: bool = False,  # 是否包含原始详细指标数据
        format_type: str = "prometheus"  # "prometheus"
    ) -> Dict[str, Any]:
        """
        Get monitoring metrics from Doris FE and BE nodes
        
        Args:
            role: Role selection ("fe", "be", "all")
            monitor_type: Monitor type selection ("process", "jvm", "machine", "all")
            priority: Priority selection ("p0", "all")
            info_only: Whether to return only monitoring metric information
            include_raw_metrics: Whether to include raw detailed metrics data
            format_type: Return format ("prometheus")
            
        Returns:
            Dict containing monitoring metrics data with summary aggregations
        """
        try:
            result = {
                "success": True,
                "role": role,
                "monitor_type": monitor_type,
                "priority": priority,
                "info_only": info_only,
                "include_raw_metrics": include_raw_metrics,
                "format_type": format_type,
                "timestamp": datetime.now().isoformat(),
                "data": {}
            }
            
            # If only return monitoring metric information
            if info_only:
                if priority == "p0":
                    if role in ["fe", "all"]:
                        fe_metrics = self._get_metrics_by_type("fe", monitor_type)
                        if fe_metrics:
                            if monitor_type == "process":
                                result["data"]["fe_process_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in fe_metrics.items()
                                }
                            elif monitor_type == "jvm":
                                result["data"]["fe_jvm_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in fe_metrics.items()
                                }
                            elif monitor_type == "machine":
                                result["data"]["fe_machine_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in fe_metrics.items()
                                }
                            else:  # "all"
                                result["data"]["fe_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in fe_metrics.items()
                                }
                    
                    if role in ["be", "all"]:
                        be_metrics = self._get_metrics_by_type("be", monitor_type)
                        if be_metrics:
                            if monitor_type == "process":
                                result["data"]["be_process_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in be_metrics.items()
                                }
                            elif monitor_type == "jvm":
                                result["data"]["be_jvm_info"] = "BE nodes do not have JVM metrics"
                            elif monitor_type == "machine":
                                result["data"]["be_machine_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in be_metrics.items()
                                }
                            else:  # "all"
                                result["data"]["be_p0_metrics"] = {
                                    name: metric.to_dict() for name, metric in be_metrics.items()
                                }
                        elif monitor_type == "jvm":
                            result["data"]["be_jvm_info"] = "BE nodes do not have JVM metrics"
                else:  # priority == "all"
                    # Return all metrics info (P0 and non-P0)
                    all_metrics = P0Metrics.get_all_p0_metrics()
                    result["data"]["all_metrics"] = {
                        name: metric.to_dict() for name, metric in all_metrics.items()
                    }
                
                return result
            
            # Get actual monitoring data
            if role in ["fe", "all"]:
                fe_data = await self._get_fe_metrics(monitor_type, priority, format_type, include_raw_metrics)
                if fe_data:
                    result["data"]["fe"] = fe_data
            
            if role in ["be", "all"]:
                be_data = await self._get_be_metrics(monitor_type, priority, format_type, include_raw_metrics)
                if be_data:
                    result["data"]["be"] = be_data
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to get monitoring metrics: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    async def _get_fe_metrics(self, monitor_type: str, priority: str, format_type: str, include_raw_metrics: bool) -> Dict[str, Any]:
        """Get FE monitoring metrics"""
        try:
            db_config = self.connection_manager.config.database
            fe_url = f"http://{db_config.host}:{db_config.fe_http_port}/metrics"
            
            fe_result = await self.fetch_metrics_from_url(
                fe_url, 
                "fe", 
                {"host": db_config.host, "port": db_config.fe_http_port}
            )
            
            if fe_result.get("success") and priority == "p0":
                fe_p0_metrics = self._get_metrics_by_type("fe", monitor_type)
                fe_result["metrics"] = self._filter_p0_metrics(
                    fe_result["metrics"], 
                    fe_p0_metrics
                )
                fe_result["p0_metrics_info"] = {
                    name: metric.to_dict() 
                    for name, metric in fe_p0_metrics.items()
                }
                
                # Add aggregated summary
                fe_result["summary"] = self._calculate_aggregated_metrics(
                    fe_result["metrics"], "fe"
                )
            
            # Calculate dashboard-style metrics
            dashboard_metrics = self._calculate_dashboard_metrics(fe_result["metrics"], "fe")
            fe_result["dashboard_metrics"] = dashboard_metrics
            
            if include_raw_metrics:
                fe_result["raw_metrics"] = fe_result["metrics"]
            else:
                # Replace detailed metrics with dashboard summary
                fe_result["metrics"] = dashboard_metrics
            
            return fe_result
            
        except Exception as e:
            logger.error(f"Failed to get FE metrics: {str(e)}")
            return {"success": False, "error": str(e)}

    async def _get_be_metrics(self, monitor_type: str, priority: str, format_type: str, include_raw_metrics: bool) -> List[Dict[str, Any]]:
        """Get BE monitoring metrics from all BE nodes"""
        try:
            be_nodes = await self.get_be_nodes()
            be_results = []
            
            for be_node in be_nodes:
                if be_node.get("alive") == "true":  # Only get alive BE nodes
                    be_url = f"http://{be_node['host']}:{be_node['http_port']}/metrics"
                    
                    be_result = await self.fetch_metrics_from_url(be_url, "be", be_node)
                    
                    if be_result.get("success") and priority == "p0":
                        be_p0_metrics = self._get_metrics_by_type("be", monitor_type)
                        be_result["metrics"] = self._filter_p0_metrics(
                            be_result["metrics"], 
                            be_p0_metrics
                        )
                        be_result["p0_metrics_info"] = {
                            name: metric.to_dict() 
                            for name, metric in be_p0_metrics.items()
                        }
                        
                        # Add aggregated summary
                        be_result["summary"] = self._calculate_aggregated_metrics(
                            be_result["metrics"], "be"
                        )
                    
                    # Calculate dashboard-style metrics
                    dashboard_metrics = self._calculate_dashboard_metrics(be_result["metrics"], "be")
                    be_result["dashboard_metrics"] = dashboard_metrics
                    
                    if include_raw_metrics:
                        be_result["raw_metrics"] = be_result["metrics"]
                    else:
                        # Replace detailed metrics with dashboard summary
                        be_result["metrics"] = dashboard_metrics
                    
                    be_results.append(be_result)
            
            return be_results
            
        except Exception as e:
            logger.error(f"Failed to get BE metrics: {str(e)}")
            return [{"success": False, "error": str(e)}]

    def _calculate_aggregated_metrics(self, metrics: Dict[str, Any], node_type: str) -> Dict[str, Any]:
        """
        Calculate aggregated and human-readable metrics from raw data
        
        Args:
            metrics: Raw metrics data
            node_type: Type of node ("fe" or "be")
            
        Returns:
            Dict containing aggregated metrics
        """
        aggregated = {}
        
        try:
            if node_type == "fe":
                # FE specific aggregations
                if "doris_fe_query_total" in metrics:
                    query_data = metrics["doris_fe_query_total"]
                    if isinstance(query_data, list) and query_data:
                        total_queries = max([item.get("value", 0) for item in query_data])
                        aggregated["total_queries"] = total_queries
                
                if "doris_fe_query_err" in metrics:
                    error_data = metrics["doris_fe_query_err"]
                    if isinstance(error_data, list) and error_data:
                        total_errors = max([item.get("value", 0) for item in error_data])
                        aggregated["total_query_errors"] = total_errors
                        
                        # Calculate error rate
                        if "total_queries" in aggregated and aggregated["total_queries"] > 0:
                            error_rate = (total_errors / aggregated["total_queries"]) * 100
                            aggregated["query_error_rate_percent"] = round(error_rate, 4)
                
                if "doris_fe_connection_total" in metrics:
                    aggregated["current_connections"] = metrics["doris_fe_connection_total"]
                
                if "doris_fe_max_tablet_compaction_score" in metrics:
                    aggregated["max_compaction_score"] = metrics["doris_fe_max_tablet_compaction_score"]
                
                if "doris_fe_report_queue_size" in metrics:
                    aggregated["report_queue_size"] = metrics["doris_fe_report_queue_size"]
                    
            elif node_type == "be":
                # BE specific aggregations
                
                # CPU utilization calculation
                if "doris_be_cpu" in metrics:
                    cpu_data = metrics["doris_be_cpu"]
                    cpu_summary = self._calculate_cpu_utilization(cpu_data)
                    aggregated.update(cpu_summary)
                
                # Memory utilization
                if "doris_be_memory_allocated_bytes" in metrics:
                    memory_bytes = metrics["doris_be_memory_allocated_bytes"]
                    aggregated["memory_allocated_gb"] = round(memory_bytes / (1024**3), 2)
                    aggregated["memory_allocated_mb"] = round(memory_bytes / (1024**2), 1)
                
                # Load average
                if "doris_be_load_average" in metrics:
                    load_data = metrics["doris_be_load_average"]
                    load_summary = self._extract_load_average(load_data)
                    aggregated.update(load_summary)
                
                # Network throughput
                if "doris_be_max_network_receive_bytes_rate" in metrics:
                    aggregated["network_receive_rate_mbps"] = round(
                        metrics["doris_be_max_network_receive_bytes_rate"] / (1024**2), 2
                    )
                
                if "doris_be_max_network_send_bytes_rate" in metrics:
                    aggregated["network_send_rate_mbps"] = round(
                        metrics["doris_be_max_network_send_bytes_rate"] / (1024**2), 2
                    )
                
                # Disk IO utilization
                if "doris_be_max_disk_io_util_percent" in metrics:
                    aggregated["disk_io_util_percent"] = metrics["doris_be_max_disk_io_util_percent"]
                
                # File descriptor usage
                if "doris_be_fd_num_used" in metrics and "doris_be_fd_num_limit" in metrics:
                    used = metrics["doris_be_fd_num_used"]
                    limit = metrics["doris_be_fd_num_limit"]
                    if limit > 0:
                        fd_usage_percent = round((used / limit) * 100, 2)
                        aggregated["fd_usage_percent"] = fd_usage_percent
                        aggregated["fd_used"] = used
                        aggregated["fd_limit"] = limit
                
                # Process info
                if "doris_be_process_thread_num" in metrics:
                    aggregated["thread_count"] = metrics["doris_be_process_thread_num"]
        
        except Exception as e:
            logger.error(f"Error calculating aggregated metrics for {node_type}: {str(e)}")
        
        return aggregated

    def _calculate_cpu_utilization(self, cpu_data: List[Dict]) -> Dict[str, Any]:
        """
        Calculate CPU utilization summary from raw CPU metrics
        
        Args:
            cpu_data: List of CPU metrics with labels and values
            
        Returns:
            Dict containing CPU utilization summary
        """
        cpu_summary = {}
        
        try:
            # Extract total CPU metrics (device="cpu")
            total_cpu_metrics = {}
            for item in cpu_data:
                labels = item.get("labels", {})
                if labels.get("device") == "cpu":
                    mode = labels.get("mode")
                    if mode:
                        total_cpu_metrics[mode] = item.get("value", 0)
            
            if total_cpu_metrics:
                # Calculate total time
                total_time = sum(total_cpu_metrics.values())
                
                if total_time > 0:
                    # Calculate percentages
                    idle_time = total_cpu_metrics.get("idle", 0)
                    user_time = total_cpu_metrics.get("user", 0)
                    system_time = total_cpu_metrics.get("system", 0)
                    iowait_time = total_cpu_metrics.get("iowait", 0)
                    
                    cpu_summary["cpu_usage_percent"] = round((1 - idle_time / total_time) * 100, 2)
                    cpu_summary["cpu_user_percent"] = round((user_time / total_time) * 100, 2)
                    cpu_summary["cpu_system_percent"] = round((system_time / total_time) * 100, 2)
                    cpu_summary["cpu_iowait_percent"] = round((iowait_time / total_time) * 100, 2)
                    cpu_summary["cpu_idle_percent"] = round((idle_time / total_time) * 100, 2)
        
        except Exception as e:
            logger.error(f"Error calculating CPU utilization: {str(e)}")
        
        return cpu_summary

    def _extract_load_average(self, load_data: List[Dict]) -> Dict[str, Any]:
        """
        Extract load average values
        
        Args:
            load_data: List of load average metrics
            
        Returns:
            Dict containing load average values
        """
        load_summary = {}
        
        try:
            for item in load_data:
                labels = item.get("labels", {})
                mode = labels.get("mode")
                value = item.get("value", 0)
                
                if mode == "1_minutes":
                    load_summary["load_avg_1min"] = value
                elif mode == "5_minutes":
                    load_summary["load_avg_5min"] = value
                elif mode == "15_minutes":
                    load_summary["load_avg_15min"] = value
        
        except Exception as e:
            logger.error(f"Error extracting load average: {str(e)}")
        
        return load_summary

    def _get_metrics_by_type(self, role: str, monitor_type: str) -> Dict[str, P0MetricInfo]:
        """
        Get P0 metrics by role and monitor type
        
        Args:
            role: Node role ("fe" or "be")
            monitor_type: Monitor type ("process", "jvm", "machine", "all")
            
        Returns:
            Dict of P0 metric information
        """
        if role == "fe":
            if monitor_type == "process":
                return P0Metrics.get_fe_process_metrics()
            elif monitor_type == "jvm":
                return P0Metrics.get_fe_jvm_metrics()
            elif monitor_type == "machine":
                return P0Metrics.get_fe_machine_metrics()
            else:  # "all"
                return P0Metrics.get_fe_p0_metrics()
        elif role == "be":
            if monitor_type == "process":
                return P0Metrics.get_be_process_metrics()
            elif monitor_type == "jvm":
                return {}  # BE doesn't have JVM metrics
            elif monitor_type == "machine":
                return P0Metrics.get_be_machine_metrics()
            else:  # "all"
                return P0Metrics.get_be_p0_metrics()
        
        return {}

    def _filter_p0_metrics(self, metrics: Dict[str, Any], p0_metrics: Dict[str, P0MetricInfo]) -> Dict[str, Any]:
        """Filter out P0 level monitoring metrics"""
        filtered_metrics = {}
        
        for metric_name, metric_value in metrics.items():
            # Check if it's a P0 level metric
            if metric_name in p0_metrics:
                filtered_metrics[metric_name] = metric_value
            else:
                # Check if it's a variant of P0 metric (with labels)
                for p0_name in p0_metrics.keys():
                    if metric_name.startswith(p0_name):
                        filtered_metrics[metric_name] = metric_value
                        break
        
        return filtered_metrics 

    def _simplify_fe_metrics(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Simplify FE metrics"""
        simplified_metrics = {}
        
        for metric_name, metric_value in metrics.items():
            if isinstance(metric_value, list):
                # Convert list to single value
                simplified_metrics[metric_name] = max([item.get("value", 0) for item in metric_value])
            else:
                simplified_metrics[metric_name] = metric_value
        
        return simplified_metrics 

    def _simplify_be_metrics(self, raw_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simplify BE metrics by aggregating complex arrays into single values
        
        Args:
            raw_metrics: Raw metrics data with complex arrays
            
        Returns:
            Simplified metrics with aggregated values
        """
        simplified = {}
        
        for key, value in raw_metrics.items():
            if key == "doris_be_cpu" and isinstance(value, list):
                # Calculate actual CPU usage percentage from cumulative CPU time values
                cpu_times = {}
                total_time = 0
                
                for item in value:
                    if isinstance(item, dict) and "labels" in item:
                        device = item["labels"].get("device", "")
                        mode = item["labels"].get("mode", "")
                        cpu_value = item.get("value", 0)
                        
                        # Only process total CPU (device="cpu") metrics
                        if device == "cpu":
                            cpu_times[mode] = cpu_value
                            total_time += cpu_value
                
                # Calculate CPU usage percentage
                if total_time > 0:
                    idle_time = cpu_times.get("idle", 0)
                    usage_time = total_time - idle_time
                    cpu_usage_percent = round((usage_time / total_time) * 100, 2)
                    simplified[key] = cpu_usage_percent
                else:
                    simplified[key] = 0.0
                    
            elif key in ["doris_be_network_receive_bytes", "doris_be_network_send_bytes"] and isinstance(value, list):
                # Sum network bytes across all devices (excluding loopback)
                total_bytes = 0
                for item in value:
                    if isinstance(item, dict) and "labels" in item:
                        device = item["labels"].get("device", "")
                        # Exclude loopback interface
                        if device != "lo":
                            total_bytes += item.get("value", 0)
                simplified[key] = total_bytes
                
            elif key == "doris_be_load_average" and isinstance(value, list):
                # Convert load average array to dict for easier access
                load_avg = {}
                for item in value:
                    if isinstance(item, dict) and "labels" in item:
                        mode = item["labels"].get("mode", "")
                        load_avg[mode] = item.get("value", 0)
                simplified[key] = load_avg
                
            elif key == "doris_be_proc" and isinstance(value, list):
                # Convert proc array to dict for easier access
                proc_info = {}
                for item in value:
                    if isinstance(item, dict) and "labels" in item:
                        mode = item["labels"].get("mode", "")
                        proc_info[mode] = item.get("value", 0)
                simplified[key] = proc_info
                
            else:
                # Keep simple values as-is
                simplified[key] = value
                
        return simplified

    def _calculate_dashboard_metrics(self, raw_metrics: Dict[str, Any], role: str) -> Dict[str, Any]:
        """
        Calculate dashboard-style aggregated metrics based on Doris Dashboard configuration
        
        Args:
            raw_metrics: Raw metrics data from Prometheus endpoint
            role: Node role (fe/be)
            
        Returns:
            Dashboard-style aggregated metrics
        """
        dashboard_metrics = {}
        
        if role == "fe":
            dashboard_metrics.update(self._calculate_fe_dashboard_metrics(raw_metrics))
        elif role == "be":
            dashboard_metrics.update(self._calculate_be_dashboard_metrics(raw_metrics))
            
        return dashboard_metrics
    
    def _calculate_fe_dashboard_metrics(self, raw_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate FE dashboard metrics based on Dashboard configuration
        """
        fe_metrics = {}
        
        # Query metrics
        fe_metrics["query_total_rate"] = self._get_rate_value(raw_metrics, "doris_fe_query_total")
        fe_metrics["query_latency_99p_ms"] = self._get_quantile_value(raw_metrics, "doris_fe_query_latency_ms", "0.99")
        fe_metrics["query_error_count"] = self._get_simple_value(raw_metrics, "doris_fe_query_err")
        fe_metrics["query_error_rate"] = self._get_rate_value(raw_metrics, "doris_fe_query_err")
        
        # Connection metrics
        fe_metrics["connection_total"] = self._get_simple_value(raw_metrics, "doris_fe_connection_total")
        
        # Request metrics
        fe_metrics["request_total_rate"] = self._get_rate_value(raw_metrics, "doris_fe_request_total")
        
        # JVM metrics
        fe_metrics["jvm_heap_used_bytes"] = self._get_simple_value(raw_metrics, "jvm_heap_size_bytes", labels={"type": "used"})
        fe_metrics["jvm_heap_max_bytes"] = self._get_simple_value(raw_metrics, "jvm_heap_size_bytes", labels={"type": "max"})
        fe_metrics["jvm_heap_usage_percent"] = self._calculate_jvm_heap_usage_percent(raw_metrics)
        
        # Old/Young GC metrics
        fe_metrics["jvm_old_gc_count"] = self._get_simple_value(raw_metrics, "jvm_old_gc", labels={"type": "count"})
        fe_metrics["jvm_old_gc_avg_time"] = self._calculate_gc_avg_time(raw_metrics, "jvm_old_gc")
        fe_metrics["jvm_young_gc_count"] = self._get_simple_value(raw_metrics, "jvm_young_gc", labels={"type": "count"})
        fe_metrics["jvm_young_gc_avg_time"] = self._calculate_gc_avg_time(raw_metrics, "jvm_young_gc")
        
        # Tablet metrics
        fe_metrics["tablet_max_compaction_score"] = self._get_simple_value(raw_metrics, "doris_fe_tablet_max_compaction_score")
        fe_metrics["tablet_unhealthy_count"] = self._get_simple_value(raw_metrics, "doris_fe_tablet_status_count", labels={"type": "unhealthy"})
        fe_metrics["tablet_scheduled_num"] = self._get_simple_value(raw_metrics, "doris_fe_scheduled_tablet_num")
        
        # Transaction metrics
        fe_metrics["txn_begin_total"] = self._get_simple_value(raw_metrics, "doris_fe_txn_counter", labels={"type": "begin"})
        fe_metrics["txn_success_total"] = self._get_simple_value(raw_metrics, "doris_fe_txn_counter", labels={"type": "success"})
        fe_metrics["txn_begin_rate"] = self._get_rate_value(raw_metrics, "doris_fe_txn_counter", labels={"type": "begin"})
        fe_metrics["txn_success_rate"] = self._get_rate_value(raw_metrics, "doris_fe_txn_counter", labels={"type": "success"})
        fe_metrics["txn_reject_rate"] = self._get_rate_value(raw_metrics, "doris_fe_txn_counter", labels={"type": "reject"})
        fe_metrics["txn_failed_rate"] = self._get_rate_value(raw_metrics, "doris_fe_txn_counter", labels={"type": "failed"})
        
        # Edit log metrics
        fe_metrics["edit_log_write_rate"] = self._get_rate_value(raw_metrics, "doris_fe_edit_log", labels={"type": "write"})
        fe_metrics["edit_log_read_rate"] = self._get_rate_value(raw_metrics, "doris_fe_edit_log", labels={"type": "read"})
        fe_metrics["edit_log_write_latency_99p_ms"] = self._get_quantile_value(raw_metrics, "doris_fe_editlog_write_latency_ms", "0.99")
        
        # Report queue
        fe_metrics["report_queue_size"] = self._get_simple_value(raw_metrics, "doris_fe_report_queue_size")
        
        return {k: v for k, v in fe_metrics.items() if v is not None}
    
    def _calculate_be_dashboard_metrics(self, raw_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate BE dashboard metrics based on Dashboard configuration
        """
        be_metrics = {}
        
        # Stream load metrics
        be_metrics["stream_load_receive_bytes_rate"] = self._get_rate_value(raw_metrics, "doris_be_stream_load", labels={"type": "receive_bytes"})
        be_metrics["stream_load_rows_rate"] = self._get_rate_value(raw_metrics, "doris_be_stream_load", labels={"type": "load_rows"})
        be_metrics["stream_load_txn_request_rate"] = self._get_rate_value(raw_metrics, "doris_be_stream_load_txn_request")
        
        # Engine request metrics
        be_metrics["engine_publish_total"] = self._get_simple_value(raw_metrics, "doris_be_engine_requests_total", labels={"type": "publish", "status": "total"})
        be_metrics["engine_publish_failed_rate"] = self._get_rate_value(raw_metrics, "doris_be_engine_requests_total", labels={"type": "publish", "status": "failed"})
        
        # Disk metrics
        be_metrics["disks_used_capacity_bytes"] = self._get_simple_value(raw_metrics, "doris_be_disks_local_used_capacity")
        be_metrics["disks_total_capacity_bytes"] = self._get_simple_value(raw_metrics, "doris_be_disks_total_capacity")
        be_metrics["disks_usage_percent"] = self._calculate_disk_usage_percent(raw_metrics)
        
        # Memory metrics
        be_metrics["memory_allocated_bytes"] = self._get_simple_value(raw_metrics, "doris_be_memory_allocated_bytes")
        be_metrics["memory_jemalloc_active_bytes"] = self._get_simple_value(raw_metrics, "doris_be_memory_jemalloc_active_bytes")
        be_metrics["memory_jemalloc_allocated_bytes"] = self._get_simple_value(raw_metrics, "doris_be_memory_jemalloc_allocated_bytes")
        be_metrics["memory_jemalloc_resident_bytes"] = self._get_simple_value(raw_metrics, "doris_be_memory_jemalloc_resident_bytes")
        
        # Process metrics
        be_metrics["process_fd_num_limit_soft"] = self._get_simple_value(raw_metrics, "doris_be_process_fd_num_limit_soft")
        be_metrics["process_fd_num_used"] = self._get_simple_value(raw_metrics, "doris_be_process_fd_num_used")
        be_metrics["process_fd_usage_percent"] = self._calculate_fd_usage_percent(raw_metrics)
        
        # CPU usage calculation (based on dashboard logic)
        be_metrics["cpu_usage_percent"] = self._calculate_cpu_usage_percent(raw_metrics)
        
        # Network metrics (aggregated)
        be_metrics["network_receive_bytes_total"] = self._aggregate_network_bytes(raw_metrics, "doris_be_network_receive_bytes")
        be_metrics["network_send_bytes_total"] = self._aggregate_network_bytes(raw_metrics, "doris_be_network_send_bytes")
        
        return {k: v for k, v in be_metrics.items() if v is not None}
    
    def _get_simple_value(self, raw_metrics: Dict[str, Any], metric_name: str, labels: Dict[str, str] = None) -> float:
        """
        Get simple metric value, optionally filtered by labels
        """
        try:
            if metric_name not in raw_metrics:
                return None
                
            metric_data = raw_metrics[metric_name]
            
            if isinstance(metric_data, (int, float)):
                return float(metric_data)
            elif isinstance(metric_data, list):
                if labels:
                    # Find matching labels
                    for item in metric_data:
                        if isinstance(item, dict) and "labels" in item:
                            if all(item["labels"].get(k) == v for k, v in labels.items()):
                                return float(item.get("value", 0))
                else:
                    # Sum all values if no labels specified
                    return sum(float(item.get("value", 0)) for item in metric_data if isinstance(item, dict))
            
            return None
        except (ValueError, TypeError, KeyError):
            return None
    
    def _get_rate_value(self, raw_metrics: Dict[str, Any], metric_name: str, labels: Dict[str, str] = None) -> float:
        """
        Get rate value (would need historical data for actual rate calculation, using current value as approximation)
        """
        # For now, return the current value as rate calculation needs time series data
        return self._get_simple_value(raw_metrics, metric_name, labels)
    
    def _get_quantile_value(self, raw_metrics: Dict[str, Any], metric_name: str, quantile: str) -> float:
        """
        Get quantile value from metrics
        """
        return self._get_simple_value(raw_metrics, metric_name, labels={"quantile": quantile})
    
    def _calculate_jvm_heap_usage_percent(self, raw_metrics: Dict[str, Any]) -> float:
        """
        Calculate JVM heap usage percentage: used / max * 100
        """
        try:
            used = self._get_simple_value(raw_metrics, "jvm_heap_size_bytes", labels={"type": "used"})
            max_size = self._get_simple_value(raw_metrics, "jvm_heap_size_bytes", labels={"type": "max"})
            
            if used is not None and max_size is not None and max_size > 0:
                return round((used / max_size) * 100, 2)
            return None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    
    def _calculate_gc_avg_time(self, raw_metrics: Dict[str, Any], gc_metric_name: str) -> float:
        """
        Calculate GC average time: total_time / count
        """
        try:
            total_time = self._get_simple_value(raw_metrics, gc_metric_name, labels={"type": "time"})
            count = self._get_simple_value(raw_metrics, gc_metric_name, labels={"type": "count"})
            
            if total_time is not None and count is not None and count > 0:
                return round(total_time / count, 2)
            return None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    
    def _calculate_disk_usage_percent(self, raw_metrics: Dict[str, Any]) -> float:
        """
        Calculate disk usage percentage: used / total * 100
        """
        try:
            used = self._get_simple_value(raw_metrics, "doris_be_disks_local_used_capacity")
            total = self._get_simple_value(raw_metrics, "doris_be_disks_total_capacity")
            
            if used is not None and total is not None and total > 0:
                return round((used / total) * 100, 2)
            return None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    
    def _calculate_fd_usage_percent(self, raw_metrics: Dict[str, Any]) -> float:
        """
        Calculate file descriptor usage percentage: used / limit * 100
        """
        try:
            used = self._get_simple_value(raw_metrics, "doris_be_process_fd_num_used")
            limit = self._get_simple_value(raw_metrics, "doris_be_process_fd_num_limit_soft")
            
            if used is not None and limit is not None and limit > 0:
                return round((used / limit) * 100, 2)
            return None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    
    def _calculate_cpu_usage_percent(self, raw_metrics: Dict[str, Any]) -> float:
        """
        Calculate CPU usage percentage based on dashboard logic: 100 - idle%
        """
        try:
            if "doris_be_cpu" not in raw_metrics:
                return None
                
            cpu_data = raw_metrics["doris_be_cpu"]
            if not isinstance(cpu_data, list):
                return None
            
            total_idle = 0
            total_time = 0
            
            for item in cpu_data:
                if isinstance(item, dict) and "labels" in item and "value" in item:
                    mode = item["labels"].get("mode", "")
                    value = float(item["value"])
                    total_time += value
                    if mode == "idle":
                        total_idle += value
            
            if total_time > 0:
                idle_percent = (total_idle / total_time) * 100
                cpu_usage = 100 - idle_percent
                return round(max(0, min(100, cpu_usage)), 2)
            
            return None
        except (ValueError, TypeError, ZeroDivisionError):
            return None
    
    def _aggregate_network_bytes(self, raw_metrics: Dict[str, Any], metric_name: str) -> int:
        """
        Aggregate network bytes excluding loopback interface
        """
        try:
            if metric_name not in raw_metrics:
                return None
                
            network_data = raw_metrics[metric_name]
            if not isinstance(network_data, list):
                return int(network_data) if isinstance(network_data, (int, float)) else None
            
            total_bytes = 0
            for item in network_data:
                if isinstance(item, dict) and "labels" in item and "value" in item:
                    device = item["labels"].get("device", "")
                    if device != "lo":  # Exclude loopback
                        total_bytes += int(item["value"])
            
            return total_bytes
        except (ValueError, TypeError):
            return None
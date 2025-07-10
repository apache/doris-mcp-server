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
Enhanced Logging configuration for Doris MCP Server.
Features:
- Log level-based file separation
- Timestamped log entries
- Automatic log rotation
- Comprehensive logging coverage
"""

import logging
import logging.config
import logging.handlers
import sys
import os
import asyncio
import time
from pathlib import Path
from typing import Any, Optional
from datetime import datetime, timedelta
import threading


class TimestampedFormatter(logging.Formatter):
    """Custom formatter with enhanced timestamp and structured format"""
    
    def __init__(self, fmt=None, datefmt=None, style='%'):
        if fmt is None:
            fmt = "%(asctime)s.%(msecs)03d %(level_aligned)s %(name)s:%(lineno)d - %(message)s"
        if datefmt is None:
            datefmt = "%Y-%m-%d %H:%M:%S"
        super().__init__(fmt, datefmt, style)
    
    def format(self, record):
        """Format log record with enhanced information and proper alignment"""
        # Add process info if available
        if hasattr(record, 'process') and record.process:
            record.process_info = f"[PID:{record.process}]"
        else:
            record.process_info = ""
        
        # Add thread info if available
        if hasattr(record, 'thread') and record.thread:
            record.thread_info = f"[TID:{record.thread}]"
        else:
            record.thread_info = ""
        
        # Format with proper alignment after the level name
        # Calculate padding needed for alignment
        level_name = record.levelname
        max_level_length = 8  # Length of "CRITICAL"
        padding = max_level_length - len(level_name)
        record.level_aligned = f"[{level_name}]{' ' * padding}"
        
        return super().format(record)


class LevelBasedFileHandler(logging.Handler):
    """Custom handler that writes different log levels to different files"""
    
    def __init__(self, log_dir: str, base_name: str = "doris_mcp_server", 
                 max_bytes: int = 10*1024*1024, backup_count: int = 5):
        super().__init__()
        self.log_dir = Path(log_dir)
        self.base_name = base_name
        self.max_bytes = max_bytes
        self.backup_count = backup_count
        
        # Ensure log directory exists
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Create handlers for different log levels
        self.handlers = {}
        self._setup_level_handlers()
    
    def _setup_level_handlers(self):
        """Setup rotating file handlers for different log levels"""
        level_files = {
            'DEBUG': 'debug.log',
            'INFO': 'info.log', 
            'WARNING': 'warning.log',
            'ERROR': 'error.log',
            'CRITICAL': 'critical.log'
        }
        
        formatter = TimestampedFormatter()
        
        for level, filename in level_files.items():
            file_path = self.log_dir / f"{self.base_name}_{filename}"
            handler = logging.handlers.RotatingFileHandler(
                file_path, 
                maxBytes=self.max_bytes,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            handler.setFormatter(formatter)
            handler.setLevel(getattr(logging, level))
            self.handlers[level] = handler
    
    def emit(self, record):
        """Emit log record to appropriate level-based file"""
        level_name = record.levelname
        if level_name in self.handlers:
            try:
                self.handlers[level_name].emit(record)
            except Exception:
                self.handleError(record)
    
    def close(self):
        """Close all handlers"""
        for handler in self.handlers.values():
            handler.close()
        super().close()


class LogCleanupManager:
    """Log file cleanup manager for automatic maintenance"""
    
    def __init__(self, log_dir: str, max_age_days: int = 30, cleanup_interval_hours: int = 24):
        """
        Initialize log cleanup manager.
        
        Args:
            log_dir: Directory containing log files
            max_age_days: Maximum age of log files in days (default: 30 days)
            cleanup_interval_hours: Cleanup interval in hours (default: 24 hours)
        """
        self.log_dir = Path(log_dir)
        self.max_age_days = max_age_days
        self.cleanup_interval_hours = cleanup_interval_hours
        self.cleanup_thread = None
        self.stop_event = threading.Event()
        self.logger = None
    
    def start_cleanup_scheduler(self):
        """Start the cleanup scheduler in a background thread"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            return
        
        self.stop_event.clear()
        self.cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
        self.cleanup_thread.start()
        
        # Get logger for this class
        if not self.logger:
            self.logger = logging.getLogger("doris_mcp_server.log_cleanup")
        
        self.logger.info(f"Log cleanup scheduler started - cleanup every {self.cleanup_interval_hours}h, max age {self.max_age_days} days")
    
    def stop_cleanup_scheduler(self):
        """Stop the cleanup scheduler"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.stop_event.set()
            self.cleanup_thread.join(timeout=5)
            if self.logger:
                self.logger.info("Log cleanup scheduler stopped")
    
    def _cleanup_loop(self):
        """Background loop for periodic cleanup"""
        while not self.stop_event.is_set():
            try:
                self.cleanup_old_logs()
                # Sleep for the specified interval, but check stop event every 60 seconds
                for _ in range(self.cleanup_interval_hours * 60):  # Convert hours to minutes
                    if self.stop_event.wait(60):  # Wait 60 seconds or until stop event
                        break
            except Exception as e:
                if self.logger:
                    self.logger.error(f"Error in log cleanup loop: {e}")
                # Sleep for 5 minutes before retrying
                self.stop_event.wait(300)
    
    def cleanup_old_logs(self):
        """Clean up old log files based on age"""
        if not self.log_dir.exists():
            return
        
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(days=self.max_age_days)
        
        cleaned_files = []
        cleaned_size = 0
        
        # Pattern for log files (including backup files)
        log_patterns = [
            "doris_mcp_server_*.log",
            "doris_mcp_server_*.log.*"  # Backup files
        ]
        
        for pattern in log_patterns:
            for log_file in self.log_dir.glob(pattern):
                try:
                    # Get file modification time
                    file_mtime = datetime.fromtimestamp(log_file.stat().st_mtime)
                    
                    if file_mtime < cutoff_time:
                        file_size = log_file.stat().st_size
                        log_file.unlink()  # Delete the file
                        cleaned_files.append(log_file.name)
                        cleaned_size += file_size
                        
                except Exception as e:
                    if self.logger:
                        self.logger.warning(f"Failed to cleanup log file {log_file}: {e}")
        
        if cleaned_files and self.logger:
            size_mb = cleaned_size / (1024 * 1024)
            self.logger.info(f"Cleaned up {len(cleaned_files)} old log files, freed {size_mb:.2f} MB")
            self.logger.debug(f"Cleaned files: {', '.join(cleaned_files)}")
    
    def get_cleanup_stats(self) -> dict:
        """Get statistics about log files and cleanup status"""
        if not self.log_dir.exists():
            return {"error": "Log directory does not exist"}
        
        stats = {
            "log_directory": str(self.log_dir.absolute()),
            "max_age_days": self.max_age_days,
            "cleanup_interval_hours": self.cleanup_interval_hours,
            "scheduler_running": self.cleanup_thread and self.cleanup_thread.is_alive(),
            "total_files": 0,
            "total_size_mb": 0,
            "files_by_age": {"recent": 0, "old": 0},
            "oldest_file": None,
            "newest_file": None
        }
        
        current_time = datetime.now()
        cutoff_time = current_time - timedelta(days=self.max_age_days)
        oldest_time = None
        newest_time = None
        
        log_patterns = ["doris_mcp_server_*.log", "doris_mcp_server_*.log.*"]
        
        for pattern in log_patterns:
            for log_file in self.log_dir.glob(pattern):
                try:
                    file_stat = log_file.stat()
                    file_mtime = datetime.fromtimestamp(file_stat.st_mtime)
                    
                    stats["total_files"] += 1
                    stats["total_size_mb"] += file_stat.st_size / (1024 * 1024)
                    
                    if file_mtime < cutoff_time:
                        stats["files_by_age"]["old"] += 1
                    else:
                        stats["files_by_age"]["recent"] += 1
                    
                    if oldest_time is None or file_mtime < oldest_time:
                        oldest_time = file_mtime
                        stats["oldest_file"] = {"name": log_file.name, "age_days": (current_time - file_mtime).days}
                    
                    if newest_time is None or file_mtime > newest_time:
                        newest_time = file_mtime
                        stats["newest_file"] = {"name": log_file.name, "age_days": (current_time - file_mtime).days}
                        
                except Exception:
                    continue
        
        stats["total_size_mb"] = round(stats["total_size_mb"], 2)
        
        return stats


class DorisLoggerManager:
    """Centralized logger manager for Doris MCP Server"""
    
    def __init__(self):
        self.is_initialized = False
        self.log_dir = None
        self.config = None
        self.loggers = {}
        self.cleanup_manager = None
    
    def setup_logging(self, 
                     level: str = "INFO",
                     log_dir: str = "logs",
                     enable_console: bool = True,
                     enable_file: bool = True,
                     enable_audit: bool = True,
                     audit_file: Optional[str] = None,
                     max_file_size: int = 10*1024*1024,
                     backup_count: int = 5,
                     enable_cleanup: bool = True,
                     max_age_days: int = 30,
                     cleanup_interval_hours: int = 24) -> None:
        """
        Setup comprehensive logging configuration.
        
        Args:
            level: Base logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_dir: Directory for log files
            enable_console: Enable console output
            enable_file: Enable file logging
            enable_audit: Enable audit logging
            audit_file: Custom audit log file path
            max_file_size: Maximum size per log file (bytes)
            backup_count: Number of backup files to keep
            enable_cleanup: Enable automatic log cleanup
            max_age_days: Maximum age of log files in days (default: 30)
            cleanup_interval_hours: Cleanup interval in hours (default: 24)
        """
        if self.is_initialized:
            return
        
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Clear existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Set root logger level
        root_logger.setLevel(logging.DEBUG)  # Allow all levels, handlers will filter
        
        handlers = []
        
        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, level.upper()))
            console_formatter = TimestampedFormatter(
                fmt="%(asctime)s.%(msecs)03d %(level_aligned)s %(name)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            console_handler.setFormatter(console_formatter)
            handlers.append(console_handler)
        
        # Level-based file handlers
        if enable_file:
            level_handler = LevelBasedFileHandler(
                log_dir=str(self.log_dir),
                base_name="doris_mcp_server",
                max_bytes=max_file_size,
                backup_count=backup_count
            )
            level_handler.setLevel(logging.DEBUG)  # Accept all levels
            handlers.append(level_handler)
        
        # Combined application log (all levels in one file)
        if enable_file:
            app_log_file = self.log_dir / "doris_mcp_server_all.log"
            app_handler = logging.handlers.RotatingFileHandler(
                app_log_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            app_handler.setLevel(getattr(logging, level.upper()))
            app_formatter = TimestampedFormatter()
            app_handler.setFormatter(app_formatter)
            handlers.append(app_handler)
        
        # Audit logger (separate from main logging)
        if enable_audit:
            audit_file_path = audit_file or str(self.log_dir / "doris_mcp_server_audit.log")
            audit_logger = logging.getLogger("audit")
            audit_logger.setLevel(logging.INFO)
            
            # Clear existing audit handlers
            for handler in audit_logger.handlers[:]:
                audit_logger.removeHandler(handler)
            
            audit_handler = logging.handlers.RotatingFileHandler(
                audit_file_path,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            audit_formatter = TimestampedFormatter(
                fmt="%(asctime)s.%(msecs)03d [AUDIT] %(name)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            audit_handler.setFormatter(audit_formatter)
            audit_logger.addHandler(audit_handler)
            audit_logger.propagate = False  # Don't propagate to root logger
        
        # Add all handlers to root logger
        for handler in handlers:
            root_logger.addHandler(handler)
        
        # Setup package-specific loggers
        self._setup_package_loggers(level)
        
        # Setup log cleanup manager
        if enable_cleanup and enable_file:
            self.cleanup_manager = LogCleanupManager(
                log_dir=str(self.log_dir),
                max_age_days=max_age_days,
                cleanup_interval_hours=cleanup_interval_hours
            )
            self.cleanup_manager.start_cleanup_scheduler()
        
        self.is_initialized = True
        
        # Log initialization message
        logger = self.get_logger("doris_mcp_server.logger")
        logger.info("=" * 80)
        logger.info("Doris MCP Server Logging System Initialized")
        logger.info(f"Log Level: {level}")
        logger.info(f"Log Directory: {self.log_dir.absolute()}")
        logger.info(f"Console Logging: {'Enabled' if enable_console else 'Disabled'}")
        logger.info(f"File Logging: {'Enabled' if enable_file else 'Disabled'}")
        logger.info(f"Audit Logging: {'Enabled' if enable_audit else 'Disabled'}")
        logger.info(f"Log Cleanup: {'Enabled' if enable_cleanup and enable_file else 'Disabled'}")
        if enable_cleanup and enable_file:
            logger.info(f"Cleanup Settings: Max age {max_age_days} days, interval {cleanup_interval_hours}h")
        logger.info("=" * 80)
    
    def _setup_package_loggers(self, level: str):
        """Setup specific loggers for different modules"""
        package_loggers = [
            "doris_mcp_server",
            "doris_mcp_server.main",
            "doris_mcp_server.utils",
            "doris_mcp_server.tools",
            "doris_mcp_client"
        ]
        
        for logger_name in package_loggers:
            logger = logging.getLogger(logger_name)
            logger.setLevel(getattr(logging, level.upper()))
            # Don't add handlers here - they inherit from root logger
    
    def get_logger(self, name: str) -> logging.Logger:
        """
        Get a logger instance with proper configuration.
        
        Args:
            name: Logger name (usually __name__)
            
        Returns:
            Configured logger instance
        """
        if name not in self.loggers:
            logger = logging.getLogger(name)
            self.loggers[name] = logger
        
        return self.loggers[name]
    
    def get_audit_logger(self) -> logging.Logger:
        """Get the audit logger"""
        return logging.getLogger("audit")
    
    def log_system_info(self):
        """Log system information for debugging"""
        logger = self.get_logger("doris_mcp_server.system")
        logger.info("System Information:")
        logger.info(f"Python Version: {sys.version}")
        logger.info(f"Platform: {sys.platform}")
        logger.info(f"Working Directory: {os.getcwd()}")
        logger.info(f"Process ID: {os.getpid()}")
        
        # Log environment variables (filtered)
        env_vars = ["LOG_LEVEL", "LOG_FILE_PATH", "ENABLE_AUDIT", "AUDIT_FILE_PATH"]
        for var in env_vars:
            value = os.getenv(var, "Not Set")
            logger.info(f"Environment {var}: {value}")
    
    def get_cleanup_stats(self) -> dict:
        """Get log cleanup statistics"""
        if self.cleanup_manager:
            return self.cleanup_manager.get_cleanup_stats()
        else:
            return {"error": "Log cleanup is not enabled"}
    
    def manual_cleanup(self) -> dict:
        """Manually trigger log cleanup and return statistics"""
        if self.cleanup_manager:
            self.cleanup_manager.cleanup_old_logs()
            return self.cleanup_manager.get_cleanup_stats()
        else:
            return {"error": "Log cleanup is not enabled"}
    
    def shutdown(self):
        """Shutdown logging system"""
        if not self.is_initialized:
            return
        
        logger = self.get_logger("doris_mcp_server.logger")
        logger.info("Shutting down logging system...")
        
        # Stop cleanup manager
        if self.cleanup_manager:
            self.cleanup_manager.stop_cleanup_scheduler()
        
        # Close all handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            try:
                handler.close()
            except Exception as e:
                print(f"Error closing handler: {e}")
        
        # Close audit logger handlers
        audit_logger = logging.getLogger("audit")
        for handler in audit_logger.handlers[:]:
            try:
                handler.close()
            except Exception as e:
                print(f"Error closing audit handler: {e}")
        
        self.is_initialized = False


# Global logger manager instance
_logger_manager = DorisLoggerManager()


def setup_logging(level: str = "INFO",
                 log_dir: str = "logs",
                 enable_console: bool = True,
                 enable_file: bool = True,
                 enable_audit: bool = True,
                 audit_file: Optional[str] = None,
                 max_file_size: int = 10*1024*1024,
                 backup_count: int = 5,
                 enable_cleanup: bool = True,
                 max_age_days: int = 30,
                 cleanup_interval_hours: int = 24) -> None:
    """
    Setup logging configuration (convenience function).
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        enable_console: Enable console output
        enable_file: Enable file logging
        enable_audit: Enable audit logging
        audit_file: Custom audit log file path
        max_file_size: Maximum size per log file (bytes)
        backup_count: Number of backup files to keep
        enable_cleanup: Enable automatic log cleanup
        max_age_days: Maximum age of log files in days (default: 30)
        cleanup_interval_hours: Cleanup interval in hours (default: 24)
    """
    _logger_manager.setup_logging(
        level=level,
        log_dir=log_dir,
        enable_console=enable_console,
        enable_file=enable_file,
        enable_audit=enable_audit,
        audit_file=audit_file,
        max_file_size=max_file_size,
        backup_count=backup_count,
        enable_cleanup=enable_cleanup,
        max_age_days=max_age_days,
        cleanup_interval_hours=cleanup_interval_hours
    )


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance.
    
    Args:
        name: Logger name (usually __name__)
        
    Returns:
        Configured logger instance
    """
    return _logger_manager.get_logger(name)


def get_audit_logger() -> logging.Logger:
    """Get the audit logger"""
    return _logger_manager.get_audit_logger()


def log_system_info():
    """Log system information for debugging"""
    _logger_manager.log_system_info()


def get_cleanup_stats() -> dict:
    """Get log cleanup statistics"""
    return _logger_manager.get_cleanup_stats()


def manual_cleanup() -> dict:
    """Manually trigger log cleanup and return statistics"""
    return _logger_manager.manual_cleanup()


def shutdown_logging():
    """Shutdown logging system"""
    _logger_manager.shutdown()


# Compatibility function for existing code
def setup_logging_old(level: str = "INFO",
                     log_file: str | None = None,
                     log_format: str | None = None) -> None:
    """
    Legacy setup function for backward compatibility.
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_file: Optional log file path (deprecated - use log_dir instead)
        log_format: Optional custom log format (deprecated)
    """
    # Extract directory from log_file if provided
    log_dir = "logs"
    if log_file:
        log_dir = str(Path(log_file).parent)
    
    setup_logging(
        level=level,
        log_dir=log_dir,
        enable_console=True,
        enable_file=True,
        enable_audit=True
    )

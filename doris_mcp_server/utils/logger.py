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
import os
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from .redaction import SensitiveDataFilter

_sensitive_data_filter = SensitiveDataFilter()


class TimestampedFormatter(logging.Formatter):
    """Custom formatter with enhanced timestamp and structured format"""

    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        style: Literal["%", "{", "$"] = "%",
    ) -> None:
        if fmt is None:
            fmt = "%(asctime)s.%(msecs)03d %(level_aligned)s [user=%(user)s token=%(token_id)s ip=%(client_ip)s] %(name)s:%(lineno)d - %(message)s"
        if datefmt is None:
            datefmt = "%Y-%m-%d %H:%M:%S"
        super().__init__(fmt, datefmt, style)

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with enhanced information and proper alignment"""
        # Ensure request-auth fields always resolve. RequestAuthContextFilter
        # normally sets them on every record; setdefault is a safety net for
        # records that somehow bypassed the filter, so format() never KeyErrors.
        record.__dict__.setdefault("user", "-")
        record.__dict__.setdefault("token_id", "-")
        record.__dict__.setdefault("client_ip", "-")

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


class RequestAuthContextFilter(logging.Filter):
    """Inject the current request's user identity into every log record.

    Reads ``AuthContext`` from the ``mcp_auth_context_var`` ContextVar (set
    per-request by the auth middleware / HTTP entrypoints) and exposes
    ``user`` / ``token_id`` / ``client_ip`` on the record so the formatter
    can include them. Falls back to '-' when no request is in flight
    (stdio mode, startup logs, background threads).

    Attach to a Handler (not a Logger) so it runs for records emitted by any
    submodule. ``Filter.filter()`` runs before ``Formatter.format()``, so the
    ``%(user)s`` / ``%(token_id)s`` / ``%(client_ip)s`` placeholders resolve.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            # Lazy import avoids a circular dependency (security imports
            # logger helpers for its own logging).
            from .security import mcp_auth_context_var

            ctx = mcp_auth_context_var.get()
        except Exception:
            ctx = None
        record.user = getattr(ctx, "user_id", "") or "-"
        record.token_id = getattr(ctx, "token_id", "") or "-"
        record.client_ip = getattr(ctx, "client_ip", "") or "-"
        return True


class TimestampRotatingFileHandler(logging.handlers.RotatingFileHandler):
    """Size-based rotating handler whose backups are stamped with the rollover time.

    Rotates by file size exactly like ``RotatingFileHandler``, but instead of
    producing ``file.log.1``, ``file.log.2`` ... it renames the current file to
    ``file_<YYYYmmdd_HHMMSS>.log`` on each rollover and keeps only the most
    recent ``backupCount`` backups (oldest-by-mtime are pruned).
    """

    _TS_FMT = "%Y%m%d_%H%M%S"

    def _rotated_path(self, ts: str) -> str:
        base = self.baseFilename
        if base.endswith(".log"):
            return f"{base[:-len('.log')]}_{ts}.log"
        return f"{base}_{ts}"

    def _backup_files(self) -> list[str]:
        """List rotated backup files owned by this handler (excludes the live file)."""
        base = self.baseFilename
        parent = os.path.dirname(base) or "."
        if base.endswith(".log"):
            stem = os.path.basename(base[:-len(".log")])
        else:
            stem = os.path.basename(base)
        prefix = f"{stem}_"
        files: list[str] = []
        try:
            for name in os.listdir(parent):
                if name.startswith(prefix) and name.endswith(".log"):
                    files.append(os.path.join(parent, name))
        except OSError:
            return []
        return files

    def doRollover(self) -> None:
        """Rotate the current log to a timestamped backup, pruning old backups."""
        if self.stream:
            self.stream.close()
            self.stream = None

        ts = datetime.now().strftime(self._TS_FMT)
        rotated = self._rotated_path(ts)
        # Disambiguate same-second rollovers with a millisecond suffix
        if os.path.exists(rotated):
            ms = int(time.time() * 1000) % 1000
            rotated = self._rotated_path(f"{ts}_{ms:03d}")

        if os.path.exists(self.baseFilename):
            try:
                os.rename(self.baseFilename, rotated)
            except OSError:
                pass

        # Prune oldest backups beyond backupCount (keep newest by mtime)
        if self.backupCount > 0:
            backups = self._backup_files()
            backups.sort(key=lambda p: os.path.getmtime(p))
            for stale in backups[:-self.backupCount]:
                try:
                    os.remove(stale)
                except OSError:
                    pass

        if not self.delay:
            self.stream = self._open()


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
        self.handlers: dict[str, logging.Handler] = {}
        self._setup_level_handlers()

    def _setup_level_handlers(self) -> None:
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
            handler = TimestampRotatingFileHandler(
                file_path,
                maxBytes=self.max_bytes,
                backupCount=self.backup_count,
                encoding='utf-8'
            )
            handler.setFormatter(formatter)
            handler.setLevel(getattr(logging, level))
            self.handlers[level] = handler

    def emit(self, record: logging.LogRecord) -> None:
        """Emit log record to appropriate level-based file"""
        level_name = record.levelname
        if level_name in self.handlers:
            try:
                self.handlers[level_name].emit(record)
            except Exception:
                self.handleError(record)

    def close(self) -> None:
        """Close all handlers"""
        for handler in self.handlers.values():
            handler.close()
        super().close()


class LogCleanupManager:
    """Log file cleanup manager for automatic maintenance"""

    def __init__(self, log_dir: str, max_age_days: int = 30, cleanup_interval_hours: int = 24,
                 cleanup_at_startup: bool = False):
        """
        Initialize log cleanup manager.

        Args:
            log_dir: Directory containing log files
            max_age_days: Maximum age of log files in days (default: 30 days)
            cleanup_interval_hours: Cleanup interval in hours (default: 24 hours)
            cleanup_at_startup: If True, run a cleanup pass immediately when the
                scheduler starts. When False (default) the first cleanup waits one
                full interval, so logs left from a previous run are not purged on
                boot.
        """
        self.log_dir = Path(log_dir)
        self.max_age_days = max_age_days
        self.cleanup_interval_hours = cleanup_interval_hours
        self.cleanup_at_startup = cleanup_at_startup
        self.cleanup_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.logger: logging.Logger | None = None

    def start_cleanup_scheduler(self) -> None:
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

    def stop_cleanup_scheduler(self) -> None:
        """Stop the cleanup scheduler"""
        if self.cleanup_thread and self.cleanup_thread.is_alive():
            self.stop_event.set()
            self.cleanup_thread.join(timeout=5)
            if self.logger:
                self.logger.info("Log cleanup scheduler stopped")

    def _cleanup_loop(self) -> None:
        """Background loop for periodic cleanup.

        When ``cleanup_at_startup`` is False (the default), the loop waits one
        full interval before its first cleanup pass, so logs from a previous
        run are not purged the moment the server boots.
        """
        first_pass = True
        while not self.stop_event.is_set():
            try:
                # Skip the immediate cleanup on the very first pass unless
                # cleanup_at_startup was explicitly requested.
                if first_pass and not self.cleanup_at_startup:
                    first_pass = False
                else:
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

    def cleanup_old_logs(self) -> None:
        """Clean up old log files based on age"""
        if not self.log_dir.exists():
            return

        current_time = datetime.now()
        cutoff_time = current_time - timedelta(days=self.max_age_days)

        cleaned_files: list[str] = []
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

    def get_cleanup_stats(self) -> dict[str, Any]:
        """Get statistics about log files and cleanup status"""
        if not self.log_dir.exists():
            return {"error": "Log directory does not exist"}

        stats: dict[str, Any] = {
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
        oldest_time: datetime | None = None
        newest_time: datetime | None = None

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

                except OSError as exc:
                    if self.logger:
                        self.logger.debug(
                            f"Unable to inspect log file {log_file}: {exc}"
                        )
                    continue

        stats["total_size_mb"] = round(stats["total_size_mb"], 2)

        return stats


class DorisLoggerManager:
    """Centralized logger manager for Doris MCP Server"""

    def __init__(self) -> None:
        self.is_initialized = False
        self.log_dir: Path | None = None
        self.loggers: dict[str, logging.Logger] = {}
        self.cleanup_manager: LogCleanupManager | None = None

    def setup_logging(self,
                     level: str = "INFO",
                     log_dir: str = "logs",
                     base_name: str = "doris_mcp_server",
                     enable_console: bool = True,
                     enable_file: bool = True,
                     enable_audit: bool = True,
                     audit_file: str | None = None,
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
            base_name: Base name for log files (e.g. "doris_mcp_server_3000"
                when running multiple instances on different ports)
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
        log_dir_writable = True  # Initialize the variable

        # Try to create log directory, fallback to console-only if fails
        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            # If we can't create log directory (e.g., read-only filesystem in stdio mode),
            # fall back to console-only logging
            log_dir_writable = False
            enable_file = False
            enable_audit = False
            enable_cleanup = False
            # Don't use print() in stdio mode as it interferes with MCP JSON protocol
            # Log the warning through the logging system instead, which will be handled after setup

        # Clear existing handlers
        root_logger = logging.getLogger()
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        # Set root logger level
        root_logger.setLevel(logging.DEBUG)  # Allow all levels, handlers will filter

        handlers: list[logging.Handler] = []

        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(getattr(logging, level.upper()))
            console_handler.addFilter(_sensitive_data_filter)
            console_handler.addFilter(RequestAuthContextFilter())
            console_formatter = TimestampedFormatter(
                fmt="%(asctime)s.%(msecs)03d %(level_aligned)s [user=%(user)s token=%(token_id)s ip=%(client_ip)s] %(name)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            console_handler.setFormatter(console_formatter)
            handlers.append(console_handler)

        # Level-based file handlers
        if enable_file:
            level_handler = LevelBasedFileHandler(
                log_dir=str(self.log_dir),
                base_name=base_name,
                max_bytes=max_file_size,
                backup_count=backup_count
            )
            level_handler.setLevel(logging.DEBUG)  # Accept all levels
            level_handler.addFilter(_sensitive_data_filter)
            # Attach to the composite handler (not the per-level sub-handlers):
            # sub-handlers receive records via emit(), which bypasses their filters.
            level_handler.addFilter(RequestAuthContextFilter())
            handlers.append(level_handler)

        # Combined application log (all levels in one file)
        if enable_file:
            app_log_file = self.log_dir / f"{base_name}_all.log"
            app_handler = TimestampRotatingFileHandler(
                app_log_file,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            app_handler.setLevel(getattr(logging, level.upper()))
            app_handler.addFilter(_sensitive_data_filter)
            app_formatter = TimestampedFormatter()
            app_handler.setFormatter(app_formatter)
            handlers.append(app_handler)

        # Audit logger (separate from main logging)
        if enable_audit:
            audit_file_path = audit_file or str(self.log_dir / f"{base_name}_audit.log")
            audit_logger = logging.getLogger("audit")
            audit_logger.setLevel(logging.INFO)

            # Clear existing audit handlers
            for handler in audit_logger.handlers[:]:
                audit_logger.removeHandler(handler)

            audit_handler = TimestampRotatingFileHandler(
                audit_file_path,
                maxBytes=max_file_size,
                backupCount=backup_count,
                encoding='utf-8'
            )
            audit_handler.addFilter(_sensitive_data_filter)
            audit_handler.addFilter(RequestAuthContextFilter())
            audit_formatter = TimestampedFormatter(
                fmt="%(asctime)s.%(msecs)03d [AUDIT] [user=%(user)s token=%(token_id)s ip=%(client_ip)s] %(name)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            audit_handler.setFormatter(audit_formatter)
            audit_logger.addHandler(audit_handler)
            audit_logger.addFilter(_sensitive_data_filter)
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
        if log_dir_writable:
            logger.info(f"Log Directory: {self.log_dir.absolute()}")
        else:
            logger.info("Log Directory: Not available (console-only mode)")
        logger.info(f"Console Logging: {'Enabled' if enable_console else 'Disabled'}")
        logger.info(f"File Logging: {'Enabled' if enable_file else 'Disabled (fallback mode)'}")
        logger.info(f"Audit Logging: {'Enabled' if enable_audit else 'Disabled (fallback mode)'}")
        logger.info(f"Log Cleanup: {'Enabled' if enable_cleanup and enable_file else 'Disabled (fallback mode)'}")
        if enable_cleanup and enable_file:
            logger.info(f"Cleanup Settings: Max age {max_age_days} days, interval {cleanup_interval_hours}h")
        if not log_dir_writable:
            logger.warning("Running in console-only logging mode due to filesystem permissions")
            logger.warning(f"Could not create log directory '{log_dir}' - stdio mode fallback enabled")
        logger.info("=" * 80)

    def _setup_package_loggers(self, level: str) -> None:
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
            if _sensitive_data_filter not in logger.filters:
                logger.addFilter(_sensitive_data_filter)
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
            if _sensitive_data_filter not in logger.filters:
                logger.addFilter(_sensitive_data_filter)
            self.loggers[name] = logger

        return self.loggers[name]

    def get_audit_logger(self) -> logging.Logger:
        """Get the audit logger"""
        return logging.getLogger("audit")

    def log_system_info(self) -> None:
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

    def get_cleanup_stats(self) -> dict[str, Any]:
        """Get log cleanup statistics"""
        if self.cleanup_manager:
            return self.cleanup_manager.get_cleanup_stats()
        else:
            return {"error": "Log cleanup is not enabled"}

    def manual_cleanup(self) -> dict[str, Any]:
        """Manually trigger log cleanup and return statistics"""
        if self.cleanup_manager:
            self.cleanup_manager.cleanup_old_logs()
            return self.cleanup_manager.get_cleanup_stats()
        else:
            return {"error": "Log cleanup is not enabled"}

    def shutdown(self) -> None:
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
                 base_name: str = "doris_mcp_server",
                 enable_console: bool = True,
                 enable_file: bool = True,
                 enable_audit: bool = True,
                 audit_file: str | None = None,
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
        base_name: Base name for log files (e.g. "doris_mcp_server_3000")
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
        base_name=base_name,
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


def log_system_info() -> None:
    """Log system information for debugging"""
    _logger_manager.log_system_info()


def get_cleanup_stats() -> dict[str, Any]:
    """Get log cleanup statistics"""
    return _logger_manager.get_cleanup_stats()


def manual_cleanup() -> dict[str, Any]:
    """Manually trigger log cleanup and return statistics"""
    return _logger_manager.manual_cleanup()


def shutdown_logging() -> None:
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

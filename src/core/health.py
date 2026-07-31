"""Service health state tracking.

Central registry for component health status. Updated by watcher on hot-reload
success/failure. Queryable via check_service_health Tool and /health endpoint.
"""

from __future__ import annotations

import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ComponentStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"  # Partially working (e.g. engine fallback to CLI mode)
    ERROR = "error"        # Component failed
    UNKNOWN = "unknown"


@dataclass
class ComponentHealth:
    status: ComponentStatus = ComponentStatus.UNKNOWN
    message: str = ""
    last_updated: float = 0.0
    last_error: str = ""
    last_error_time: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)

    def set_healthy(self, message: str = "", **details: Any) -> None:
        self.status = ComponentStatus.HEALTHY
        self.message = message
        self.last_updated = time.time()
        self.details = details

    def set_degraded(self, message: str, **details: Any) -> None:
        self.status = ComponentStatus.DEGRADED
        self.message = message
        self.last_updated = time.time()
        self.details = details

    def set_error(self, message: str, **details: Any) -> None:
        self.status = ComponentStatus.ERROR
        self.message = message
        self.last_error = message
        self.last_error_time = time.time()
        self.last_updated = time.time()
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "status": self.status.value,
            "message": self.message,
        }
        if self.last_updated:
            d["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.last_updated))
        if self.last_error:
            d["last_error"] = self.last_error
            d["last_error_time"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.last_error_time))
        if self.details:
            d.update(self.details)
        return d


class ServiceHealth:
    """Thread-safe service health registry."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._components: dict[str, ComponentHealth] = {
            "doris_connection": ComponentHealth(),
            "config_watcher": ComponentHealth(),
            "auth": ComponentHealth(),
        }

    def reset(self) -> None:
        """Reset to initial state (base components only)."""
        with self._lock:
            self._components = {
                "doris_connection": ComponentHealth(),
                "config_watcher": ComponentHealth(),
                "auth": ComponentHealth(),
            }

    def get(self, component: str) -> ComponentHealth:
        with self._lock:
            if component not in self._components:
                self._components[component] = ComponentHealth()
            return self._components[component]

    def overall_status(self) -> ComponentStatus:
        """Return worst status across all components."""
        with self._lock:
            statuses = [c.status for c in self._components.values()]
        if ComponentStatus.ERROR in statuses:
            return ComponentStatus.ERROR
        if ComponentStatus.DEGRADED in statuses:
            return ComponentStatus.DEGRADED
        if ComponentStatus.UNKNOWN in statuses:
            return ComponentStatus.DEGRADED
        return ComponentStatus.HEALTHY

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "status": self.overall_status().value,
                "components": {k: v.to_dict() for k, v in self._components.items()},
            }


# Global singleton
service_health = ServiceHealth()

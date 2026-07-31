"""Semantic layer version tracking.

Maintains a snapshot of the currently loaded semantic layer state.
Only ``loaded_at`` is exposed externally (health/tool responses).
All other fields are for internal logging and decision-making.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class SemanticLayerVersion:
    """Immutable snapshot of a loaded semantic layer version."""

    loaded_at: str
    """ISO8601 timestamp of when this version was loaded — the sole external identifier."""

    revision: str
    """Store-returned opaque revision (for equality comparison)."""

    source_type: str
    """Store backend type: "local", "s3", "git"."""

    source_uri: str
    """Human-readable source location (for logs)."""

    loaded_epoch: float = field(default_factory=time.time)
    """Epoch timestamp for cooldown comparison (not serialized)."""

    version_label: str | None = None
    """Store-provided human-readable label (e.g. .version content, git tag)."""

    metric_count: int = 0
    """Number of metrics in this version."""

    last_reload_success: bool = True
    """Whether the last reload attempt succeeded."""

    @staticmethod
    def now_iso() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class VersionTracker:
    """Thread-safe container for the current SemanticLayerVersion."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._version: SemanticLayerVersion | None = None

    @property
    def current(self) -> SemanticLayerVersion | None:
        with self._lock:
            return self._version

    def update(self, version: SemanticLayerVersion) -> None:
        with self._lock:
            self._version = version

    def touch_epoch(self) -> None:
        """Bump loaded_epoch to now without changing the version identity.

        Used when a freshness check finds revision unchanged — records
        that we verified the version is still current, resetting the
        cooldown timer without a full reload.
        """
        with self._lock:
            if self._version:
                self._version.loaded_epoch = time.time()

    def mark_failure(self) -> None:
        """Mark the last reload as failed (keeps existing version otherwise)."""
        with self._lock:
            if self._version:
                self._version = SemanticLayerVersion(
                    loaded_at=self._version.loaded_at,
                    loaded_epoch=self._version.loaded_epoch,
                    revision=self._version.revision,
                    source_type=self._version.source_type,
                    source_uri=self._version.source_uri,
                    version_label=self._version.version_label,
                    metric_count=self._version.metric_count,
                    last_reload_success=False,
                )

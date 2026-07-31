"""Compiled semantic artifact persistence.

Artifacts live inside the workspace directory (``.artifacts/``), one JSON
file per artifact, next to the model sources they were compiled from. The
envelope records provenance (source filename, provider, creation time) so
the metadata API can list artifacts without loading payloads.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from providers.base import CompiledArtifact, ProviderError

_ARTIFACT_DIR = ".artifacts"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def make_artifact_id(provider: str, name: str) -> str:
    raw = f"{provider}__{name}"
    # Normalize to a filesystem- and API-safe id.
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw).strip("_")
    return safe or f"{provider}__artifact"


class ArtifactStore:
    """File-backed artifact store scoped to one workspace directory."""

    def __init__(self, workspace_dir: str | Path) -> None:
        self._dir = Path(workspace_dir) / _ARTIFACT_DIR

    # -- paths ---------------------------------------------------------------

    def _path(self, artifact_id: str) -> Path:
        if not _ID_RE.match(artifact_id):
            raise ProviderError(f"Invalid artifact id: {artifact_id!r}")
        return self._dir / f"{artifact_id}.json"

    # -- CRUD -----------------------------------------------------------------

    def save(
        self,
        artifact: CompiledArtifact,
        source_filename: str = "",
        artifact_id: str | None = None,
    ) -> str:
        """Persist an artifact, returning its id (overwrites same-id entries)."""
        artifact_id = artifact_id or make_artifact_id(artifact.provider, artifact.name)
        path = self._path(artifact_id)
        self._dir.mkdir(parents=True, exist_ok=True)
        envelope = {
            "meta": {
                "artifact_id": artifact_id,
                "provider": artifact.provider,
                "name": artifact.name,
                "source_filename": source_filename,
                "source_digest": artifact.source_digest,
                "created_at": int(time.time()),
            },
            "artifact": json.loads(artifact.to_json()),
        }
        path.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")
        return artifact_id

    def load(self, artifact_id: str) -> CompiledArtifact:
        path = self._path(artifact_id)
        if not path.exists():
            raise ProviderError(f"Artifact not found: '{artifact_id}'")
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ProviderError(f"Corrupt artifact '{artifact_id}': {e}") from e
        return CompiledArtifact.from_json(json.dumps(envelope["artifact"]))

    def get_meta(self, artifact_id: str) -> dict[str, Any]:
        path = self._path(artifact_id)
        if not path.exists():
            raise ProviderError(f"Artifact not found: '{artifact_id}'")
        envelope = json.loads(path.read_text(encoding="utf-8"))
        return dict(envelope.get("meta") or {})

    def list(self) -> list[dict[str, Any]]:
        """List artifact metadata (id, provider, name, digest, created_at)."""
        if not self._dir.exists():
            return []
        out: list[dict[str, Any]] = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                envelope = json.loads(path.read_text(encoding="utf-8"))
                meta = envelope.get("meta")
                if isinstance(meta, dict):
                    out.append(meta)
            except (json.JSONDecodeError, OSError):
                continue  # skip corrupt entries instead of failing the listing
        return out

    def delete(self, artifact_id: str) -> bool:
        path = self._path(artifact_id)
        if path.exists():
            path.unlink()
            return True
        return False

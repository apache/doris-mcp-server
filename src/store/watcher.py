"""Multi-workspace semantic reload manager.

Each workspace:
  - Own store (active_store_{name})
  - Own manifest + compiler (MetricFlowEngine)
  - On-demand freshness via ensure_fresh() (no background polling)
  - Independent toggle (semantic_enabled per workspace)

Global router: metric_name → (engine, workspace_name)
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from store.store import DorisStore
from store.version import SemanticLayerVersion, VersionTracker

logger = logging.getLogger("doris_new_mcp.watcher")


def _check_staging_duplicates(models_dir: Path) -> tuple[list[str], list[str]]:
    """Check staging YAML files for duplicate names across semantic_models.

    Detects two kinds of duplicates:
    1. Duplicate measure names across models (MetricFlow silently drops one).
    2. Duplicate semantic_model names across files (bootstrap rejects).

    Returns (errors, warnings) where:
    - errors: hard blockers that must be fixed before commit
    - warnings: informational, non-blocking
    """
    import yaml

    # Collect: measure_name → [(model_name, filename)]
    measure_sources: dict[str, list[tuple[str, str]]] = {}
    # Collect: model_name → [filename]
    model_sources: dict[str, list[str]] = {}

    for yaml_file in sorted(models_dir.rglob("*.yml")) + sorted(models_dir.rglob("*.yaml")):
        try:
            text = yaml_file.read_text(encoding="utf-8")
            docs = list(yaml.safe_load_all(text))
        except Exception:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            sm = doc.get("semantic_model")
            if not isinstance(sm, dict):
                continue
            model_name = sm.get("name", yaml_file.stem)
            model_sources.setdefault(model_name, []).append(yaml_file.name)

            measures = sm.get("measures", [])
            if not isinstance(measures, list):
                continue
            for m in measures:
                if not isinstance(m, dict):
                    continue
                mname = m.get("name", "")
                if mname:
                    measure_sources.setdefault(mname, []).append((model_name, yaml_file.name))

    errors: list[str] = []
    warnings: list[str] = []

    # P1-2: Duplicate model names
    for mname, files in model_sources.items():
        if len(files) > 1:
            errors.append(
                f"Duplicate semantic_model name '{mname}' in files: "
                + ", ".join(files)
                + ". Each semantic_model must have a unique name."
            )

    # P1-1: Duplicate measure names
    for mname, sources in measure_sources.items():
        if len(sources) > 1:
            files = [f"{model} ({fname})" for model, fname in sources]
            errors.append(
                f"Duplicate measure '{mname}' defined in {len(sources)} models: "
                + ", ".join(files)
                + ". Only one will survive in MetricFlow (the last one wins). "
                + "Rename one of them to avoid silent data loss."
            )

    return errors, warnings


class RWLock:
    """Read-write lock. Multiple concurrent readers OR one exclusive writer.

    Currently used only for write-side guarding of per-workspace manifest/compiler
    atomic swaps. Read-side is not locked — Python GIL makes single-attribute
    assignment atomic, and the swap window is microseconds.
    """

    def __init__(self) -> None:
        self._readers = 0
        self._readers_lock = threading.Lock()
        self._writer_lock = threading.Lock()

    def read_acquire(self) -> None:
        with self._readers_lock:
            self._readers += 1
            if self._readers == 1:
                self._writer_lock.acquire()

    def read_release(self) -> None:
        with self._readers_lock:
            self._readers -= 1
            if self._readers == 0:
                self._writer_lock.release()

    def write_acquire(self) -> None:
        self._writer_lock.acquire()

    def write_release(self) -> None:
        self._writer_lock.release()


# ---------------------------------------------------------------------------
# WorkspaceState
# ---------------------------------------------------------------------------

@dataclass
class WorkspaceState:
    """Runtime state for one workspace."""
    name: str
    store: DorisStore
    config_dir: Path
    workspace_dir: Path
    models_dir: Path

    # Semantic state
    enabled: bool = True
    manifest: Any | None = None
    compiler: Any | None = None
    
    # Polling
    known_revision: str = ""
    parsing: bool = False

    # Version tracking
    version_tracker: VersionTracker = field(default_factory=VersionTracker)
    rwlock: RWLock = field(default_factory=RWLock)


# ---------------------------------------------------------------------------
# MetricRouter
# ---------------------------------------------------------------------------

class MetricRouter:
    """metric_name → (engine, workspace_name)"""

    def __init__(self) -> None:
        self._map: dict[str, tuple[Any, str]] = {}

    def rebuild(self, workspaces: dict[str, WorkspaceState]) -> None:
        self._map.clear()
        for ws_name, ws in workspaces.items():
            if not ws.manifest or not ws.enabled:
                continue
            for m in ws.manifest.list_metrics():
                name = m["name"]
                if name in self._map:
                    logger.warning(
                        f"Metric '{name}' exists in multiple workspaces "
                        f"({self._map[name][1]} and {ws_name}), using first"
                    )
                    continue
                self._map[name] = (ws.compiler, ws_name)


# ---------------------------------------------------------------------------
# MultiWorkspaceWatcher
# ---------------------------------------------------------------------------

class MultiWorkspaceWatcher:
    """Manages N workspaces, each with independent store/polling/engine.

    Workspaces are discovered and loaded ON DEMAND — no background
    polling.  Every store operation runs in request context so the
    credential contextvar is available.
    """

    def __init__(
        self,
        config_dir: Path,
        workspace_root: Path,
        app_config: Any,
    ):
        self._config_dir = Path(config_dir)
        self._workspace_root = Path(workspace_root)
        self._app_config = app_config

        self._workspaces: dict[str, WorkspaceState] = {}
        self._router = MetricRouter()

        # P2-1: Track which workspaces have had staging validated since last change
        self._staging_validated: set[str] = set()

        # Lazy-init guards
        self._initialized: bool = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def router(self) -> MetricRouter:
        return self._router

    @property
    def workspaces(self) -> dict[str, WorkspaceState]:
        return self._workspaces

    def get_workspace(self, name: str) -> WorkspaceState | None:
        return self._workspaces.get(name)

    def workspace_names(self) -> list[str]:
        return sorted(self._workspaces.keys())

    def has_workspace(self, name: str) -> bool:
        return name in self._workspaces

    # ------------------------------------------------------------------
    # Lazy init — called once on first authenticated request
    # ------------------------------------------------------------------

    def initialize(self) -> None:
        """Discover and bootstrap all workspaces from Doris.

        Must be called within request context (credentials must be set
        via set_request_credentials before calling this).
        """
        if self._initialized:
            return
        existing = DorisStore.discover_workspaces()
        if not existing:
            logger.warning("No workspace tables found in system_mcp (active_store_*)")
        for ws_name in existing:
            self._init_workspace(ws_name, first_load=True)
        self._initialized = True
        logger.info(f"Watcher initialized: {len(self._workspaces)} workspace(s)")

    def _init_workspace(self, ws_name: str, first_load: bool = False) -> WorkspaceState:
        # Invalidate any negative-cache verdict (e.g. workspace just created
        # via api_workspace_create after earlier "not found" lookups).
        self.__dict__.setdefault("_missing_workspaces", {}).pop(ws_name, None)

        store = DorisStore(workspace=ws_name)
        ws_dir = self._workspace_root / ws_name
        models_dir = ws_dir / "models_cache"
        ws_dir.mkdir(parents=True, exist_ok=True)

        ws = WorkspaceState(
            name=ws_name,
            store=store,
            config_dir=self._config_dir,
            workspace_dir=ws_dir,
            models_dir=models_dir,
            enabled=True,
        )

        self._workspaces[ws_name] = ws

        if first_load:
            self._reload_workspace(ws)
        else:
            try:
                ws.known_revision = store.check_remote().revision
            except Exception:
                ws.known_revision = ""

        self._router.rebuild(self._workspaces)
        logger.info(f"Workspace '{ws_name}' initialized (first_load={first_load})")
        return ws

    # ------------------------------------------------------------------
    # On-demand freshness (called within request context)
    # ------------------------------------------------------------------

    _FRESHNESS_TTL = 60.0  # seconds between reload checks
    _MISSING_WS_TTL = 30.0  # seconds to remember a "workspace not found" verdict

    def ensure_fresh(self, workspace_name: str) -> WorkspaceState | None:
        """Ensure the workspace manifest/compiler is up-to-date.

        Called from tool handlers within request context.  If the
        workspace hasn't been loaded yet, discovers it.  Cooldown
        prevents redundant reloads within _FRESHNESS_TTL seconds.
        A "workspace not found" verdict is negative-cached for
        _MISSING_WS_TTL seconds so repeated calls with a bad workspace
        name don't each cost a Doris round-trip.

        Returns WorkspaceState on success, None if workspace not found
        or store unavailable.
        """
        # Lazy discover
        if workspace_name not in self._workspaces:
            # Negative cache: name → epoch of the last "not found" verdict.
            # Runs under asyncio.to_thread (multi-threaded); single dict
            # operations are atomic under the GIL, and a rare duplicate
            # discover on a race is harmless, so no lock is needed.
            # setdefault also covers watchers built without __init__ (tests).
            missing: dict[str, float] = self.__dict__.setdefault("_missing_workspaces", {})
            now = time.time()
            cached_at = missing.get(workspace_name)
            if cached_at is not None and now - cached_at < self._MISSING_WS_TTL:
                return None
            try:
                existing = set(DorisStore.discover_workspaces())
            except Exception:
                logger.warning(f"ensure_fresh [{workspace_name}]: discover failed")
                return None
            if workspace_name in existing:
                missing.pop(workspace_name, None)
                self._init_workspace(workspace_name, first_load=True)
            else:
                # Drop expired entries so the cache stays bounded to the
                # distinct bad names seen within one TTL window.
                for name, ts in list(missing.items()):
                    if now - ts >= self._MISSING_WS_TTL:
                        del missing[name]
                missing[workspace_name] = now
                logger.warning(f"ensure_fresh [{workspace_name}]: workspace not found")
                return None

        ws = self._workspaces.get(workspace_name)
        if ws is None:
            return None

        if ws.parsing:
            return ws

        # Cooldown — skip reload if fresh enough
        current = ws.version_tracker.current
        if current is not None and time.time() - current.loaded_epoch < self._FRESHNESS_TTL:
            return ws

        # Check if revision changed.  A failure here means we cannot tell
        # whether the loaded manifest is current; serving it anyway would
        # hand back silently-outdated metric definitions, so refuse instead.
        try:
            new_rev = ws.store.check_remote().revision
        except Exception:
            logger.exception(
                f"ensure_fresh [{workspace_name}]: revision check failed, "
                f"refusing to serve a possibly stale manifest"
            )
            return None

        if current is not None and new_rev == ws.known_revision:
            ws.version_tracker.touch_epoch()
            return ws

        self._reload_workspace(ws)
        return ws

    # ------------------------------------------------------------------
    # Reload
    # ------------------------------------------------------------------

    def _reload_workspace(self, ws: WorkspaceState) -> None:
        if ws.parsing:
            logger.info(f"[{ws.name}] Reload skipped: already in progress")
            return

        ws.parsing = True
        t0 = time.monotonic()
        logger.info(f"[{ws.name}] Reloading...")

        try:
            from store.bootstrap import bootstrap
            from store.manifest import SemanticManifest
            from store.compiler import MetricFlowCompiler

            # Sync from Doris to local cache
            ws.store.fetch(ws.models_dir)

            # Bootstrap
            ok, err = bootstrap(self._config_dir, ws.workspace_dir, models_dir=ws.models_dir)
            if not ok:
                logger.error(f"[{ws.name}] Bootstrap failed: {err}. Keeping old version.")
                ws.version_tracker.mark_failure()
                ws.known_revision = ws.store.check_remote().revision
                return

            # Build new manifest + compiler
            manifest_path = ws.workspace_dir / "target" / "semantic_manifest.json"
            new_manifest = SemanticManifest(manifest_path)
            new_compiler = MetricFlowCompiler(ws.workspace_dir)
            metric_count = len(new_manifest.list_metrics())

            # Atomic swap
            ws.rwlock.write_acquire()
            try:
                if ws.manifest and ws.compiler:
                    ws.manifest.replace_with(new_manifest)
                    ws.compiler.replace_with(new_compiler)
                else:
                    ws.manifest = new_manifest
                    ws.compiler = new_compiler
            finally:
                ws.rwlock.write_release()

            ws.known_revision = ws.store.check_remote().revision
            duration = (time.monotonic() - t0) * 1000
            now_epoch = time.time()

            # Update version tracker (with epoch for cooldown)
            version = SemanticLayerVersion(
                loaded_at=SemanticLayerVersion.now_iso(),
                loaded_epoch=now_epoch,
                revision=ws.known_revision,
                source_type=ws.store.store_type,
                source_uri=ws.store.source_uri,
                metric_count=metric_count,
                last_reload_success=True,
            )
            ws.version_tracker.update(version)

            # Rebuild global router
            self._router.rebuild(self._workspaces)

            logger.info(
                f"[{ws.name}] Reload done: {metric_count} metrics in {duration:.0f}ms"
            )

        except Exception as e:
            logger.exception(f"[{ws.name}] Reload failed: {e}")
            ws.version_tracker.mark_failure()
        finally:
            ws.parsing = False

    # ------------------------------------------------------------------
    # Manual reload
    # ------------------------------------------------------------------

    def force_reload(self, workspace: str) -> tuple[str, str]:
        ws = self._workspaces.get(workspace)
        if not ws:
            return "rejected", f"Workspace not found: {workspace}"
        if ws.parsing:
            return "already_running", "Reload already in progress"

        ws.known_revision = ""
        self._reload_workspace(ws)
        # _reload_workspace handles its own exceptions internally;
        # check the version tracker to determine success.
        ver = ws.version_tracker.current
        if ver is None or not ver.last_reload_success:
            return "failed", "Reload failed — check server logs for details"
        return "done", f"Reload completed ({ver.revision[:12]})"

    # ------------------------------------------------------------------
    # Staging
    # ------------------------------------------------------------------

    def validate_staging(self, workspace: str) -> tuple[bool, str, dict | None]:
        import shutil, tempfile
        ws = self._workspaces.get(workspace)
        if not ws:
            return False, f"Workspace not found: {workspace}", None

        stg_files = ws.store.staging_list()
        if not stg_files:
            return False, "No staging changes to validate", None

        # P2-1: Clear validation tracking at start (re-validated on success)
        self._staging_validated.discard(workspace)

        pending_deletes = [
            item["filename"] for item in stg_files if item.get("action") == "delete"
        ]
        if pending_deletes:
            from tools.dependency import check_delete_dependencies

            active_files = {
                entry["filename"]: file_info["content"]
                for entry in ws.store.list_files()
                if (file_info := ws.store.get_file(entry["filename"])) and file_info.get("content")
            }
            dependency_errors = [
                error
                for filename in pending_deletes
                if (deleted_content := active_files.get(filename))
                for error in check_delete_dependencies(filename, deleted_content, active_files)
            ]

            if dependency_errors:
                return False, f"Validation failed: {dependency_errors[0]}", {
                    "phase": "dependencies",
                    "staging_files": stg_files,
                    "errors": dependency_errors,
                }

        try:
            tmp_models = Path(tempfile.mkdtemp(prefix=f"stg_{workspace}_"))
            ws.store.staging_fetch(tmp_models)

            yml_count = len(list(tmp_models.rglob("*.yml"))) + len(list(tmp_models.rglob("*.yaml")))
            if yml_count == 0:
                shutil.rmtree(str(tmp_models), ignore_errors=True)
                return False, "No valid YAML files in staging", None

            from store.bootstrap import bootstrap, pre_validate_physical
            ok, err = pre_validate_physical(tmp_models)
            if not ok:
                shutil.rmtree(str(tmp_models), ignore_errors=True)
                return False, f"Physical validation failed: {err}", {"phase": "physical"}

            tmp_ws = Path(tempfile.mkdtemp(prefix=f"stg_ws_{workspace}_"))
            ok, err = bootstrap(self._config_dir, tmp_ws, models_dir=tmp_models)
            if not ok:
                shutil.rmtree(str(tmp_models), ignore_errors=True)
                shutil.rmtree(str(tmp_ws), ignore_errors=True)
                return False, f"Semantic validation failed: {err}", {"phase": "semantic"}

            from store.manifest import SemanticManifest
            manifest_path = tmp_ws / "target" / "semantic_manifest.json"
            manifest = SemanticManifest(manifest_path)
            metrics = manifest.list_metrics()

            # P1-1+P1-2: Check for duplicate names across models before reporting success
            dup_errors, dup_warnings = _check_staging_duplicates(tmp_models)

            shutil.rmtree(str(tmp_models), ignore_errors=True)
            shutil.rmtree(str(tmp_ws), ignore_errors=True)

            if dup_errors:
                self._staging_validated.discard(workspace)
                return False, f"Validation failed: {dup_errors[0]}", {
                    "phase": "semantic",
                    "metric_count": len(metrics),
                    "metrics": [m["name"] for m in metrics],
                    "staging_files": stg_files,
                    "errors": dup_errors,
                }

            if dup_warnings:
                self._staging_validated.add(workspace)
                return True, f"Validation passed: {len(metrics)} metrics. WARNING: {dup_warnings}", {
                    "phase": "complete",
                    "metric_count": len(metrics),
                    "metrics": [m["name"] for m in metrics],
                    "staging_files": stg_files,
                    "warnings": dup_warnings,
                }

            self._staging_validated.add(workspace)
            return True, f"Validation passed: {len(metrics)} metrics", {
                "phase": "complete",
                "metric_count": len(metrics),
                "metrics": [m["name"] for m in metrics],
                "staging_files": stg_files,
            }
        except Exception as e:
            logger.exception(f"[{workspace}] Staging validation failed")
            return False, str(e), None

    def commit_staging(self, workspace: str) -> tuple[bool, str]:
        ws = self._workspaces.get(workspace)
        if not ws:
            return False, f"Workspace not found: {workspace}"

        # P2-1: Enforce validate-before-commit
        if workspace not in self._staging_validated:
            return False, "Staging must be validated before commit. Run 'Validate' first."

        try:
            state = ws.store.staging_commit()
        except Exception as e:
            return False, f"Commit failed: {e}"

        # Clear validation tracking after successful commit
        self._staging_validated.discard(workspace)

        status, _ = self.force_reload(workspace)
        remaining = ws.store.staging_list()
        if remaining:
            logger.warning(f"[{workspace}] {len(remaining)} staging items remain after commit")
            return True, f"Committed (revision: {state.revision[:12]}), reload triggered. {len(remaining)} items remain — retry after reload."

        return True, f"Committed and reload triggered (revision: {state.revision[:12]})"

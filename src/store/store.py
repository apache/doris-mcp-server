"""Semantic configuration store backed by Doris.

Multi-workspace: each workspace has its own pair of Doris tables:

  system_mcp.active_store_{workspace}   — active (production) models
  system_mcp.staging_store_{workspace}  — pending changes

Tables
------
active_store_{workspace}
    filename    VARCHAR(512)   PRIMARY KEY
    updated_at  DATETIME       NOT NULL
    content     STRING         NOT NULL

staging_store_{workspace}
    filename    VARCHAR(512)   PRIMARY KEY
    action      VARCHAR(16)    NOT NULL   -- 'upsert' or 'delete'
    updated_at  DATETIME       NOT NULL
    content     STRING         -- NULL for delete actions
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pymysql

logger = logging.getLogger("doris_new_mcp.store")

# ---------------------------------------------------------------------------
# StoreState
# ---------------------------------------------------------------------------


@dataclass
class StoreState:
    revision: str
    version_label: str | None = None
    updated_at: str | None = None


# ---------------------------------------------------------------------------
# DorisStore
# ---------------------------------------------------------------------------

_DORIS_HOST = "127.0.0.1"
_DORIS_PORT = 9030
_DORIS_DB = "system_mcp"

# Request-scoped credential override. Set once at the start of each
# authenticated request, read by _get_conn(). Destroyed when the
# asyncio Task ends — no cross-request leakage.
_request_creds: contextvars.ContextVar[tuple[str, str] | None] = \
    contextvars.ContextVar('_doris_store_creds', default=None)


def set_request_credentials(user: str, password: str) -> None:
    """Inject Doris credentials for the current request.

    Called once at request entry (CredentialVerifier or HTTP auth).
    The credentials live only for the duration of this asyncio Task.
    """
    _request_creds.set((user, password))


def set_doris_port(port: int) -> None:
    """Update the Doris admin port (called at startup from config)."""
    global _DORIS_PORT
    _DORIS_PORT = port


def _get_conn() -> pymysql.Connection:
    creds = _request_creds.get()
    if creds is None:
        raise RuntimeError(
            "No Doris credentials in request context. "
            "Ensure the request carries a valid Bearer token or session cookie."
        )
    user, password = creds
    return pymysql.connect(
        host=_DORIS_HOST, port=_DORIS_PORT,
        user=user, password=password,
        charset="utf8mb4", autocommit=True,
        connect_timeout=5,
    )


class DorisStore:
    """Semantic model storage for a single workspace.

    Each workspace has its own pair of tables:
      active_store_{workspace}
      staging_store_{workspace}
    """

    def __init__(self, workspace: str = "example") -> None:
        self._workspace = workspace
        self._active_table = f"active_store_{workspace}"
        self._staging_table = f"staging_store_{workspace}"
        self._ensure_tables()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def workspace(self) -> str:
        return self._workspace

    @property
    def store_type(self) -> str:
        return "doris"

    @property
    def source_uri(self) -> str:
        return f"doris://{_DORIS_HOST}:{_DORIS_PORT}/{_DORIS_DB}/{self._active_table}"

    @property
    def active_table(self) -> str:
        return self._active_table

    @property
    def staging_table(self) -> str:
        return self._staging_table

    # ------------------------------------------------------------------
    # Workspace discovery (class-level)
    # ------------------------------------------------------------------

    @classmethod
    def discover_workspaces(cls) -> list[str]:
        """Scan system_mcp for all active_store_* tables, return workspace names."""
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS {_DORIS_DB}")
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute("SHOW TABLES LIKE 'active_store_%'")
                tables = [r[0] for r in cur.fetchall()]
        finally:
            conn.close()
        return [t[len("active_store_"):] for t in tables]

    @classmethod
    def drop_workspace_tables(cls, workspace: str) -> None:
        """Drop ONLY the semantic model tables for a workspace.

        Drops: active_store_{workspace}, staging_store_{workspace}
        Does NOT touch any data tables (e.g., dw.orders, dw.users).

        Safe to call when tables don't exist (uses IF EXISTS).
        """
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"DROP TABLE IF EXISTS active_store_{workspace}")
                cur.execute(f"DROP TABLE IF EXISTS staging_store_{workspace}")
            logger.info(f"Dropped semantic tables for workspace '{workspace}'")
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # check_remote
    # ------------------------------------------------------------------

    def check_remote(self) -> StoreState:
        self._ensure_tables()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                try:
                    cur.execute(f"SHOW TABLETS FROM {self._active_table}")
                    rows = cur.fetchall()
                    if rows and cur.description:
                        cols = [d[0] for d in cur.description]
                        if "Version" in cols:
                            vi = cols.index("Version")
                            max_ver = max(int(r[vi]) for r in rows)
                            return StoreState(revision=str(max_ver))
                except Exception:
                    pass
                return StoreState(revision="")
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # fetch
    # ------------------------------------------------------------------

    def fetch(self, local_dir: Path) -> StoreState:
        self._ensure_tables()
        local_dir.mkdir(parents=True, exist_ok=True)

        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"SELECT filename, updated_at, content FROM {self._active_table}")
                rows = cur.fetchall()
        finally:
            conn.close()

        if not rows:
            return StoreState(revision="", updated_at=None)

        db_filenames: set[str] = set()
        latest_updated: datetime | None = None

        for filename, updated_at, content in rows:
            db_filenames.add(filename)
            filepath = local_dir / filename
            filepath.parent.mkdir(parents=True, exist_ok=True)
            filepath.write_text(content, encoding="utf-8")
            if isinstance(updated_at, datetime):
                if latest_updated is None or updated_at > latest_updated:
                    latest_updated = updated_at

        for root, _, filenames in os.walk(local_dir):
            for fn in filenames:
                if not fn.endswith((".yml", ".yaml")):
                    continue
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, local_dir)
                if rel not in db_filenames:
                    os.remove(full)

        revision = hashlib.sha256(
            json.dumps(sorted(db_filenames), ensure_ascii=False).encode()
        ).hexdigest()
        updated_at = latest_updated.strftime("%Y-%m-%dT%H:%M:%SZ") if latest_updated else None
        logger.info(f"fetch [{self._workspace}]: {len(rows)} files → {local_dir}")
        return StoreState(revision=revision, updated_at=updated_at)

    # ------------------------------------------------------------------
    # Active file helpers
    # ------------------------------------------------------------------

    def list_files(self) -> list[dict]:
        self._ensure_tables()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(
                    f"SELECT filename, updated_at, LENGTH(content) AS size_bytes "
                    f"FROM {self._active_table} ORDER BY filename"
                )
                rows = cur.fetchall()
        except Exception as e:
            logger.warning(f"list_files [{self._workspace}]: {e}")
            return []
        finally:
            conn.close()
        return [
            {"filename": r[0], "updated_at": r[1].strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(r[1], datetime) else str(r[1]), "size_bytes": r[2]}
            for r in rows
        ]

    def get_file(self, filename: str) -> dict | None:
        self._ensure_tables()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"SELECT filename, updated_at, content FROM {self._active_table} WHERE filename = %s", (filename,))
                row = cur.fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return {
            "filename": row[0],
            "updated_at": row[1].strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(row[1], datetime) else str(row[1]),
            "content": row[2],
        }

    # ------------------------------------------------------------------
    # Staging helpers
    # ------------------------------------------------------------------

    def staging_list(self) -> list[dict]:
        self._ensure_tables()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(
                    f"SELECT filename, action, updated_at, LENGTH(content) AS size_bytes "
                    f"FROM {self._staging_table} ORDER BY filename"
                )
                rows = cur.fetchall()
        except Exception as e:
            logger.warning(f"staging_list [{self._workspace}]: {e}")
            return []
        finally:
            conn.close()
        return [
            {"filename": r[0], "action": r[1], "updated_at": r[2].strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(r[2], datetime) else str(r[2]), "size_bytes": r[3] if r[3] else 0}
            for r in rows
        ]

    def staging_upsert(self, filename: str, content: str) -> None:
        self._ensure_tables()
        now = datetime.now()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"SELECT 1 FROM {self._staging_table} WHERE filename = %s", (filename,))
                if cur.fetchone():
                    cur.execute(
                        f"UPDATE {self._staging_table} SET action='upsert', updated_at=%s, content=%s WHERE filename=%s",
                        (now, content, filename),
                    )
                else:
                    cur.execute(
                        f"INSERT INTO {self._staging_table} (filename, action, updated_at, content) VALUES (%s, 'upsert', %s, %s)",
                        (filename, now, content),
                    )
        finally:
            conn.close()
        logger.info(f"staging upsert [{self._workspace}]: {filename}")

    def staging_delete(self, filename: str) -> str:
        """Mark file for deletion in staging. Smart undo-aware:
        - If file is already in staging → remove it (undo pending change)
        - If file is in active_store → add 'delete' record to staging
        Returns 'removed', 'staged', or 'not_found'.
        """
        self._ensure_tables()
        conn = _get_conn()
        now = datetime.now()
        result = "not_found"
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                # Check staging first
                cur.execute(f"SELECT 1 FROM {self._staging_table} WHERE filename = %s", (filename,))
                if cur.fetchone():
                    cur.execute(f"DELETE FROM {self._staging_table} WHERE filename = %s", (filename,))
                    result = "removed"
                    logger.info(f"staging delete [{self._workspace}]: removed {filename} from staging (undo)")
                else:
                    # Check active store
                    cur.execute(f"SELECT 1 FROM {self._active_table} WHERE filename = %s", (filename,))
                    if cur.fetchone():
                        cur.execute(
                            f"INSERT INTO {self._staging_table} (filename, action, updated_at, content) VALUES (%s, 'delete', %s, NULL)",
                            (filename, now),
                        )
                        result = "staged"
                        logger.info(f"staging delete [{self._workspace}]: queued delete for {filename}")
        finally:
            conn.close()
        return result

    def staging_discard(self) -> None:
        self._ensure_tables()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"DELETE FROM {self._staging_table}")
        finally:
            conn.close()
        logger.info(f"staging discarded [{self._workspace}]")

    def staging_fetch(self, local_dir: Path) -> StoreState:
        self._ensure_tables()
        local_dir.mkdir(parents=True, exist_ok=True)

        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"SELECT filename, content FROM {self._active_table}")
                active = {r[0]: r[1] for r in cur.fetchall()}
                cur.execute(f"SELECT filename, action, content FROM {self._staging_table}")
                staging = {r[0]: (r[1], r[2]) for r in cur.fetchall()}
        finally:
            conn.close()

        merged: dict[str, str | None] = dict(active)
        for fn, (action, content) in staging.items():
            if action == "delete":
                merged.pop(fn, None)
            elif action == "upsert":
                merged[fn] = content

        for root, _, filenames in os.walk(local_dir):
            for fn in filenames:
                if fn.endswith((".yml", ".yaml")):
                    os.remove(os.path.join(root, fn))

        for fn, content in merged.items():
            if content is not None:
                filepath = local_dir / fn
                filepath.parent.mkdir(parents=True, exist_ok=True)
                filepath.write_text(content, encoding="utf-8")

        revision = hashlib.sha256(
            json.dumps(sorted(merged.keys()), ensure_ascii=False).encode()
        ).hexdigest()
        logger.info(f"staging fetch [{self._workspace}]: {len(merged)} files → {local_dir}")
        return StoreState(revision=revision)

    def staging_commit(self) -> StoreState:
        self._ensure_tables()
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"SELECT filename, action, content, updated_at FROM {self._staging_table}")
                stg_rows = cur.fetchall()

                if not stg_rows:
                    cur.execute(f"SELECT MAX(updated_at), COUNT(*) FROM {self._active_table}")
                    row = cur.fetchone()
                    revision = hashlib.sha256(f"{row[0]}_{row[1]}".encode()).hexdigest() if row and row[0] else ""
                    return StoreState(revision=revision)

                for fn, action, content, stg_ts in stg_rows:
                    if action == "delete":
                        cur.execute(f"DELETE FROM {self._active_table} WHERE filename = %s", (fn,))
                    elif action == "upsert":
                        cur.execute(f"SELECT 1 FROM {self._active_table} WHERE filename = %s", (fn,))
                        if cur.fetchone():
                            cur.execute(
                                f"UPDATE {self._active_table} SET updated_at=%s, content=%s WHERE filename=%s",
                                (stg_ts, content, fn),
                            )
                        else:
                            cur.execute(
                                f"INSERT INTO {self._active_table} (filename, updated_at, content) VALUES (%s, %s, %s)",
                                (fn, stg_ts, content),
                            )

                cur.execute(f"DELETE FROM {self._staging_table}")

                cur.execute(f"SELECT MAX(updated_at), COUNT(*) FROM {self._active_table}")
                row = cur.fetchone()
                if row and row[0] is not None:
                    max_ts, cnt = row
                    revision = hashlib.sha256(f"{max_ts}_{cnt}".encode()).hexdigest()
                    updated_at = max_ts.strftime("%Y-%m-%dT%H:%M:%SZ") if isinstance(max_ts, datetime) else str(max_ts)
                else:
                    revision, updated_at = "", None
        finally:
            conn.close()

        logger.info(f"staging committed [{self._workspace}]: {len(stg_rows)} changes, staging cleared")
        return StoreState(revision=revision, updated_at=updated_at)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    _table_cache: dict[str, bool] = {}

    def _ensure_tables(self) -> None:
        key = self._workspace
        if self._table_cache.get(key):
            return
        conn = _get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE IF NOT EXISTS {_DORIS_DB}")
                cur.execute(f"USE {_DORIS_DB}")
                cur.execute(f"""\
                    CREATE TABLE IF NOT EXISTS {self._active_table} (
                        filename    VARCHAR(512) NOT NULL,
                        updated_at  DATETIME NOT NULL,
                        content     STRING NOT NULL
                    ) UNIQUE KEY(filename)
                    DISTRIBUTED BY HASH(filename) BUCKETS 1
                    PROPERTIES ('replication_num' = '1')
                """)
                cur.execute(f"""\
                    CREATE TABLE IF NOT EXISTS {self._staging_table} (
                        filename    VARCHAR(512) NOT NULL,
                        action      VARCHAR(16) NOT NULL,
                        updated_at  DATETIME NOT NULL,
                        content     STRING NULL
                    ) UNIQUE KEY(filename)
                    DISTRIBUTED BY HASH(filename) BUCKETS 1
                    PROPERTIES ('replication_num' = '1')
                """)
            self._table_cache[key] = True
            logger.info(f"Tables ensured for workspace '{self._workspace}': {self._active_table}, {self._staging_table}")
        except Exception as e:
            self._table_cache.pop(key, None)
            logger.warning(f"Table init failed for workspace '{self._workspace}': {e}")
        finally:
            conn.close()

"""FastMCP server definition with tool registration."""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from fastmcp import FastMCP
# ToolAnnotations is defined in mcp.types. `fastmcp.tools.tool` resolves at
# runtime only through a compatibility shim — that module has no file on disk
# in fastmcp 3.4, so importing from it breaks whenever the shim is dropped.
from mcp.types import ToolAnnotations

if TYPE_CHECKING:
    # Names used only in annotations. The handlers import what they need at
    # call time; `from __future__ import annotations` means these signatures
    # are never evaluated, so nothing here is imported at runtime.
    from starlette.requests import Request
    from starlette.responses import Response

    from store.store import DorisStore

from auth import check_tool_access, init_guard
from config.loader import AppConfig
from core.audit import init_audit_log, log_tool_call
from core.connection import ConnectionPool
from core.pool_manager import PoolManager
from core.response import ErrorCode, error_response, success_response
from core.sensitive_mask import mask_sensitive
from tools.discovery import (
    describe_table as _describe_table,
    list_databases as _list_databases,
    list_tables as _list_tables,
)
from tools.query import execute_query as _execute_query

logger = logging.getLogger("doris_new_mcp")

_WEBUI_SESSION_COOKIE = "doris_mcp_session"

# RFC 1918 private IPv4 networks (excludes loopback, link-local, etc.)
_IPV4_RFC1918_NETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)


def _is_rfc1918_ipv4(ip: ipaddress.IPv4Address) -> bool:
    """Return ``True`` if *ip* belongs to one of the three RFC-1918 blocks.

    This deliberately rejects loopback (127.0.0.0/8), link-local
    (169.254.0.0/16) and every other non-RFC-1918 address that
    :attr:`ipaddress.IPv4Address.is_private` would accept.
    """
    return any(ip in net for net in _IPV4_RFC1918_NETS)


def _encode_webui_session_cookie(session_id: str, server_ip: str) -> str:
    """Encode a Web UI session ID with the issuing server's IPv4 address."""
    if not session_id or "." in session_id:
        raise ValueError("Session ID must be non-empty and cannot contain '.'")
    parsed_ip = ipaddress.ip_address(server_ip)
    if not isinstance(parsed_ip, ipaddress.IPv4Address):
        raise ValueError("Web UI session cookie requires an IPv4 server IP")
    return f"{session_id}.{parsed_ip.compressed}"


def _decode_webui_session_cookie(cookie_value: str | None) -> tuple[str, str] | None:
    """Return ``(session_id, server_ip)`` from a Web UI session cookie."""
    if not cookie_value:
        return None
    session_id, separator, server_ip = cookie_value.partition(".")
    if not separator or not session_id or not server_ip:
        return None
    try:
        parsed_ip = ipaddress.ip_address(server_ip)
    except ValueError:
        return None
    if not isinstance(parsed_ip, ipaddress.IPv4Address):
        return None
    return session_id, parsed_ip.compressed


def get_machine_ip() -> str | None:
    """Best-effort local IPv4 detection via the UDP route to a public endpoint.

    Returns ``None`` instead of raising when the probe fails (offline host,
    no default route, IPv6-only stack) so startup can degrade gracefully.
    """
    import socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def resolve_machine_ip(configured_private_ip: str | None) -> str:
    """Resolve this node's IPv4 identity for session affinity.

    Preference order: configured ``privateIp`` → UDP auto-detection →
    ``127.0.0.1`` fallback.  Non-RFC-1918 addresses (e.g. public IPs) are
    accepted with a warning instead of being rejected.
    """
    if configured_private_ip is None:
        candidate = ""
    elif isinstance(configured_private_ip, str):
        candidate = configured_private_ip.strip()
    else:
        raise ValueError("Configured private IP must be a string or null")

    if candidate:
        # A configured value is operator input — fail fast on garbage.
        source = "Configured private IP"
        try:
            parsed_ip = ipaddress.ip_address(candidate)
        except ValueError as exc:
            raise ValueError(f"{source} must be an IPv4 address: {candidate!r}") from exc
        if not isinstance(parsed_ip, ipaddress.IPv4Address):
            raise ValueError(f"{source} must be an IPv4 address: {candidate!r}")
    else:
        # Auto-detection is best-effort: an unusable result must not abort
        # startup.  127.0.0.1 is harmless for single-node deployments (the
        # affinity cookie always points back at this node); multi-node
        # deployments must configure ``privateIp`` so nodes can be told apart.
        parsed_ip = None
        detected = get_machine_ip()
        if detected:
            try:
                probed = ipaddress.ip_address(detected)
                if isinstance(probed, ipaddress.IPv4Address):
                    parsed_ip = probed
            except ValueError:
                pass
        if parsed_ip is None:
            logger.warning(
                "Could not auto-detect the machine IP (offline host, no default "
                "route, or IPv6-only stack); falling back to 127.0.0.1. This is "
                "fine for single-node deployments; multi-node deployments must "
                "set server.privateIp in mcp-server.toml."
            )
            return "127.0.0.1"

    if not _is_rfc1918_ipv4(parsed_ip):
        logger.warning(
            "Node IP %s is not an RFC-1918 private address; using it anyway "
            "for session-affinity node identity.",
            parsed_ip.compressed,
        )
    return parsed_ip.compressed


def create_server(
    config_dir: str | None = None,
    env_file: str | None = None,
    machine_ip: str | None = None,
    webui_ip: str | None = None,
    config: "AppConfig | None" = None,
) -> FastMCP:
    """Create and configure the MCP server."""
    if config_dir is None:
        config_dir = os.environ.get("DORIS_MCP_CONFIG_DIR", "config")

    config_path = os.path.abspath(config_dir)
    # Reuse a pre-built config when the caller (main.py) already parsed it,
    # so the TOML/dotenv files are read exactly once per process.
    cfg = config if config is not None else AppConfig(config_path, env_file=env_file)
    cc = cfg.cluster

    # Workspace directory
    workspace_dir = os.path.join(os.path.dirname(config_path), "workspace")
    os.makedirs(workspace_dir, exist_ok=True)

    # ── Multi-workspace init ──
    from pathlib import Path as _Path
    _ws_root = _Path(workspace_dir) / "workspaces"
    _ws_root.mkdir(parents=True, exist_ok=True)

    # Lazy initialization is deferred until credentials are available.
    # Automatic example deployment is intentionally Admin-only because it
    # creates databases/tables and grants privileges.
    _watcher_initialized = False
    _example_auto_seed_done = False
    _example_lock = asyncio.Lock()
    # Background example deploy/delete job state — the POST endpoint returns
    # immediately and the frontend polls /example/deployment/status, so a
    # slow seed never trips proxy/LB idle timeouts (504 HTML pages).
    _example_job: dict = {"status": "idle", "message": "", "deploy": None}

    # Multi-workspace watcher (lazy — discovered on first request)
    from store.watcher import MultiWorkspaceWatcher
    from store.store import set_doris_port
    set_doris_port(cc.fe_mysql_port)
    multi_watcher = MultiWorkspaceWatcher(
        config_dir=_Path(config_path),
        workspace_root=_ws_root,
        app_config=cfg,
    )
    logger.info("Multi-workspace watcher created (lazy init)")

    async def _deploy_example(user: str, password: str) -> bool:
        """Deploy example data/models with verified Admin credentials."""
        nonlocal _watcher_initialized, _example_auto_seed_done
        from store.seed import seed_all, set_doris_port as seed_set_port
        from store.store import set_request_credentials as _set_creds

        async with _example_lock:
            _set_creds(user, password)
            seed_set_port(cc.fe_mysql_port)
            performed = await asyncio.to_thread(seed_all)

            if not _watcher_initialized:
                await asyncio.to_thread(multi_watcher.initialize)
                _watcher_initialized = True
            elif multi_watcher.has_workspace("example"):
                await asyncio.to_thread(multi_watcher.force_reload, "example")
            else:
                await asyncio.to_thread(
                    multi_watcher._init_workspace, "example", first_load=True
                )

            # Allow all authenticated Doris users to query the sample tables.
            try:
                import pymysql as _pymysql
                _conn = await asyncio.to_thread(
                    _pymysql.connect,
                    host="127.0.0.1",
                    port=cc.fe_mysql_port,
                    user=user,
                    password=password,
                    charset="utf8mb4",
                    connect_timeout=5,
                )
                try:
                    await asyncio.to_thread(
                        _conn.cursor().execute, "GRANT SELECT_PRIV ON *.* TO '%'"
                    )
                finally:
                    await asyncio.to_thread(_conn.close)
                logger.info("GRANT SELECT_PRIV ON *.* TO %s — done", "'%'")
            except Exception as exc:
                logger.warning("Example deployed, but GRANT SELECT_PRIV failed: %s", exc)

            _example_auto_seed_done = True
            return performed

    async def _delete_example(user: str, password: str) -> None:
        """Delete example deployment and detach it from the global router."""
        nonlocal _example_auto_seed_done
        from store.seed import delete_example
        from store.store import DorisStore, set_request_credentials as _set_creds

        async with _example_lock:
            _set_creds(user, password)
            await asyncio.to_thread(delete_example)
            multi_watcher._workspaces.pop("example", None)
            multi_watcher._staging_validated.discard("example")
            multi_watcher.router.rebuild(multi_watcher._workspaces)
            DorisStore._table_cache.pop("example", None)

            import shutil as _shutil
            await asyncio.to_thread(
                _shutil.rmtree, _ws_root / "example", ignore_errors=True
            )

    async def _run_example_job(deploy: bool, user: str, password: str) -> None:
        """Run example deploy/delete in the background and record the outcome."""
        try:
            if deploy:
                await _deploy_example(user, password)
                message = "Example files and sample database deployed."
            else:
                await _delete_example(user, password)
                message = "Example files and sample database deleted."
            from store.seed import is_example_deployed
            deployed = await asyncio.to_thread(is_example_deployed)
            log_tool_call(
                "example_deployment",
                client_id=user or "admin",
                params={"deploy": deploy},
                success=(deployed == deploy),
                duration_ms=0,
            )
            if deployed != deploy:
                _example_job.update(
                    status="failed",
                    message=f"Post-check failed: expected deployed={deploy}, got {deployed}",
                )
                return
            _example_job.update(status="success", message=message)
        except Exception as exc:
            logger.exception("Example deployment switch failed")
            _example_job.update(status="failed", message=str(exc))
            # Prevent seed_example=true from immediately undoing a manual delete.
            # It remains the default again after a process restart.
            _example_auto_seed_done = True

    async def _ensure_initialized(user: str, password: str) -> None:
        """Initialize workspaces once authenticated credentials are available."""
        nonlocal _watcher_initialized
        from store.store import set_request_credentials as _set_creds

        _set_creds(user, password)
        try:
            async with _example_lock:
                if not _watcher_initialized:
                    await asyncio.to_thread(multi_watcher.initialize)
                    _watcher_initialized = True
                    logger.info(
                        "Watcher initialized: %s", multi_watcher.workspace_names()
                    )
        except Exception:
            logger.exception("Lazy initialization failed — workspace may be empty")

    # Setup logging: write to workspace/logs/server.log + stderr
    import logging as _logging
    logs_dir = os.path.join(workspace_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_level = getattr(_logging, cfg.mcp.log_level.upper(), _logging.INFO)
    root_logger = _logging.getLogger()
    root_logger.setLevel(log_level)
    # File handler with timed rotation (always add, avoid duplicates on hot-reload)
    from logging.handlers import TimedRotatingFileHandler as _TRFH
    server_log_path = os.path.join(logs_dir, "server.log")
    if not any(
        isinstance(h, _logging.FileHandler) and getattr(h, "baseFilename", None) == os.path.abspath(server_log_path)
        for h in root_logger.handlers
    ):
        fh = _TRFH(
            server_log_path,
            when=cfg.mcp.log_rotation_when,
            backupCount=cfg.mcp.log_rotation_backup_count,
            encoding="utf-8",
        )
        fh.setLevel(log_level)
        fh.setFormatter(_logging.Formatter(
            "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root_logger.addHandler(fh)
        logger.info("Server log file: %s (rotation=%s, backup_count=%d)",
                     server_log_path, cfg.mcp.log_rotation_when, cfg.mcp.log_rotation_backup_count)

    # Audit log in workspace/logs/
    audit_path = cfg.mcp.audit_log_path
    if not os.path.isabs(audit_path):
        audit_path = os.path.join(workspace_dir, audit_path)
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    init_audit_log(audit_path, when=cfg.mcp.log_rotation_when, backup_count=cfg.mcp.log_rotation_backup_count)

    # Per-user pool manager — all Doris connections use request credentials.
    pool_manager: PoolManager | None = PoolManager(cc)

    init_guard(
        pool_manager=pool_manager,
        transport="streamable-http",
    )

    # Init health tracking
    from core.health import service_health
    service_health.reset()
    service_health.get("doris_connection").set_healthy(
        f"Admin pool: {cc.fe_host}:{cc.fe_mysql_port}", user="admin")
    if cfg.auth is not None:
        if cfg.auth.static:
            mode = f"static({len(cfg.auth.static.tokens)} tokens)"
        elif cfg.auth.jwt:
            mode = "jwt"
        elif cfg.auth.oauth:
            mode = "oauth"
        else:
            mode = "none"
        service_health.get("auth").set_healthy(f"Auth enabled: {mode}")
    else:
        service_health.get("auth").set_healthy("Auth disabled (no auth config)")

    # Credential-based auth: username:password → Doris verification → 10-min cache
    from auth.credential_cache import CredentialCache
    from auth.credential_verifier import CredentialVerifier
    _credential_cache = CredentialCache(ttl_seconds=600)

    async def _async_verify_credentials(user: str, password: str) -> bool:
        """Async wrapper for Doris credential verification."""
        ok, _ = await asyncio.to_thread(_verify_doris_credentials, user, password)
        return ok

    auth_provider = CredentialVerifier(_credential_cache, _async_verify_credentials,
                                        on_authenticated=_ensure_initialized)
    logger.info("Auth: CredentialVerifier registered (username:password, 10-min cache, lazy seed)")

    # Helper: get store for a workspace (defaults to "example")
    def _get_workspace_from_request(request: Request) -> str:
        """Extract workspace from query param for all methods."""
        return (request.query_params.get("workspace", "") or "example").strip()

    def _get_store(workspace: str) -> DorisStore:
        """Get or create a DorisStore for the given workspace."""
        from store.store import DorisStore as _DS
        return _DS(workspace=workspace)

    from starlette.datastructures import UploadFile as _UploadFile

    def _form_str(form, key: str, default: str = "") -> str:
        """Read a form field as text.

        ``form.get()`` yields ``UploadFile | str | None`` — a client may post
        a file part where a text field is expected. Treat any non-text value
        as absent rather than letting an UploadFile flow into string code.
        """
        value = form.get(key)
        return value if isinstance(value, str) else default

    # ── Auth infrastructure ──

    import re as _re
    import secrets as _secrets
    _VALID_WORKSPACE_NAME = _re.compile(r'^[a-zA-Z][a-zA-Z0-9_]*$')
    _webui_sessions: dict[str, dict] = {}
    _SESSION_TTL = 24 * 3600  # 24 hours
    _WEBUI_SESSION_MAX = 1000  # hard cap on in-memory sessions

    def _prune_webui_sessions() -> None:
        """Drop expired sessions, then evict the oldest while over capacity.

        Called on login (the only write path) so the dict cannot grow
        without bound and expired entries do not linger until revisited.
        """
        now = time.time()
        for sid in [s for s, v in _webui_sessions.items()
                    if now - v["created_at"] >= _SESSION_TTL]:
            _webui_sessions.pop(sid, None)
        while len(_webui_sessions) >= _WEBUI_SESSION_MAX:
            oldest = min(_webui_sessions,
                         key=lambda s: _webui_sessions[s]["created_at"])
            _webui_sessions.pop(oldest, None)

    # Brute-force guard: consecutive login failures per username.  After
    # _LOGIN_MAX_FAILURES failures the account is locked for
    # _LOGIN_LOCKOUT_SECONDS; a successful login clears the counter.
    # In-memory only — not shared across processes, so multi-instance
    # deployments still need an external rate limiter.
    _LOGIN_MAX_FAILURES = 5
    _LOGIN_LOCKOUT_SECONDS = 300  # 5 minutes
    _LOGIN_FAILURES_MAX = 10000  # cap on tracked usernames
    _login_failures: dict[str, tuple[int, float]] = {}  # user -> (count, locked_until)

    def _login_locked(user: str) -> bool:
        entry = _login_failures.get(user)
        if not entry:
            return False
        count, locked_until = entry
        if count < _LOGIN_MAX_FAILURES:
            return False
        if time.time() < locked_until:
            return True
        _login_failures.pop(user, None)  # lock expired
        return False

    def _record_login_failure(user: str) -> None:
        count, _ = _login_failures.get(user, (0, 0.0))
        count += 1
        locked_until = (
            time.time() + _LOGIN_LOCKOUT_SECONDS
            if count >= _LOGIN_MAX_FAILURES else 0.0
        )
        _login_failures[user] = (count, locked_until)
        if len(_login_failures) > _LOGIN_FAILURES_MAX:
            # Bound memory: drop entries with no active lock first.
            now = time.time()
            for u in [u for u, (c, t) in _login_failures.items()
                      if c < _LOGIN_MAX_FAILURES or now >= t]:
                _login_failures.pop(u, None)
            if len(_login_failures) > _LOGIN_FAILURES_MAX:
                _login_failures.clear()

    def _record_login_success(user: str) -> None:
        _login_failures.pop(user, None)

    async def _get_per_user_pool() -> ConnectionPool:
        """Return a per-user connection pool from the request Bearer token.

        Credentials are extracted from the FastMCP auth context (set by
        CredentialVerifier).  Raises RuntimeError if no valid token is
        present — there is no fallback to a shared admin pool.
        """
        if pool_manager is None:
            raise RuntimeError("PoolManager not initialized")
        from mcp.server.auth.middleware.auth_context import get_access_token
        access_token = get_access_token()
        if not access_token or not access_token.client_id:
            raise RuntimeError(
                "No credentials in request context — "
                "ensure the request carries a valid Bearer token."
            )
        token_str = access_token.token
        parts = token_str.split(":", 1)
        username = access_token.client_id
        password = parts[1] if len(parts) > 1 else ""
        return await pool_manager.get_or_create_local_pool(
            username, password, host=_MACHINE_IP,
            on_auth_error=lambda: _credential_cache.clear(username, password),
        )

    async def _acquire_pool(tool_name: str) -> ConnectionPool | str:
        """Resolve the per-user pool, or return an error response to send back.

        Tool handlers must never let a connection failure escape — an
        uncaught exception tears down the MCP transport instead of
        returning a result the caller can act on.

        Returns the pool on success, or the JSON error string on failure.
        Callers narrow with ``isinstance(pool, str)``.
        """
        try:
            return await _get_per_user_pool()
        except Exception as e:
            logger.warning("%s: cannot acquire Doris connection: %s", tool_name, e)
            return error_response(
                ErrorCode.CONNECTION_ERROR,
                f"Cannot connect to Doris with the supplied credentials: {e}",
            )

    # Node identity: used for local Doris connections and as the
    # session-affinity local IP.  Prefers the caller-provided value, then
    # the configured ``privateIp``, then auto-detection (with fallback).
    _MACHINE_IP = machine_ip if machine_ip is not None else resolve_machine_ip(cfg.mcp.private_ip)
    # Web UI IP written into session cookies; defaults to the node identity
    # (cookie-affinity mode).
    _WEBUI_IP = webui_ip if webui_ip is not None else _MACHINE_IP

    def _verify_doris_credentials(user: str, password: str) -> tuple[bool, bool]:
        import pymysql
        if _login_locked(user):
            # Same result as a wrong password — do not reveal lock state.
            return False, False
        try:
            conn = pymysql.connect(
                host=_MACHINE_IP, port=cc.fe_mysql_port,
                user=user, password=password,
                charset="utf8mb4", connect_timeout=5,
            )
            conn.close()
            _record_login_success(user)
            return True, (user in cfg.mcp.admin_users)
        except Exception:
            _record_login_failure(user)
            return False, False

    def _webui_redirect_login():
        from starlette.responses import RedirectResponse as _R
        return _R("/mcp/web/login", status_code=303)

    async def _check_semantic_access(
        request: Request, require_admin: bool = False,
    ) -> tuple[str | None, bool, Response | None]:
        JSONResponse = _JSONResponse  # alias

        # 1. Session cookie
        session_cookie = _decode_webui_session_cookie(
            request.cookies.get(_WEBUI_SESSION_COOKIE)
        )
        if session_cookie:
            session_id, server_ip = session_cookie
            session = _webui_sessions.get(session_id)
        else:
            session_id, server_ip, session = None, None, None
        if session and session["server_ip"] == server_ip:
            if time.time() - session["created_at"] < _SESSION_TTL:
                client_id = session["doris_user"]
                is_admin = (client_id in cfg.mcp.admin_users)
                if require_admin and not is_admin:
                    return None, False, JSONResponse(
                        {"success": False, "error": {"code": "PERMISSION_DENIED", "message": "Only admin can modify semantic models."}},
                        status_code=403)
                from store.store import set_request_credentials
                set_request_credentials(client_id, session.get("doris_password", ""))
                await _ensure_initialized(client_id, session.get("doris_password", ""))
                return client_id, is_admin, None
            del _webui_sessions[session_id]

        # 2. Bearer token (CLI / API)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token_str = auth_header[7:]
            parts = token_str.split(":", 1)
            username = parts[0]
            password = parts[1] if len(parts) > 1 else ""
            ok, is_admin = await asyncio.to_thread(_verify_doris_credentials, username, password)
            if ok:
                if require_admin and not is_admin:
                    return None, False, JSONResponse(
                        {"success": False, "error": {"code": "PERMISSION_DENIED", "message": "Only admin can modify semantic models."}},
                        status_code=403)
                from store.store import set_request_credentials
                set_request_credentials(username, password)
                await _ensure_initialized(username, password)
                return username, is_admin, None
            return None, False, JSONResponse(
                {"success": False, "error": {"code": "UNAUTHORIZED", "message": "Invalid credentials"}},
                status_code=401)

        if "text/html" in (request.headers.get("accept") or ""):
            return None, False, _webui_redirect_login()
        return None, False, JSONResponse(
            {"success": False, "error": {"code": "UNAUTHORIZED", "message": "Session expired or missing"}},
            status_code=401)

    async def _check_admin_access(request: Request) -> tuple[str | None, Response | None]:
        client_id, _, err = await _check_semantic_access(request, require_admin=True)
        return client_id, err

    def _check_webui_admin_cookie(
        request: Request,
    ) -> tuple[dict | None, Response | None]:
        """Authorize the example switch using only the WebUI session cookie."""
        session_cookie = _decode_webui_session_cookie(
            request.cookies.get(_WEBUI_SESSION_COOKIE)
        )
        if session_cookie:
            session_id, server_ip = session_cookie
            session = _webui_sessions.get(session_id)
        else:
            session_id, server_ip, session = None, None, None
        if session and session.get("server_ip") != server_ip:
            session = None
        if session is None:
            return None, _JSONResponse(
                {
                    "success": False,
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "A valid Admin WebUI session is required.",
                    },
                },
                status_code=401,
            )
        if time.time() - session["created_at"] >= _SESSION_TTL:
            if session_id:
                _webui_sessions.pop(session_id, None)
            return None, _JSONResponse(
                {
                    "success": False,
                    "error": {
                        "code": "UNAUTHORIZED",
                        "message": "Admin WebUI session has expired.",
                    },
                },
                status_code=401,
            )
        # is_admin was resolved against cfg.mcp.admin_users at login time.
        if not session.get("is_admin"):
            return None, _JSONResponse(
                {
                    "success": False,
                    "error": {
                        "code": "PERMISSION_DENIED",
                        "message": "Only the Admin WebUI account can manage example.",
                    },
                },
                status_code=403,
            )

        from store.store import set_request_credentials
        set_request_credentials(session.get("doris_user", ""), session.get("doris_password", ""))
        return session, None

    # Load query guide from package resource
    _query_guide = ""
    try:
        from importlib.resources import files
        _query_guide = files("skills").joinpath("doris-mcp-skill.md").read_text(encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to load query guide: {e}")

    _instructions = (
        "IMPORTANT: Before any data query, call get_query_guide() to get the complete workflow. "
        "Then call check_service_health() to see workspace status. "
        "Each data query tool requires a workspace parameter — use 'example' to start. "
        "Follow the guide strictly — do NOT improvise tool calling order."
    )

    @asynccontextmanager
    async def _lifespan(app: "FastMCP"):
        try:
            yield
        finally:
            if pool_manager is not None:
                try:
                    await pool_manager.close_all()
                except Exception:
                    logger.exception("Failed during pool_manager.close_all()")
            logger.info("All Doris connection pools closed")

    mcp = FastMCP(
        name=cfg.mcp.name,
        instructions=_instructions,
        auth=auth_provider,
        lifespan=_lifespan,
    )

    # ========== Credential-based Auth (MCP tools) ==========

    from starlette.responses import JSONResponse as _JSONResponse

    # ========== Base Tools (always registered) ==========

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def get_query_guide() -> str:
        """CALL THIS FIRST before any data query. Returns the complete workflow guide: health check procedure, metric layer vs basic SQL routing, tool calling order, search strategies, and query syntax. Without this guide you will use tools incorrectly."""
        auth = check_tool_access("get_query_guide")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        if _query_guide:
            result = success_response({"guide": _query_guide})
        else:
            result = error_response(ErrorCode.INTERNAL_ERROR, "Query guide not found")
        log_tool_call("get_query_guide", client_id=auth.client_id,
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=False)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def list_databases(page_size: int = 50, page_token: str = "") -> str:
        """Lists all databases. For data queries, prefer list_metrics + query_metric over exploring schema."""
        auth = check_tool_access("list_databases")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        pool = await _acquire_pool("list_databases")
        if isinstance(pool, str):
            return pool
        result = await _list_databases(pool, page_size, page_token or None, cc.db_whitelist or None)
        log_tool_call("list_databases", client_id=auth.client_id,
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=False)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def list_tables(
        database: str, like: str = "",
        page_size: int = 50, page_token: str = "",
    ) -> str:
        """LOWEST TOOL, STOP: If your goal is to query data, use list_metrics + query_metric instead. Returns table names only; use describe_table for column detail."""
        auth = check_tool_access("list_tables")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        if cc.db_whitelist and database not in cc.db_whitelist:
            return error_response(ErrorCode.PERMISSION_DENIED, f"Database '{database}' not in whitelist")
        pool = await _acquire_pool("list_tables")
        if isinstance(pool, str):
            return pool
        result = await _list_tables(pool, database, like or None, page_size, page_token or None)
        log_tool_call("list_tables", client_id=auth.client_id, params={"database": database},
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=False)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def describe_table(database: str, table: str, detail_level: str = "summary") -> str:
        """LOWEST TOOL, STOP: If your goal is to query data, use list_metrics + query_metric instead. This tool returns physical schema only. Do NOT use table columns to write raw SQL for metrics — use query_metric. detail_level: 'names'/'summary'/'full'."""
        auth = check_tool_access("describe_table")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        if cc.db_whitelist and database not in cc.db_whitelist:
            return error_response(ErrorCode.PERMISSION_DENIED, f"Database '{database}' not in whitelist")
        pool = await _acquire_pool("describe_table")
        if isinstance(pool, str):
            return pool
        result = await _describe_table(pool, database, table, detail_level)
        log_tool_call("describe_table", client_id=auth.client_id, params={"database": database, "table": table},
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=False)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False)
    )
    async def execute_query(sql: str, database: str = "", max_rows: int = 0) -> str:
        """Raw SQL fallback. Always returns error format — read the message to decide next step. If metrics exist for this query, switch to query_metric. If no matching metric, the data is in the error details. Supports SHOW/DESCRIBE, CTEs, JOINs, UNION ALL."""
        auth = check_tool_access("execute_query")
        if auth.denied:
            return auth.denied

        # The whitelist is enforced only against the explicit `database`
        # argument — reliably parsing the target DB out of arbitrary SQL is
        # not feasible, so fully-qualified cross-database references in SQL
        # are not caught here. Empty whitelist = no restriction.
        if database and cc.db_whitelist and database not in cc.db_whitelist:
            return error_response(ErrorCode.PERMISSION_DENIED, f"Database '{database}' not in whitelist")

        pool = await _acquire_pool("execute_query")
        if isinstance(pool, str):
            return pool

        start = time.monotonic()
        result = await _execute_query(pool, sql, database or None, max_rows or None)
        duration = (time.monotonic() - start) * 1000

        import json
        parsed = json.loads(result)
        actual_success = parsed.get("success", False)

        log_tool_call("execute_query", client_id=auth.client_id, params={"sql": mask_sensitive(sql[:200]), "database": database},
                      success=actual_success, duration_ms=duration, metricflow=False)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def check_service_health() -> str:
        """FIRST TOOL to call at the start of any session. Returns doris connectivity and all workspace statuses. Use to determine which workspaces are available."""
        auth = check_tool_access("check_service_health")
        if auth.denied:
            return auth.denied
        start = time.monotonic()

        # Verify Doris DB connectivity (use per-user pool with request credentials)
        db_ok = False
        db_error = ""
        health_pool = await _acquire_pool("check_service_health")
        try:
            if isinstance(health_pool, str):
                raise RuntimeError("credentials rejected by Doris")
            await health_pool.execute("SELECT 1")
            db_ok = True
        except Exception as e:
            db_error = str(e)

        if db_ok:
            service_health.get("doris_connection").set_healthy(
                f"Doris FE {cc.fe_host}:{cc.fe_mysql_port}", user="admin")
        else:
            service_health.get("doris_connection").set_error(f"Connection failed: {db_error}")

        # Ensure all known workspaces are loaded (on-demand)
        for ws_name in multi_watcher.workspace_names():
            await asyncio.to_thread(multi_watcher.ensure_fresh, ws_name)

        # Per-workspace status
        ws_statuses: dict[str, dict] = {}
        for ws_name in multi_watcher.workspace_names():
            ws = multi_watcher.get_workspace(ws_name)
            if not ws:
                continue
            if ws.manifest and ws.compiler:
                metrics = ws.manifest.list_metrics()
                if ws.compiler.is_engine_mode:
                    ws_statuses[ws_name] = {
                        "status": "healthy",
                        "metric_count": len(metrics),
                    }
                else:
                    ws_statuses[ws_name] = {
                        "status": "not_ready",
                        "message": "Engine init failed — check model YAML (e.g., missing agg_time_dimension)",
                    }
            else:
                files = await asyncio.to_thread(ws.store.list_files)
                if not files:
                    ws_statuses[ws_name] = {
                        "status": "no_models",
                        "message": "No YAML files uploaded",
                    }
                else:
                    ws_statuses[ws_name] = {
                        "status": "not_ready",
                        "message": "Files present but failed to load",
                    }

        health_data = {
            "doris": "connected" if db_ok else "unavailable",
            "workspaces": ws_statuses,
        }
        if not db_ok:
            health_data["doris_error"] = db_error

        log_tool_call("check_service_health", client_id=auth.client_id,
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=False)
        return success_response(health_data)

    # ========== Metric Layer Tools (always registered, gated at runtime) ==========

    from tools.semantic import (
        list_metrics as _list_metrics,
        list_dimensions_for_metric as _list_dims,
        query_metric as _query_metric,
    )
    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def list_metrics(workspace: str, page_size: int = 50, page_token: str = "") -> str:
        """Lists all available metrics (name, description, type). workspace is required. Use 'example' for built-in sample."""
        auth = check_tool_access("list_metrics")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        ws = await asyncio.to_thread(multi_watcher.ensure_fresh, workspace)
        if not ws or not ws.manifest or not ws.compiler:
            return error_response(ErrorCode.SERVICE_NOT_READY, f"Semantic layer not initialized for workspace '{workspace}'")
        result = await _list_metrics(ws.manifest, page_size, page_token or None)
        log_tool_call("list_metrics", client_id=auth.client_id,
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=True)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def list_dimensions_for_metric(workspace: str, metric_name: str) -> str:
        """Returns valid group_by dimensions for a metric. workspace is required."""
        auth = check_tool_access("list_dimensions_for_metric")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        ws = await asyncio.to_thread(multi_watcher.ensure_fresh, workspace)
        if not ws or not ws.manifest or not ws.compiler:
            return error_response(ErrorCode.SERVICE_NOT_READY, f"Semantic layer not initialized for workspace '{workspace}'")
        result = await _list_dims(ws.manifest, metric_name)
        log_tool_call("list_dimensions_for_metric", client_id=auth.client_id, params={"metric_name": metric_name},
                      duration_ms=(time.monotonic() - start) * 1000, metricflow=True)
        return result

    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=False, openWorldHint=False)
    )
    async def query_metric(
        workspace: str,
        metrics: list[str],
        group_by: list[str] = [],
        where: str = "",
        order_by: list[str] = [],
        limit: int = 0,
        database: str = "",
        max_rows: int = 0,
        having: str = "",
    ) -> str:
        """PRIMARY tool for ALL data queries involving counts, sums, rates, averages, rankings, or trends. Requires workspace with healthy semantic layer (check via check_service_health). Generates semantically correct SQL via MetricFlow. group_by/order_by/where accept bare names (auto-resolved). having filters on aggregated metric values. One query = one call."""
        auth = check_tool_access("query_metric")
        if auth.denied:
            return auth.denied
        start = time.monotonic()
        ws = await asyncio.to_thread(multi_watcher.ensure_fresh, workspace)
        if not ws or not ws.manifest or not ws.compiler:
            return error_response(ErrorCode.SERVICE_NOT_READY, f"Semantic layer not initialized for workspace '{workspace}'")
        if group_by:
            group_by = ws.compiler.resolve_group_by(metrics, group_by)
        if order_by:
            order_by = ws.compiler.resolve_group_by(metrics, order_by)
        if where:
            where = ws.compiler.resolve_where(metrics, where)

        pool = await _acquire_pool("query_metric")
        if isinstance(pool, str):
            return pool

        result = await _query_metric(ws.compiler, pool, metrics, group_by or None, where or None, order_by or None, limit or None, database or None, max_rows or None, having or None)
        duration = (time.monotonic() - start) * 1000
        success = '"success": true' in result
        mf_cmd = f"mf query --metrics {','.join(metrics)}"
        if group_by:
            mf_cmd += f" --group-by {','.join(group_by)}"
        log_tool_call("query_metric", client_id=auth.client_id, params={"metrics": metrics, "group_by": group_by},
                      success=success, duration_ms=duration, metricflow=True, mf_command=mf_cmd)
        return result

    # ========== Manual reload Tool ==========
    @mcp.tool(
        annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=False)
    )
    async def reload_semantic_layer(workspace: str) -> str:
        """Reloads the metric layer for a workspace and waits for the result. workspace is required."""
        auth = check_tool_access("reload_semantic_layer")
        if auth.denied:
            return auth.denied
        ws = await asyncio.to_thread(multi_watcher.ensure_fresh, workspace)
        if not ws:
            return error_response(ErrorCode.VALIDATION_ERROR, f"Workspace not found: {workspace}")
        status, msg = await asyncio.to_thread(multi_watcher.force_reload, workspace)
        log_tool_call("reload_semantic_layer", client_id=auth.client_id,
                      success=(status == "done"), duration_ms=0, metricflow=True)
        if status == "failed":
            return error_response(ErrorCode.INTERNAL_ERROR, msg)
        return success_response({"status": status, "message": msg})


    @mcp.custom_route("/mcp/web/semantic/reload", methods=["POST"])
    async def api_reload_semantic_layer(request: Request) -> Response:
        """HTTP endpoint for CI/CD and schedulers. Admin only."""
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            body = {}
        ws = body.get("workspace", "example")
        if not multi_watcher.has_workspace(ws):
            return _JSONResponse({"success": False, "error": {"code": "VALIDATION_ERROR", "message": f"Workspace not found: {ws}"}}, status_code=400)
        status, msg = await asyncio.to_thread(multi_watcher.force_reload, ws)
        log_tool_call("reload_semantic_layer", client_id=client_id,
                      success=(status == "done"), duration_ms=0, metricflow=True)
        if status in ("rejected", "failed"):
            return _JSONResponse({"success": False, "error": {"code": "RELOAD_FAILED", "message": msg}}, status_code=500)
        return _JSONResponse({"success": True, "data": {"status": status, "message": msg}})

    @mcp.custom_route("/mcp/web/example/deployment", methods=["POST"])
    async def api_example_deployment(request: Request) -> Response:
        """Deploy/delete example using the verified Admin WebUI session."""
        session, err = _check_webui_admin_cookie(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            body = {}
        deploy = body.get("deploy")
        if not isinstance(deploy, bool):
            return _JSONResponse(
                {
                    "success": False,
                    "error": {
                        "code": "BAD_REQUEST",
                        "message": "deploy must be true or false.",
                    },
                },
                status_code=400,
            )

        user = session.get("doris_user", "") if session else ""
        password = session.get("doris_password", "") if session else ""

        if _example_job["status"] == "running":
            return _JSONResponse(
                {
                    "success": True,
                    "data": {"status": "running", "message": _example_job["message"]},
                }
            )

        _example_job.update(
            status="running",
            message=(
                "Deploying example files and sample database..."
                if deploy
                else "Deleting example files and sample database..."
            ),
            deploy=deploy,
        )
        asyncio.get_running_loop().create_task(_run_example_job(deploy, user, password))
        return _JSONResponse(
            {
                "success": True,
                "data": {"status": "running", "message": _example_job["message"]},
            }
        )

    @mcp.custom_route("/mcp/web/example/deployment/status", methods=["GET"])
    async def api_example_deployment_status(request: Request) -> Response:
        """Poll the background example deploy/delete job."""
        session, err = _check_webui_admin_cookie(request)
        if err:
            return err
        data: dict = {
            "status": _example_job["status"],
            "message": _example_job["message"],
        }
        if _example_job["status"] == "success":
            deployed = bool(_example_job.get("deploy"))
            data["deployed"] = deployed
            data["redirect"] = (
                "/mcp/web/models?workspace=example" if deployed else "/mcp/web"
            )
        return _JSONResponse({"success": True, "data": data})

    @mcp.custom_route("/mcp/web/workspace/create", methods=["POST"])
    async def api_workspace_create(request: Request) -> Response:
        """Create a new workspace by creating storage tables."""
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            return _JSONResponse({"success": False, "error": {"code": "BAD_REQUEST", "message": "Invalid JSON"}}, status_code=400)
        name = (body.get("name", "") or "").strip()
        if not name or not _VALID_WORKSPACE_NAME.match(name):
            return _JSONResponse({"success": False, "error": {"code": "VALIDATION_ERROR", "message": "Workspace name must start with a letter and contain only letters, digits, underscores"}}, status_code=400)
        if multi_watcher.has_workspace(name):
            return _JSONResponse({"success": False, "error": {"code": "CONFLICT", "message": f"Workspace '{name}' already exists"}}, status_code=409)
        # Initialize immediately in watcher so it appears in workspace list
        await asyncio.to_thread(multi_watcher._init_workspace, name)
        logger.info(f"Workspace '{name}' created by {client_id}")
        return _JSONResponse({"success": True, "data": {"workspace": name, "message": f"Workspace '{name}' created."}})

    @mcp.custom_route("/mcp/web/workspace/delete", methods=["POST"])
    async def api_workspace_delete(request: Request) -> Response:
        """Delete a workspace by dropping its storage tables."""
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            return _JSONResponse({"success": False, "error": {"code": "BAD_REQUEST", "message": "Invalid JSON"}}, status_code=400)
        name = (body.get("workspace", "") or "").strip()
        if not name:
            return _JSONResponse({"success": False, "error": {"code": "VALIDATION_ERROR", "message": "workspace is required"}}, status_code=400)
        if name == "example":
            return _JSONResponse({"success": False, "error": {"code": "FORBIDDEN", "message": "Cannot delete built-in example workspace"}}, status_code=403)
        
        # DROP only semantic model tables (active_store + staging_store), NOT data tables
        from store.store import DorisStore
        await asyncio.to_thread(DorisStore.drop_workspace_tables, name)
        # Immediately remove from watcher and clear table cache so it disappears from UI
        multi_watcher._workspaces.pop(name, None)
        multi_watcher.router.rebuild(multi_watcher._workspaces)
        # Clear the DorisStore class-level table cache so re-creation works
        from store.store import DorisStore
        DorisStore._table_cache.pop(name, None)
        logger.info(f"Workspace '{name}' deleted by {client_id}")
        return _JSONResponse({"success": True, "data": {"workspace": name, "message": f"Workspace '{name}' deleted"}})


    @mcp.custom_route("/mcp/web/semantic/push", methods=["POST"])
    async def api_semantic_push(request: Request) -> Response:
        """CLI push: upload YAML files directly to staging_store for a workspace."""
        import yaml as _yaml
        client_id, err = await _check_admin_access(request)
        if err:
            return err

        try:
            form = await request.form()
        except Exception:
            return _JSONResponse(
                {"success": False, "error": {"code": "BAD_REQUEST", "message": "Invalid multipart form"}},
                status_code=400,
            )
        
        ws = _form_str(form, "workspace", "example")
        st = await asyncio.to_thread(_get_store, ws)

        files_staged = 0
        for _, upload in form.multi_items():
            if not isinstance(upload, _UploadFile) or not upload.filename:
                continue
            filename = upload.filename
            if ".." in filename or "/" in filename or "\\" in filename:
                continue
            if not filename.endswith((".yml", ".yaml")):
                continue
            content = await upload.read()
            if len(content) > 1 * 1024 * 1024:
                continue
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                continue
            try:
                _yaml.safe_load(text)
            except _yaml.YAMLError as e:
                return _JSONResponse(
                    {"success": False, "error": {"code": "BAD_REQUEST", "message": f"Invalid YAML in {filename}: {e}"}},
                    status_code=400,
                )
            await asyncio.to_thread(st.staging_upsert, filename, text)
            files_staged += 1

        if files_staged == 0:
            return _JSONResponse(
                {"success": False, "error": {"code": "BAD_REQUEST", "message": "No valid YAML files uploaded"}},
                status_code=400,
            )

        log_tool_call("semantic_push", client_id=client_id,
                      params={"workspace": ws, "file_count": files_staged},
                      success=True, duration_ms=0)
        return _JSONResponse(
            {"success": True, "data": {"workspace": ws, "files_staged": files_staged, "hint": "Use staging validate + commit to apply"}},
            status_code=200,
        )

    @mcp.custom_route("/mcp/web/semantic/push/{request_id}", methods=["GET"])
    async def api_semantic_push_result(request: Request) -> Response:
        return _JSONResponse({"success": True, "data": {"message": "Push go to staging. Use validate + commit."}})

    @mcp.custom_route("/mcp/web/semantic/pull", methods=["GET"])
    async def api_semantic_pull(request: Request) -> Response:
        """CLI pull: download all active YAML files for a workspace as .tar.gz."""
        import io as _io, tarfile as _tarfile
        from starlette.responses import Response as _StarletteResponse
        client_id, _, err = await _check_semantic_access(request)
        if err:
            return err
        
        ws = _get_workspace_from_request(request)
        st = await asyncio.to_thread(_get_store, ws)
        files = await asyncio.to_thread(st.list_files)
        
        if not files:
            return _JSONResponse(
                {"success": False, "error": {"code": "NOT_FOUND", "message": f"No files in workspace '{ws}'"}},
                status_code=404,
            )
        
        buf = _io.BytesIO()
        with _tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for f in files:
                data = await asyncio.to_thread(st.get_file, f["filename"])
                if data and data.get("content"):
                    info = _tarfile.TarInfo(name=f["filename"])
                    content_bytes = data["content"].encode("utf-8")
                    info.size = len(content_bytes)
                    tar.addfile(info, _io.BytesIO(content_bytes))
        buf.seek(0)
        return _StarletteResponse(
            content=buf.getvalue(),
            media_type="application/gzip",
            headers={"Content-Disposition": f'attachment; filename="{ws}-models.tar.gz"'},
        )

    _SEMANTIC_LOGIN_HTML = """\
<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{SERVER_NAME}} — Login</title><style>
  :root { --bg: #f5f5f5; --card: #fff; --text: #333; --muted: #888;
          --link: #1a73e8; --danger: #d93025; --border: #ddd; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); display: flex;
         justify-content: center; align-items: center; min-height: 100vh; }
  .card { background: var(--card); border-radius: 12px; padding: 32px;
          box-shadow: 0 2px 8px rgba(0,0,0,.1); width: 100%; max-width: 400px; }
  h1 { font-size: 1.3rem; margin-bottom: 4px; }
  .sub { color: var(--muted); font-size: .85rem; margin-bottom: 20px; }
  label { display: block; font-size: .85rem; font-weight: 600; margin-bottom: 4px; }
  input { width: 100%; padding: 10px 12px; border: 1px solid var(--border);
          border-radius: 6px; font-size: 1rem; margin-bottom: 14px; }
  button { width: 100%; padding: 10px; background: var(--link); color: #fff;
           border: none; border-radius: 6px; font-size: 1rem; cursor: pointer; }
  button:hover { opacity: 0.9; }
  .error { background: #fce8e6; color: var(--danger); padding: 10px 14px;
           border-radius: 6px; margin-bottom: 16px; font-size: .85rem; }
</style></head><body><div class="card"><h1>{{SERVER_NAME}}</h1>
<p class="sub">Login with your Doris credentials</p>{{ERROR}}
<form method="post"><label>Username</label><input name="user" required autofocus>
<label>Password</label><input name="password" type="password">
<button type="submit">Sign in</button></form></div></body></html>"""

    def _render_login(error: str = "") -> str:
        err_html = f'<div class="error">{error}</div>' if error else ""
        return _SEMANTIC_LOGIN_HTML.replace("{{ERROR}}", err_html).replace("{{SERVER_NAME}}", cfg.mcp.name)

    @mcp.custom_route("/mcp/web/login", methods=["GET"])
    async def semantic_webui_login_page(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML
        # If already logged in, redirect to home
        session_cookie = _decode_webui_session_cookie(
            request.cookies.get(_WEBUI_SESSION_COOKIE)
        )
        if session_cookie:
            session_id, server_ip = session_cookie
            session = _webui_sessions.get(session_id)
            if (
                session
                and session["server_ip"] == server_ip
                and time.time() - session["created_at"] < _SESSION_TTL
            ):
                from starlette.responses import RedirectResponse as _R
                return _R("/mcp/web", status_code=303)
        return _HTML(_render_login())

    @mcp.custom_route("/mcp/web/login", methods=["POST"])
    async def semantic_webui_login_submit(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML, RedirectResponse as _R
        try:
            form = await request.form()
            user = _form_str(form, "user").strip()
            password = _form_str(form, "password")
        except Exception:
            return _HTML(_render_login("Invalid form submission."), status_code=400)

        if not user:
            return _HTML(_render_login("Username is required."), status_code=400)

        ok, is_admin = await asyncio.to_thread(_verify_doris_credentials, user, password)
        if not ok:
            return _HTML(_render_login(f"Authentication failed for user '{user}'. Check your credentials."), status_code=401)

        # Create session (any authenticated Doris user can log in)
        _prune_webui_sessions()
        session_id = _secrets.token_urlsafe(32)
        session_cookie_value = _encode_webui_session_cookie(session_id, _WEBUI_IP)
        _webui_sessions[session_id] = {
            "doris_user": user,
            "doris_password": password,
            "server_ip": _WEBUI_IP,
            "created_at": time.time(),
            "is_admin": is_admin,
        }
        logger.info(f"WebUI login: user='{user}', session={session_id[:8]}...")

        # seed_example is the startup default for the same WebUI switch.
        # Wait for a verified Admin login so its in-memory password can be used.
        if is_admin and cfg.mcp.seed_example and not _example_auto_seed_done:
            try:
                await _deploy_example(user, password)
                logger.info("Example deployment checked after Admin WebUI login")
            except Exception:
                logger.exception(
                    "Automatic example deployment failed; Admin can retry in WebUI"
                )

        resp = _R("/mcp/web", status_code=303)
        # Mark the cookie Secure when the request arrived over HTTPS —
        # directly, or via a TLS-terminating reverse proxy (X-Forwarded-Proto).
        secure_cookie = (
            request.url.scheme == "https"
            or request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower() == "https"
        )
        resp.set_cookie(
            _WEBUI_SESSION_COOKIE, session_cookie_value,
            httponly=True, samesite="lax", secure=secure_cookie, max_age=_SESSION_TTL,
            path="/mcp/web",
        )
        return resp

    @mcp.custom_route("/mcp/web/logout", methods=["GET"])
    async def semantic_webui_logout(request: Request) -> Response:
        from starlette.responses import RedirectResponse as _R
        session_cookie = _decode_webui_session_cookie(
            request.cookies.get(_WEBUI_SESSION_COOKIE)
        )
        if session_cookie:
            session_id, server_ip = session_cookie
            session = _webui_sessions.get(session_id)
            if session and session["server_ip"] == server_ip:
                _webui_sessions.pop(session_id, None)
        resp = _R("/mcp/web/login", status_code=303)
        resp.delete_cookie(_WEBUI_SESSION_COOKIE, path="/mcp/web")
        return resp

    # -- Semantic model pages --

    @mcp.custom_route("/mcp/web", methods=["GET"])
    async def semantic_webui_home(request: Request) -> Response:
        """Home: redirect to first available workspace models page."""
        from starlette.responses import RedirectResponse as _R
        client_id, _, err = await _check_semantic_access(request)
        if err:
            return err
        ws = request.query_params.get("workspace", "")
        if not ws:
            ws_names = multi_watcher.workspace_names()
            ws = ws_names[0] if ws_names else "example"
        return _R(f"/mcp/web/models?workspace={ws}", status_code=303)

    @mcp.custom_route("/mcp/web/models", methods=["GET"])
    async def semantic_webui_models(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML
        client_id, is_admin, err = await _check_semantic_access(request)
        if err:
            return err
        ws = _get_workspace_from_request(request)
        st = await asyncio.to_thread(_get_store, ws)

        flash = ""
        staged_q = request.query_params.get("staged")
        if staged_q:
            flash = f'<div class="flash flash-ok">📦 {staged_q} file(s) staged.</div>'

        files = await asyncio.to_thread(st.list_files)
        staging = await asyncio.to_thread(st.staging_list)
        staging_map = {s["filename"]: s for s in staging}

        # ---- Active panel ----
        active_body = '<div class="panel"><div class="panel-header"><h3>📁 Active Files</h3></div><div class="panel-body">'
        active_body += flash
        if not files:
            active_body += '<div class="empty">No models yet.</div>'
        else:
            rows = []
            for f in files:
                fname = f["filename"]
                st_info = staging_map.get(fname)
                tag = ""
                if st_info and st_info["action"] == "delete":
                    tag = ' <span class="tag tag-del">pending delete</span>'
                elif st_info and st_info["action"] == "upsert":
                    tag = ' <span class="tag tag-mod">pending update</span>'
                efname = _html_escape(fname)
                edit_link = f'<a class="btn btn-sm" href="/mcp/web/{efname}?workspace={ws}">edit</a>' if is_admin else ""
                del_link = f"<a class=\"btn btn-sm btn-danger\" href=\"/mcp/web/{efname}/delete?workspace={ws}\" onclick=\"return confirm('Mark for deletion?')\">🗑</a>" if is_admin else ""
                rows.append(
                    f'<tr><td class="filename"><a href="/mcp/web/{efname}?workspace={ws}">{efname}</a>{tag}</td>'
                    f'<td style="font-size:.75rem;color:var(--muted);">{f["updated_at"]}</td>'
                    f'<td>{round(f["size_bytes"]/1024,1)} KB</td>'
                    f'<td>{edit_link} {del_link}</td></tr>'
                )
            active_body += '<table><thead><tr><th>Filename</th><th>Updated</th><th>Size</th><th></th></tr></thead><tbody>' + "".join(rows) + '</tbody></table>'
        active_body += '</div></div>'

        # ---- Staging panel ----
        staging_body = f'<div class="panel"><div class="panel-header"><h3>📦 Staging</h3>'
        if is_admin:
            staging_body += (
                f'<form method="post" id="upload-form" action="/mcp/web/upload?workspace={ws}" enctype="multipart/form-data" style="display:inline;">'
                '<input type="file" name="files" multiple accept=".yml,.yaml" onchange="document.getElementById(\'upload-form\').submit()" style="display:none;" id="upload-input">'
                '</form>'
                f'<a class="btn btn-sm" href="/mcp/web/new?workspace={ws}">+ New</a>'
                '<label for="upload-input" class="btn btn-sm" style="cursor:pointer;">📤 Upload</label>'
            )
        if staging:
            staging_body += (
                "<button class=\"btn btn-sm btn-primary\" onclick=\"wsAction('/mcp/web/staging/validate','Validating')\">💡 Validate</button>"
                "<button class=\"btn btn-sm btn-success\" onclick=\"wsAction('/mcp/web/staging/commit','Committing')\">🚀 Commit</button>"
                "<button class=\"btn btn-sm btn-danger\" onclick=\"wsAction('/mcp/web/staging/discard','Discarding')\">🗑 Discard</button>"
            )
        staging_body += '</div><div class="panel-body">'
        
        if not staging:
            staging_body += '<div class="empty">No pending changes.</div>'
        else:
            srows = []
            for s in staging:
                srows.append(
                    f'<tr><td class="filename">{_html_escape(s["filename"])}</td>'
                    f'<td><span class="tag tag-{"del" if s["action"]=="delete" else "mod"}">{s["action"]}</span></td>'
                    f'<td style="font-size:.75rem;color:var(--muted);">{s["updated_at"]}</td></tr>'
                )
            staging_body += '<table><thead><tr><th>Filename</th><th>Action</th><th>When</th></tr></thead><tbody>' + "".join(srows) + '</tbody></table>'
        staging_body += '</div></div>'
        staging_body += '<div id="ws-result" class="result" style="display:none;margin-top:16px;"></div>'
        
        # Workspace status indicator
        ws_obj = multi_watcher.get_workspace(ws)
        if ws_obj and ws_obj.manifest:
            metrics = ws_obj.manifest.list_metrics()
            status_text = f"healthy · {len(metrics)} metrics"
            status_color = "color:#1e8e3e;"
        elif ws_obj and await asyncio.to_thread(ws_obj.store.list_files):
            status_text = "not ready"
            status_color = "color:#e37400;"
        else:
            status_text = "no models"
            status_color = "color:var(--muted);"
        if is_admin:
            from store.seed import is_example_deployed
            example_deployed = await asyncio.to_thread(is_example_deployed)
            if example_deployed:
                example_action_html = (
                    '<button class="btn btn-sm btn-danger" '
                    'onclick="exampleAction(false)">🗑 Delete example</button>'
                )
            else:
                example_action_html = (
                    '<button class="btn btn-sm btn-success" '
                    'onclick="exampleAction(true)">🧪 Deploy example</button>'
                )
            ws_actions_html = (
                '<span class="btn btn-sm" style="' + status_color + ';cursor:default;">' + status_text + '</span> '
                '<button class="btn btn-sm" onclick="wsAction(\'/mcp/web/semantic/reload\',\'Reloading\')">⟳ Reload</button>'
                + example_action_html
            )
        else:
            ws_actions_html = '<span class="btn btn-sm" style="' + status_color + ';cursor:default;">' + status_text + '</span>'
        body = "{{ACTIVE_PANEL}}" + active_body + "{{STAGING_PANEL}}" + staging_body
        html = _render_page(body, client_id, is_admin, ws, ws_actions_html)
        return _HTML(html)

    @mcp.custom_route("/mcp/web/new", methods=["GET"])
    async def semantic_webui_new(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML
        client_id, _, err = await _check_semantic_access(request, require_admin=True)
        if err:
            return err
        ws = _get_workspace_from_request(request)
        html = _render_page(_SEMANTIC_NEW_HTML.replace("{{WORKSPACE}}", ws), client_id, True, ws)
        return _HTML(html)

    # ── Web UI shell templates ──

    _WEBUI_STYLE = """  :root { --bg: #f0f2f5; --card: #fff; --text: #333; --muted: #888;
          --link: #1a73e8; --danger: #d93025; --border: #ddd; --green: #1e8e3e; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: var(--bg); color: var(--text); }
  .topbar { display: flex; align-items: center; gap: 16px; padding: 12px 24px;
            background: var(--card); border-bottom: 1px solid var(--border); }
  .topbar h1 { font-size: 1.2rem; flex: 1; }
  .btn { padding: 6px 14px; border: 1px solid var(--border); border-radius: 6px;
         background: var(--card); cursor: pointer; font-size: .82rem; text-decoration: none;
         color: var(--text); display: inline-block; white-space: nowrap; }
  .btn:hover { background: #e8e8e8; }
  .btn-primary { background: var(--link); color: #fff; border-color: var(--link); }
  .btn-primary:hover { background: #1557b0; }
  .btn-success { background: var(--green); color: #fff; border-color: var(--green); }
  .btn-success:hover { background: #166b2e; }
  .btn-danger { color: var(--danger); border-color: var(--danger); }
  .btn-danger:hover { background: #fce8e6; }
  .btn-sm { padding: 6px 14px; font-size: .85rem; }
  .topbar select { padding: 6px 12px; border: 1px solid var(--border); border-radius: 6px; font-size: .85rem; min-width: 200px; background: var(--card); }
  .ws-bar select { padding: 6px 10px; border: 1px solid var(--border); border-radius: 6px; font-size: .85rem; min-width: 180px; }
  .main { display: grid; grid-template-columns: 1fr 1fr; gap: 24px; padding: 24px; }
  .panel { background: var(--card); border-radius: 10px; box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow: hidden; }
  .panel-header { display: flex; align-items: center; gap: 8px; padding: 14px 20px; border-bottom: 1px solid var(--border); background: #fafbfc; flex-wrap: wrap; }
  .panel-header h3 { font-size: .95rem; flex: 1; }
  .panel-body { padding: 16px 20px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid var(--border); font-size: .85rem; }
  th { color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase; }
  tr:hover { background: #f0f7ff; }
  .filename { font-family: 'SF Mono', Monaco, monospace; }
  .tag { display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: .7rem; font-weight: 600; }
  .tag-del { background: #fce8e6; color: var(--danger); }
  .tag-mod { background: #fef7e0; color: #e37400; }
  .tag-new { background: #e6f4ea; color: var(--green); }
  .flash { padding: 8px 15px; border-radius: 6px; margin-bottom: 12px; font-size: .85rem; }
  .flash-ok { background: #e6f4ea; color: var(--green); }
  .flash-err { background: #fce8e6; color: var(--danger); }
  .result { margin-top: 8px; padding: 10px; background: #f5f5f5; border-radius: 6px;
            font-family: monospace; font-size: .8rem; white-space: pre-wrap; max-height: 200px; overflow: auto; display: none; }
  .empty { text-align: center; padding: 30px; color: var(--muted); font-size: .85rem; }
  .editor-wrap { padding: 20px; }
  .editor-wrap textarea { width: 100%; min-height: 400px; font-family: 'SF Mono', Monaco, monospace;
             font-size: .85rem; padding: 12px; border: 1px solid var(--border); border-radius: 6px; resize: vertical; }
  .meta { color: var(--muted); font-size: .8rem; margin-bottom: 12px; }
  .actions { display: flex; gap: 8px; margin-top: 12px; }
"""

    _WEBUI_SHELL = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{SERVER_NAME}}</title><style>{{STYLE}}</style></head><body>
<div class="topbar">
  <a href="/mcp/web" style="font-size:1.2rem;font-weight:700;color:var(--text);text-decoration:none;">📋 {{SERVER_NAME}}</a>
  {{WORKSPACE_SELECTOR}}
  {{CREATE_WS_BTN}}
  {{DELETE_WS_BTN}}
  {{WS_ACTIONS}}
  <span style="flex:1;"></span>
  <span style="font-size:.82rem;color:var(--muted);">{{USER}}</span>
  <a class="btn btn-sm" href="/mcp/web/logout">🚪 Logout</a>
</div>
<div class="main">
  {{ACTIVE_PANEL}}
  {{STAGING_PANEL}}
</div>
<script>
function switchWorkspace(sel) { var u=new URL(window.location);u.searchParams.set("workspace",sel.value);window.location=u.toString(); }
function createWorkspace() { var n=prompt("New workspace name (letters, numbers, underscores only):"); if(n) { fetch("/mcp/web/workspace/create",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:n})}).then(r=>r.json()).then(d=>{if(d.success)location.reload();else alert(d.error?d.error.message:"Failed")}); } }
function deleteWorkspace(n) { if(confirm("Delete workspace '"+n+"' and all its models?")) { fetch("/mcp/web/workspace/delete",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({workspace:n})}).then(r=>r.json()).then(d=>{if(d.success)location.href="/mcp/web";else alert(d.error?d.error.message:"Failed")}); } }
function fetchJson(url,opts) {
  return fetch(url,opts).then(function(r){
    var ct=r.headers.get("content-type")||"";
    if(ct.indexOf("json")===-1){throw new Error("Request failed (HTTP "+r.status+"), please retry.");}
    return r.json();
  });
}
function exampleAction(deploy) {
  if (!deploy && !confirm("Delete example models and all four sample data tables?")) return;
  var el=document.getElementById("ws-result");
  var label=deploy?"Deploying example":"Deleting example";
  if(el){el.textContent="⏳ "+label+"...";el.style.display="block";el.style.background="";}
  fetchJson("/mcp/web/example/deployment",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({deploy:deploy})
  }).then(function(d){
    if(!d.success){throw new Error(d.error?d.error.message:"Failed");}
    pollExampleStatus(el,0);
  }).catch(function(e){
    if(el){el.textContent="❌ "+e.message;el.style.background="#fce8e6";}else alert(e.message);
  });
}
function pollExampleStatus(el,n) {
  fetchJson("/mcp/web/example/deployment/status").then(function(d){
    if(!d.success){throw new Error(d.error?d.error.message:"Failed");}
    var st=d.data.status;
    if(st==="running"||st==="idle"){
      if(el){el.textContent="⏳ "+(d.data.message||"Working...")+" ("+(n*2)+"s)";}
      if(n<150){setTimeout(function(){pollExampleStatus(el,n+1);},2000);}
      else if(el){el.textContent="❌ Timed out waiting; refresh the page to check.";el.style.background="#fce8e6";}
      return;
    }
    if(st==="failed"){if(el){el.textContent="❌ "+(d.data.message||"Failed");el.style.background="#fce8e6";}return;}
    if(el){el.textContent="✅ "+d.data.message;el.style.background="#e6f4ea";}
    setTimeout(function(){location.href=d.data.redirect||"/mcp/web";},800);
  }).catch(function(e){
    if(el){el.textContent="❌ "+e.message;el.style.background="#fce8e6";}
  });
}
function wsAction(url,label) {
  var ws=new URLSearchParams(window.location.search).get("workspace")||"example";
  var el=document.getElementById("ws-result");
  el.textContent="⏳ "+label+"..."; el.style.display="block";
  fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({workspace:ws})})
    .then(r=>r.json()).then(d=>{
        var ok = d.success && d.data && d.data.valid !== false;
        var icon = ok ? "✅ " : "❌ ";
        var msg = "";
        if (d.error) { msg = d.error.message; }
        else if (d.data && d.data.valid!==undefined) {
          // validate response: show message (pass or fail details)
          msg = d.data.message || (ok ? "Validation passed" : "Validation failed");
        }
        else { msg = d.success ? "Done" : (d.data&&d.data.message||"Failed"); }
        el.style.background = ok ? "#e6f4ea" : "#fce8e6";
        el.innerHTML = "<strong>" + icon + "</strong>" + msg.replace(/</g,"&lt;").replace(/\\n/g,"<br>");
        if (d.success && d.data && d.data.valid === undefined) setTimeout(function(){location.reload()},1500);
      })
    .catch(e=>{el.textContent="❌ "+e;});
}
</script>
</body></html>"""

    def _html_escape(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")

    def _render_page(body: str, client_id: str | None = None, is_admin: bool = True, workspace: str = "example",
                     ws_actions: str = "") -> str:
        prefix = "👑 " if is_admin else "👤 "
        user_display = prefix + (client_id or "")
        ws_names = multi_watcher.workspace_names()
        ws_options = ""
        for w in ws_names:
            sel = ' selected' if w == workspace else ''
            ws_options += f'<option value="{w}"{sel}>{w}</option>'
        ws_selector = f'<select onchange="switchWorkspace(this)">{ws_options}</select>'
        create_ws_btn = '<button class="btn btn-sm" onclick="createWorkspace()">+ New Workspace</button>' if is_admin else ""
        delete_ws_btn = f'<button class="btn btn-sm btn-danger" onclick="deleteWorkspace(\'{workspace}\')" style="margin-left:4px;">🗑</button>' if is_admin and workspace != "example" else ""
        body = body.replace("{{WORKSPACE}}", workspace)
        html = _WEBUI_SHELL
        html = html.replace("{{SERVER_NAME}}", cfg.mcp.name)
        html = html.replace("{{STYLE}}", _WEBUI_STYLE)
        html = html.replace("{{USER}}", user_display)
        html = html.replace("{{WORKSPACE_SELECTOR}}", ws_selector)
        html = html.replace("{{CREATE_WS_BTN}}", create_ws_btn)
        html = html.replace("{{DELETE_WS_BTN}}", delete_ws_btn)
        html = html.replace("{{WS_ACTIONS}}", ws_actions)
        parts = body.split("{{STAGING_PANEL}}")
        if len(parts) == 2:
            html = html.replace("{{ACTIVE_PANEL}}", parts[0].replace("{{ACTIVE_PANEL}}", ""))
            html = html.replace("{{STAGING_PANEL}}", parts[1])
        else:
            html = html.replace("{{ACTIVE_PANEL}}", body)
            html = html.replace("{{STAGING_PANEL}}", "")
        if not is_admin:
            html = html.replace('class="btn btn-danger', 'style="display:none" class="btn btn-danger')
        return html

    _SEMANTIC_EDIT_HTML = """\
<div class="panel"><div class="panel-header"><h3>Edit: {{FNAME}}</h3></div><div class="panel-body editor-wrap">
<div class="meta">Last updated: {{UPDATED}}</div>
<form method="post" action="/mcp/web/{{FNAME}}/save?workspace={{WORKSPACE}}">
<textarea name="content" spellcheck="false">{{CONTENT}}</textarea>
<div class="actions">
<button class="btn btn-primary" type="submit">💾 Save</button>
<a class="btn" href="/mcp/web/models?workspace={{WORKSPACE}}">Cancel</a>
<a class="btn btn-danger btn-sm" href="/mcp/web/{{FNAME}}/delete?workspace={{WORKSPACE}}"
   onclick="return confirm('Mark for deletion?')">🗑 Delete</a>
</div></form></div></div>"""

    _SEMANTIC_NEW_HTML = """\
<div class="panel"><div class="panel-header"><h3>New File</h3></div><div class="panel-body editor-wrap">
<form method="post" action="/mcp/web/create?workspace={{WORKSPACE}}">
<p style="margin-bottom:8px;"><label>Filename: <input name="filename" required placeholder="e.g. orders.yaml"
   style="padding:6px 10px;border:1px solid var(--border);border-radius:4px;width:300px;"></label></p>
<textarea name="content" spellcheck="false" placeholder="# Paste YAML..."></textarea>
<div class="actions">
<button class="btn btn-primary" type="submit">💾 Create</button>
<a class="btn" href="/mcp/web/models?workspace={{WORKSPACE}}">Cancel</a>
</div></form></div></div>"""

    # -- Create / Delete / Save (specific routes, MUST be before {filename:path}) --

    @mcp.custom_route("/mcp/web/{filename:path}/delete", methods=["GET"])
    async def semantic_webui_delete(request: Request) -> Response:
        from starlette.responses import RedirectResponse as _Redirect
        client_id, err = await _check_admin_access(request)
        if err:
            return err

        ws = _get_workspace_from_request(request)
        filename = request.path_params["filename"]
        if filename.endswith("/delete"):
            filename = filename[:-len("/delete")]

        # Check cross-file dependencies before staging the delete
        from tools.dependency import check_delete_dependencies
        store = await asyncio.to_thread(_get_store, ws)
        file_info = await asyncio.to_thread(store.get_file, filename)
        if file_info and file_info.get("content"):
            active_files = {}
            for f in await asyncio.to_thread(store.list_files):
                f_info = await asyncio.to_thread(store.get_file, f["filename"])
                if f_info and f_info.get("content"):
                    active_files[f["filename"]] = f_info["content"]
            errors = check_delete_dependencies(filename, file_info["content"], active_files)
            if errors:
                from starlette.responses import HTMLResponse as _HTML
                body = "<h2>Cannot Delete</h2><ul>" + "".join(f"<li>{e}</li>" for e in errors) + "</ul>"
                return _HTML(_render_page(body, client_id, True, ws), status_code=409)

        action = await asyncio.to_thread(store.staging_delete, filename)
        return _Redirect(f"/mcp/web/models?workspace={ws}&staged=1", status_code=303)

    @mcp.custom_route("/mcp/web/{filename:path}/save", methods=["POST"])
    async def semantic_webui_save(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML, RedirectResponse as _Redirect
        client_id, err = await _check_admin_access(request)
        if err:
            return err

        filename = request.path_params["filename"]
        if filename.endswith("/save"):
            filename = filename[:-len("/save")]
        ws = _get_workspace_from_request(request)
        try:
            form = await request.form()
            content = _form_str(form, "content")
            st = await asyncio.to_thread(_get_store, ws)
            await asyncio.to_thread(st.staging_upsert, filename, content)
            return _Redirect(f"/mcp/web/models?workspace={ws}", status_code=303)
        except Exception as e:
            body = f'<div class="flash flash-err">Save failed: {e}</div>'
            html = _render_page(body, client_id, True, ws)
            return _HTML(html, status_code=500)

    @mcp.custom_route("/mcp/web/create", methods=["POST"])
    async def semantic_webui_create(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML, RedirectResponse as _Redirect
        client_id, err = await _check_admin_access(request)
        if err:
            return err

        ws = _get_workspace_from_request(request)
        try:
            form = await request.form()
            filename = _form_str(form, "filename").strip()
            content = _form_str(form, "content")
            if not filename:
                body = '<div class="flash flash-err">Filename is required</div>'
                html = _render_page(body, client_id, True, ws)
                return _HTML(html, status_code=400)
            if not filename.endswith((".yml", ".yaml")):
                filename += ".yaml"
            st = await asyncio.to_thread(_get_store, ws)
            await asyncio.to_thread(st.staging_upsert, filename, content)
            return _Redirect(f"/mcp/web/models?workspace={ws}", status_code=303)
        except Exception as e:
            body = f'<div class="flash flash-err">Create failed: {e}</div>'
            html = _render_page(body, client_id, True, ws)
            return _HTML(html, status_code=500)

    # -- Upload files (multipart form) --

    @mcp.custom_route("/mcp/web/upload", methods=["POST"])
    async def semantic_webui_upload(request: Request) -> Response:
        from starlette.responses import RedirectResponse as _Redirect
        client_id, err = await _check_admin_access(request)
        if err:
            return err

        try:
            form = await request.form()
        except Exception:
            return _Redirect("/mcp/web?error=invalid_form", status_code=303)

        ws = request.query_params.get("workspace", "example")
        uploaded = 0
        skipped = 0
        for _, upload in form.multi_items():
            if not isinstance(upload, _UploadFile) or not upload.filename:
                continue
            filename = upload.filename
            if ".." in filename or "/" in filename or "\\" in filename:
                skipped += 1
                continue
            if not filename.endswith((".yml", ".yaml")):
                skipped += 1
                continue
            content = await upload.read()
            if len(content) > 1 * 1024 * 1024:
                skipped += 1
                continue
            try:
                text = content.decode("utf-8")
            except UnicodeDecodeError:
                skipped += 1
                continue
            st = await asyncio.to_thread(_get_store, ws)
            await asyncio.to_thread(st.staging_upsert, filename, text)
            uploaded += 1

        logger.info(f"WebUI upload: {uploaded} files staged, {skipped} skipped by {client_id}")
        return _Redirect(f"/mcp/web/models?workspace={ws}&staged={uploaded}&skipped={skipped}", status_code=303)

    # -- Staging API (validate / commit / discard) --

    @mcp.custom_route("/mcp/web/staging/list", methods=["GET"])
    async def api_staging_list(request: Request) -> Response:
        client_id, _, err = await _check_semantic_access(request)
        if err:
            return err
        ws = _get_workspace_from_request(request)
        st = await asyncio.to_thread(_get_store, ws)
        files = await asyncio.to_thread(st.staging_list)
        return _JSONResponse({"success": True, "data": files})

    @mcp.custom_route("/mcp/web/staging/validate", methods=["POST"])
    async def api_staging_validate(request: Request) -> Response:
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            body = {}
        ws = body.get("workspace", "example")
        valid, msg, details = await asyncio.to_thread(multi_watcher.validate_staging, ws)
        log_tool_call("staging_validate", client_id=client_id,
                      params={"valid": valid, "workspace": ws}, success=valid, duration_ms=0)
        return _JSONResponse({"success": True, "data": {"valid": valid, "message": msg, "details": details}})

    @mcp.custom_route("/mcp/web/staging/commit", methods=["POST"])
    async def api_staging_commit(request: Request) -> Response:
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            body = {}
        ws = body.get("workspace", "example")
        ok, msg = await asyncio.to_thread(multi_watcher.commit_staging, ws)
        log_tool_call("staging_commit", client_id=client_id,
                      params={"workspace": ws}, success=ok, duration_ms=0)
        return _JSONResponse({"success": ok, "data": {"message": msg}})

    @mcp.custom_route("/mcp/web/staging/discard", methods=["POST"])
    async def api_staging_discard(request: Request) -> Response:
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            body = {}
        ws = body.get("workspace", "example")
        st = await asyncio.to_thread(_get_store, ws)
        await asyncio.to_thread(st.staging_discard)
        log_tool_call("staging_discard", client_id=client_id,
                      params={"workspace": ws}, success=True, duration_ms=0)
        return _JSONResponse({"success": True, "data": {"message": "Staging discarded"}})

    # ---- Semantic toggle via WebUI form ----
    # ---- Semantic Management API (for CLI, MUST be before {filename:path}) ----

    @mcp.custom_route("/mcp/web/semantic/files", methods=["GET"])
    async def api_semantic_list_files(request: Request) -> Response:
        client_id, _, err = await _check_semantic_access(request)
        if err:
            return err
        ws = _get_workspace_from_request(request)
        st = await asyncio.to_thread(_get_store, ws)
        files = await asyncio.to_thread(st.list_files)
        return _JSONResponse({"success": True, "data": files})

    @mcp.custom_route("/mcp/web/semantic/files/{filename:path}", methods=["GET"])
    async def api_semantic_get_file(request: Request) -> Response:
        client_id, _, err = await _check_semantic_access(request)
        if err:
            return err
        ws = _get_workspace_from_request(request)
        filename = request.path_params["filename"]
        st = await asyncio.to_thread(_get_store, ws)
        data = await asyncio.to_thread(st.get_file, filename)
        if data is None:
            return _JSONResponse(
                {"success": False, "error": {"code": "NOT_FOUND", "message": f"File not found: {filename}"}},
                status_code=404,
            )
        return _JSONResponse({"success": True, "data": data})

    @mcp.custom_route("/mcp/web/semantic/files", methods=["POST"])
    async def api_semantic_save_file(request: Request) -> Response:
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        try:
            body = await request.json()
        except Exception:
            return _JSONResponse(
                {"success": False, "error": {"code": "BAD_REQUEST", "message": "Invalid JSON"}},
                status_code=400,
            )
        filename = (body.get("filename", "") or "").strip()
        content = body.get("content", "")
        if not filename or ".." in filename or "/" in filename or "\\" in filename:
            return _JSONResponse(
                {"success": False, "error": {"code": "VALIDATION_ERROR", "message": "Invalid filename"}},
                status_code=400,
            )
        if not filename.endswith((".yml", ".yaml")):
            filename += ".yaml"
        ws = body.get("workspace", "example")
        st = await asyncio.to_thread(_get_store, ws)
        await asyncio.to_thread(st.staging_upsert, filename, content)
        log_tool_call("semantic_save", client_id=client_id,
                      params={"filename": filename}, success=True, duration_ms=0)
        return _JSONResponse({"success": True, "data": {"filename": filename, "staged": True}})

    @mcp.custom_route("/mcp/web/semantic/files/{filename:path}", methods=["DELETE"])
    async def api_semantic_delete_file(request: Request) -> Response:
        client_id, err = await _check_admin_access(request)
        if err:
            return err
        ws = _get_workspace_from_request(request)
        filename = request.path_params["filename"]

        # Check cross-file dependencies before staging the delete
        from tools.dependency import check_delete_dependencies
        store = await asyncio.to_thread(_get_store, ws)
        file_info = await asyncio.to_thread(store.get_file, filename)
        if file_info and file_info.get("content"):
            active_files = {}
            for f in await asyncio.to_thread(store.list_files):
                f_info = await asyncio.to_thread(store.get_file, f["filename"])
                if f_info and f_info.get("content"):
                    active_files[f["filename"]] = f_info["content"]
            errors = check_delete_dependencies(filename, file_info["content"], active_files)
            if errors:
                log_tool_call("semantic_delete", client_id=client_id,
                              params={"filename": filename}, success=False, duration_ms=0)
                return _JSONResponse(
                    {"success": False, "error": {"code": "DEPENDENCY_CONFLICT", "message": errors}},
                    status_code=409,
                )

        action = await asyncio.to_thread(store.staging_delete, filename)
        log_tool_call("semantic_delete", client_id=client_id,
                      params={"filename": filename, "action": action}, success=True, duration_ms=0)
        return _JSONResponse({"success": True, "data": {"filename": filename, "action": action}})
    # -- Edit file (must be AFTER all specific routes) --

    @mcp.custom_route("/mcp/web/{filename:path}", methods=["GET"])
    async def semantic_webui_edit(request: Request) -> Response:
        from starlette.responses import HTMLResponse as _HTML
        client_id, is_admin, err = await _check_semantic_access(request)
        if err:
            return err

        filename = request.path_params.get("filename", "")
        ws = _get_workspace_from_request(request)
        st = await asyncio.to_thread(_get_store, ws)
        file_data = await asyncio.to_thread(st.get_file, filename)
        if file_data is None:
            body = f'<div class="flash flash-err">File not found: {filename}</div>'
        else:
            body = (
                _SEMANTIC_EDIT_HTML
                .replace("{{FNAME}}", filename)
                .replace("{{UPDATED}}", file_data["updated_at"])
                .replace("{{CONTENT}}", file_data["content"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
            )
            if not is_admin:
                body = body.replace("<button class=\"btn\" type=\"submit\"", "<button class=\"btn\" type=\"submit\" disabled")
                body = body.replace("🗑 Delete</a>", "")
        html = _render_page(body, client_id, is_admin, ws)
        return _HTML(html)

    return mcp

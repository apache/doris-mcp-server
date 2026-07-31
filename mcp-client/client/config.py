"""Resolve server URL and bearer token.

Two modes (no fallback between them):
  - Config file: ``--config`` argument (TOML)
  - Environment: ``DORIS_MCP_SERVER`` + ``DORIS_MCP_TOKEN``
"""

from __future__ import annotations

import os
from pathlib import Path

import tomli as tomllib


# Module-level config path (set by CLI callback via --config)
_cli_config_path: str | None = None


def set_config_path(path: str | None) -> None:
    """Set explicit config file path from CLI --config option."""
    global _cli_config_path
    _cli_config_path = path


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _get_env(name: str) -> str | None:
    val = os.environ.get(name)
    if val is None:
        return None
    val = val.strip()
    return val if val else None


def _load_toml_config(path: str) -> dict | None:
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError):
        return None


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def resolve_token() -> tuple[str, str]:
    """Return (server_url, token), raising RuntimeError if nothing configured."""
    if _cli_config_path:
        # Config file mode
        p = Path(_cli_config_path)
        if not p.is_file():
            raise RuntimeError(f"Config file not found: {_cli_config_path}")
        toml = _load_toml_config(_cli_config_path)
        if not toml:
            raise RuntimeError(f"Failed to parse config file: {_cli_config_path}")
        url = toml.get("server", {}).get("DORIS_MCP_SERVER")
        token = toml.get("server", {}).get("DORIS_MCP_TOKEN")
        if not url or not token:
            raise RuntimeError(
                f"Config file {_cli_config_path} must contain [server] DORIS_MCP_SERVER and DORIS_MCP_TOKEN."
            )
        return url.rstrip("/"), token

    # Environment variables mode
    env_token = _get_env("DORIS_MCP_TOKEN")
    env_url = _get_env("DORIS_MCP_SERVER")
    if env_token and env_url:
        return env_url.rstrip("/"), env_token

    raise RuntimeError(
        "No server configured. "
        "Use --config <path> or set DORIS_MCP_SERVER + DORIS_MCP_TOKEN."
    )

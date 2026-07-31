"""Configuration loader with env var interpolation (TOML)."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import tomli as tomllib

from dotenv import load_dotenv

_ENV_PATTERN = re.compile(r"\$\{(\w+)\}")


def _interpolate_env(value: Any) -> Any:
    if isinstance(value, str):
        def _replace(m: re.Match) -> str:
            var = m.group(1)
            env_val = os.environ.get(var)
            if env_val is None:
                return m.group(0)
            return env_val
        return _ENV_PATTERN.sub(_replace, value)
    if isinstance(value, dict):
        return {k: _interpolate_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interpolate_env(v) for v in value]
    return value


def load_toml(path: str | Path) -> dict:
    with open(path, "rb") as f:
        data = tomllib.load(f)
    return _interpolate_env(data)


class McpConfig:
    def __init__(self, data: dict):
        srv = data.get("server", {})
        self.name: str = srv.get("mcp_name", "doris-new-mcp")
        self.host: str = srv.get("mcp_host", "0.0.0.0")
        self.port: int = srv.get("mcp_port", 3000)

        # `privateIp` is the documented key; retain `private_ip` for legacy configs.
        private_ip = srv.get("privateIp", srv.get("private_ip", ""))
        if private_ip is None:
            private_ip = ""
        if not isinstance(private_ip, str):
            raise ValueError("server.privateIp must be a string or null")
        self.private_ip: str = private_ip.strip()

        log = data.get("logging", {})
        self.log_level: str = log.get("level", "info")
        self.audit_log_path: str = log.get("audit_log", "./logs/audit.log")
        self.log_rotation_when: str = log.get("rotation_when", "midnight")
        self.log_rotation_backup_count: int = log.get("rotation_backup_count", 30)

        _WHEN = {"S", "M", "H", "D", "midnight", "W0", "W1", "W2", "W3", "W4", "W5", "W6"}
        if self.log_rotation_when not in _WHEN:
            raise ValueError(f"Invalid rotation_when: '{self.log_rotation_when}'")

        self.seed_example: bool = srv.get("seed_example", False)

        admin_users = srv.get("admin_users", ["admin"])
        if not isinstance(admin_users, list) or not all(isinstance(u, str) for u in admin_users):
            raise ValueError("server.admin_users must be a list of strings")
        self.admin_users: list[str] = admin_users


class ClusterConfig:
    def __init__(self, server: dict, query: dict):
        self.fe_host: str = server.get("fe_host", "127.0.0.1")
        self.fe_mysql_port: int = server.get("fe_port", 9030)
        self.user_name: str = server.get("fe_user", "admin")
        self.user_password: str = server.get("fe_password", "")
        self.pool_min_size: int = query.get("pool_min_size", 0)
        self.pool_max_size: int = query.get("pool_max_size", 10)
        self.pool_idle_timeout: int = query.get("pool_idle_timeout_seconds", 300)
        self.query_timeout: int = query.get("query_timeout_seconds", 600)
        self.max_rows: int = query.get("query_max_rows", 10000)
        self.db_whitelist: list[str] = query.get("db_whitelist", []) or []


class AppConfig:
    def __init__(self, config_dir: str | Path = "config", env_file: str | Path | None = None):
        config_dir = Path(config_dir)
        if env_file:
            env_path = Path(env_file)
            if env_path.exists():
                load_dotenv(env_path, override=True)
            else:
                raise FileNotFoundError(f"Env file not found: {env_path}")

        toml_path = config_dir / "mcp-server.toml"
        yaml_path = config_dir / "mcp-server.yaml"
        if toml_path.exists():
            data = load_toml(toml_path)
        elif yaml_path.exists():
            import yaml
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f) or {}
            data = _interpolate_env(data)
        else:
            data = {}

        self.mcp = McpConfig(data)
        self.cluster = ClusterConfig(data.get("server", {}), data.get("query", {}) or {})
        self.active_store = data.get("active_store", {}) or {}
        self.auth = None

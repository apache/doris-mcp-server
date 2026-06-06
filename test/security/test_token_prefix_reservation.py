import json

import pytest

from doris_mcp_server.auth.token_manager import TokenManager
from doris_mcp_server.utils.config import DorisConfig


def _config(tmp_path):
    config = DorisConfig()
    config.security.token_file_path = str(tmp_path / "tokens.json")
    return config


@pytest.mark.asyncio
async def test_token_file_rejects_reserved_doris_oauth_prefix(tmp_path):
    config = _config(tmp_path)
    with open(config.security.token_file_path, "w", encoding="utf-8") as f:
        json.dump({"tokens": [{"token_id": "bad", "token": "doa_bad"}]}, f)

    with pytest.raises(ValueError, match="reserved Doris OAuth prefix"):
        TokenManager(config)


@pytest.mark.asyncio
async def test_env_token_rejects_reserved_doris_oauth_prefix(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.setenv("TOKEN_BAD", "doa_bad")

    with pytest.raises(ValueError, match="reserved Doris OAuth prefix"):
        TokenManager(config)


@pytest.mark.asyncio
async def test_create_token_rejects_reserved_doris_oauth_prefix(tmp_path):
    config = _config(tmp_path)
    with open(config.security.token_file_path, "w", encoding="utf-8") as f:
        json.dump({"tokens": []}, f)
    manager = TokenManager(config)
    try:
        with pytest.raises(ValueError, match="reserved Doris OAuth prefix"):
            await manager.create_token("bad", custom_token="doa_bad")
    finally:
        manager.stop_hot_reload()

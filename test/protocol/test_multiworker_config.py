import json

import pytest

from doris_mcp_server import __version__
from doris_mcp_server.main import _multiworker_environment
from doris_mcp_server.multiworker_app import health_check, root_info
from doris_mcp_server.utils.config import DorisConfig


def test_multiworker_environment_preserves_resolved_parent_config(monkeypatch):
    config = DorisConfig()
    config.database.host = "127.0.0.1"
    config.database.port = 19030
    config.database.user = "loader"
    config.database.password = "test-password"
    config.database.database = "hhm_dt_sim"
    config.server_name = "doris-mcp-server"

    worker_env = _multiworker_environment(
        config,
        host="127.0.0.1",
        port=31133,
        workers=2,
    )
    assert "SERVER_VERSION" not in worker_env
    monkeypatch.setenv("SERVER_VERSION", "9.9.9")
    for key, value in worker_env.items():
        monkeypatch.setenv(key, value)

    child_config = DorisConfig.from_env()
    assert child_config.database.host == "127.0.0.1"
    assert child_config.database.port == 19030
    assert child_config.database.user == "loader"
    assert child_config.database.password == "test-password"
    assert child_config.database.database == "hhm_dt_sim"
    assert child_config.server_host == "127.0.0.1"
    assert child_config.server_port == 31133
    assert child_config.server_name == "doris-mcp-server"
    assert child_config.server_version == __version__
    assert child_config.transport == "http"
    assert child_config.workers == 2


@pytest.mark.asyncio
async def test_multiworker_http_identity_reports_product_version():
    for handler in (health_check, root_info):
        response = await handler(None)
        payload = json.loads(response.body)
        assert payload["service"] == "doris-mcp-server"
        assert payload["version"] == __version__
        assert "mcp_version" not in payload

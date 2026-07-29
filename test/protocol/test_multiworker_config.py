from doris_mcp_server.main import _multiworker_environment
from doris_mcp_server.utils.config import DorisConfig


def test_multiworker_environment_preserves_resolved_parent_config(monkeypatch):
    config = DorisConfig()
    config.database.host = "127.0.0.1"
    config.database.port = 19030
    config.database.user = "loader"
    config.database.password = "test-password"
    config.database.database = "hhm_dt_sim"
    config.server_name = "doris-mcp-server"
    config.server_version = "0.6.1"

    worker_env = _multiworker_environment(
        config,
        host="127.0.0.1",
        port=31133,
        workers=2,
    )
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
    assert child_config.server_version == "0.6.1"
    assert child_config.transport == "http"
    assert child_config.workers == 2

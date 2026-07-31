import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest
from starlette.responses import Response

from doris_mcp_server import __version__
from doris_mcp_server.main import _multiworker_environment
from doris_mcp_server.multiworker_app import (
    health_check,
    live_check,
    readiness_check,
    root_info,
)
from doris_mcp_server.utils.config import DorisConfig


def test_legacy_http_adapter_is_default_off_and_requires_explicit_env(monkeypatch):
    monkeypatch.delenv("ENABLE_LEGACY_HTTP_ADAPTER", raising=False)
    assert DorisConfig.from_env().enable_legacy_http_adapter is False

    monkeypatch.setenv("ENABLE_LEGACY_HTTP_ADAPTER", "true")
    enabled = DorisConfig.from_env()
    assert enabled.enable_legacy_http_adapter is True
    assert enabled.to_dict()["enable_legacy_http_adapter"] is True


def test_mcp_list_page_size_is_configurable_and_bounded(monkeypatch):
    monkeypatch.delenv("MCP_LIST_PAGE_SIZE", raising=False)
    assert DorisConfig.from_env().mcp_list_page_size == 100

    monkeypatch.setenv("MCP_LIST_PAGE_SIZE", "17")
    configured = DorisConfig.from_env()
    assert configured.mcp_list_page_size == 17
    assert configured.to_dict()["mcp_list_page_size"] == 17
    assert configured.validate() == []

    configured.mcp_list_page_size = 0
    assert "MCP list page size must be in the range 1-1000" in configured.validate()
    configured.mcp_list_page_size = 1001
    assert "MCP list page size must be in the range 1-1000" in configured.validate()


def test_custom_tool_provider_allowlist_is_explicit_and_validated(monkeypatch):
    monkeypatch.delenv("MCP_TOOL_PROVIDERS", raising=False)
    assert DorisConfig.from_env().mcp_tool_providers == []

    monkeypatch.setenv("MCP_TOOL_PROVIDERS", "orders_api, customer-tools")
    configured = DorisConfig.from_env()
    assert configured.mcp_tool_providers == ["orders_api", "customer-tools"]
    assert configured.to_dict()["mcp_tool_providers"] == [
        "orders_api",
        "customer-tools",
    ]
    assert configured.validate() == []

    configured.mcp_tool_providers = ["orders_api", "orders_api"]
    assert (
        "Duplicate custom tool provider in allowlist: orders_api"
        in configured.validate()
    )
    configured.mcp_tool_providers = ["bad/provider"]
    assert any(
        error.startswith("Custom tool provider names must contain")
        for error in configured.validate()
    )
    configured.mcp_tool_providers = "orders_api"  # type: ignore[assignment]
    assert "MCP tool providers must be a list" in configured.validate()


def test_tool_exposure_mode_is_explicit_validated_and_serialized(
    monkeypatch,
) -> None:
    monkeypatch.delenv("MCP_TOOL_EXPOSURE_MODE", raising=False)
    configured = DorisConfig.from_env()
    assert configured.tool_exposure.mode == "hierarchical"

    monkeypatch.setenv("MCP_TOOL_EXPOSURE_MODE", "flat")
    configured = DorisConfig.from_env()
    assert configured.tool_exposure.mode == "flat"
    assert configured.to_dict()["tool_exposure"] == {"mode": "flat"}
    assert configured.get_config_summary()["tool_exposure"] == {
        "mode": "flat"
    }
    assert configured.validate() == []

    configured.tool_exposure.mode = "legacy"
    assert (
        "MCP tool exposure mode must be hierarchical or flat"
        in configured.validate()
    )


def test_tool_exposure_mode_loads_from_json_config(tmp_path) -> None:
    config_path = tmp_path / "doris-mcp.json"
    config_path.write_text(
        json.dumps({"tool_exposure": {"mode": "flat"}}),
        encoding="utf-8",
    )

    configured = DorisConfig.from_file(str(config_path))

    assert configured.tool_exposure.mode == "flat"


def test_capability_cache_controls_are_explicit_and_validated(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("CAPABILITY_SNAPSHOT_TTL_SECONDS", "120")
    monkeypatch.setenv("CAPABILITY_PROBE_TIMEOUT_SECONDS", "7")
    monkeypatch.setenv("CAPABILITY_STALE_GRACE_SECONDS", "480")

    configured = DorisConfig.from_env()

    assert configured.capability.snapshot_ttl_seconds == 120
    assert configured.capability.probe_timeout_seconds == 7
    assert configured.capability.stale_grace_seconds == 480
    assert configured.to_dict()["capability"] == {
        "snapshot_ttl_seconds": 120,
        "probe_timeout_seconds": 7,
        "stale_grace_seconds": 480,
    }
    assert configured.validate() == []

    config_path = tmp_path / "doris-mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "capability": {
                    "snapshot_ttl_seconds": 30,
                    "probe_timeout_seconds": 3,
                    "stale_grace_seconds": 60,
                }
            }
        ),
        encoding="utf-8",
    )
    from_file = DorisConfig.from_file(str(config_path))
    assert from_file.capability.snapshot_ttl_seconds == 30
    assert from_file.capability.probe_timeout_seconds == 3
    assert from_file.capability.stale_grace_seconds == 60

    from_file.capability.snapshot_ttl_seconds = 0
    from_file.capability.probe_timeout_seconds = 61
    from_file.capability.stale_grace_seconds = -1
    errors = from_file.validate()
    assert "Capability snapshot TTL must be in the range 1-86400 seconds" in errors
    assert "Capability probe timeout must be in the range 1-60 seconds" in errors
    assert "Capability stale grace must be in the range 0-86400 seconds" in errors


def test_governance_runtime_controls_load_serialize_and_validate(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("GOVERNANCE_MAX_SAMPLE_RATIO", "0.15")
    monkeypatch.setenv("GOVERNANCE_MAX_AUDIT_WINDOW_DAYS", "45")
    monkeypatch.setenv("GOVERNANCE_MAX_LINEAGE_EDGES", "750")
    monkeypatch.setenv(
        "GOVERNANCE_LINEAGE_STORE_TABLE",
        "governance.lineage_events",
    )
    monkeypatch.setenv("GOVERNANCE_LINEAGE_RECENT_EVENT_MINUTES", "180")

    configured = DorisConfig.from_env()

    assert configured.to_dict()["governance"] == {
        "max_sample_ratio": 0.15,
        "max_audit_window_days": 45,
        "max_lineage_edges": 750,
        "lineage_store_table": "governance.lineage_events",
        "lineage_recent_event_minutes": 180,
    }
    assert configured.validate() == []

    config_path = tmp_path / "doris-mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "governance": {
                    "max_sample_ratio": 0.2,
                    "max_audit_window_days": 60,
                    "max_lineage_edges": 900,
                    "lineage_store_table": "metadata.lineage_events",
                    "lineage_recent_event_minutes": 240,
                }
            }
        ),
        encoding="utf-8",
    )
    from_file = DorisConfig.from_file(str(config_path))
    assert from_file.governance.max_sample_ratio == 0.2
    assert from_file.governance.max_audit_window_days == 60
    assert from_file.governance.max_lineage_edges == 900
    assert from_file.governance.lineage_store_table == "metadata.lineage_events"
    assert from_file.governance.lineage_recent_event_minutes == 240

    from_file.governance.max_sample_ratio = 0
    from_file.governance.max_audit_window_days = 366
    from_file.governance.max_lineage_edges = 5001
    from_file.governance.lineage_recent_event_minutes = 0
    errors = from_file.validate()
    assert (
        "Governance maximum sample ratio must be in the range (0, 1]"
        in errors
    )
    assert "Governance audit window must be in the range 1-365 days" in errors
    assert "Governance lineage edge limit must be in the range 1-5000" in errors
    assert (
        "Governance recent lineage event window must be in the range "
        "1-525600 minutes"
        in errors
    )


def test_lakehouse_runtime_controls_load_serialize_and_validate(
    monkeypatch,
    tmp_path,
) -> None:
    monkeypatch.setenv("LAKEHOUSE_MAX_CATALOG_OBJECTS", "80")
    monkeypatch.setenv("LAKEHOUSE_MAX_CATALOG_DATABASES", "30")
    monkeypatch.setenv("LAKEHOUSE_MAX_SNAPSHOTS", "90")
    monkeypatch.setenv("LAKEHOUSE_MAX_PARTITIONS", "150")
    monkeypatch.setenv("LAKEHOUSE_MAX_VARIANT_SAMPLE_ROWS", "40")
    monkeypatch.setenv("LAKEHOUSE_MAX_VARIANT_PATHS", "300")

    configured = DorisConfig.from_env()

    assert configured.to_dict()["lakehouse"] == {
        "max_catalog_objects": 80,
        "max_catalog_databases": 30,
        "max_snapshots": 90,
        "max_partitions": 150,
        "max_variant_sample_rows": 40,
        "max_variant_paths": 300,
    }
    assert configured.validate() == []

    config_path = tmp_path / "doris-mcp.json"
    config_path.write_text(
        json.dumps(
            {
                "lakehouse": {
                    "max_catalog_objects": 75,
                    "max_catalog_databases": 25,
                    "max_snapshots": 85,
                    "max_partitions": 140,
                    "max_variant_sample_rows": 35,
                    "max_variant_paths": 250,
                }
            }
        ),
        encoding="utf-8",
    )
    from_file = DorisConfig.from_file(str(config_path))
    assert from_file.lakehouse.max_catalog_objects == 75
    assert from_file.lakehouse.max_catalog_databases == 25
    assert from_file.lakehouse.max_snapshots == 85
    assert from_file.lakehouse.max_partitions == 140
    assert from_file.lakehouse.max_variant_sample_rows == 35
    assert from_file.lakehouse.max_variant_paths == 250

    from_file.lakehouse.max_catalog_objects = 0
    from_file.lakehouse.max_catalog_databases = 101
    from_file.lakehouse.max_snapshots = 501
    from_file.lakehouse.max_partitions = 1001
    from_file.lakehouse.max_variant_sample_rows = 501
    from_file.lakehouse.max_variant_paths = 2001
    errors = from_file.validate()
    assert "Lakehouse catalog object limit must be in the range 1-500" in errors
    assert (
        "Lakehouse catalog database limit must be in the range 1-100"
        in errors
    )
    assert "Lakehouse snapshot limit must be in the range 1-500" in errors
    assert "Lakehouse partition limit must be in the range 1-1000" in errors
    assert "Lakehouse Variant sample limit must be in the range 1-500" in errors
    assert "Lakehouse Variant path limit must be in the range 1-2000" in errors


def test_state_handle_secret_and_ttl_are_configurable_without_serializing_secret(
    monkeypatch,
):
    secret = "test-shared-state-handle-secret-value"
    monkeypatch.setenv("MCP_STATE_HANDLE_SECRET", secret)
    monkeypatch.setenv("MCP_STATE_HANDLE_TTL_SECONDS", "45")

    configured = DorisConfig.from_env()
    assert configured.mcp_state_handle_secret == secret
    assert configured.mcp_state_handle_ttl_seconds == 45
    assert "mcp_state_handle_secret" not in configured.to_dict()
    assert configured.to_dict()["mcp_state_handle_ttl_seconds"] == 45
    assert configured.validate() == []

    configured.mcp_state_handle_secret = "short"
    assert (
        "MCP state handle secret must contain at least 32 bytes"
        in configured.validate()
    )
    configured.mcp_state_handle_secret = secret
    configured.mcp_state_handle_ttl_seconds = 3601
    assert (
        "MCP state handle TTL must be in the range 1-3600 seconds"
        in configured.validate()
    )


def test_multiworker_environment_preserves_resolved_parent_config(monkeypatch):
    config = DorisConfig()
    config.database.host = "127.0.0.1"
    config.database.hosts = ["127.0.0.1", "127.0.0.2"]
    config.database.port = 19030
    config.database.user = "loader"
    config.database.password = "test-password"
    config.database.database = "hhm_dt_sim"
    config.database.fe_http_host = "127.0.0.10"
    config.database.fe_http_hosts = ["127.0.0.10", "127.0.0.11"]
    config.database.be_hosts = ["127.0.0.20", "127.0.0.21"]
    config.server_name = "doris-mcp-server"
    config.mcp_allowed_hosts = ["mcp.example.test", "mcp.example.test:*"]
    config.mcp_allowed_origins = ["https://client.example.test"]
    config.enable_legacy_http_adapter = True
    config.mcp_list_page_size = 17
    config.mcp_tool_providers = ["orders_api", "customer-tools"]
    config.tool_exposure.mode = "flat"
    config.capability.snapshot_ttl_seconds = 120
    config.capability.probe_timeout_seconds = 7
    config.capability.stale_grace_seconds = 480
    config.governance.max_sample_ratio = 0.15
    config.governance.max_audit_window_days = 45
    config.governance.max_lineage_edges = 750
    config.governance.lineage_store_table = "governance.lineage_events"
    config.governance.lineage_recent_event_minutes = 180
    config.lakehouse.max_catalog_objects = 80
    config.lakehouse.max_catalog_databases = 30
    config.lakehouse.max_snapshots = 90
    config.lakehouse.max_partitions = 150
    config.lakehouse.max_variant_sample_rows = 40
    config.lakehouse.max_variant_paths = 300
    config.mcp_state_handle_secret = "parent-shared-state-handle-secret-value"
    config.mcp_state_handle_ttl_seconds = 45

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
    assert child_config.database.hosts == ["127.0.0.1", "127.0.0.2"]
    assert child_config.database.port == 19030
    assert child_config.database.user == "loader"
    assert child_config.database.password == "test-password"
    assert child_config.database.database == "hhm_dt_sim"
    assert child_config.database.fe_http_host == "127.0.0.10"
    assert child_config.database.fe_http_hosts == [
        "127.0.0.10",
        "127.0.0.11",
    ]
    assert child_config.database.be_hosts == ["127.0.0.20", "127.0.0.21"]
    assert child_config.server_host == "127.0.0.1"
    assert child_config.server_port == 31133
    assert child_config.mcp_allowed_hosts == [
        "mcp.example.test",
        "mcp.example.test:*",
    ]
    assert child_config.mcp_allowed_origins == ["https://client.example.test"]
    assert child_config.enable_legacy_http_adapter is True
    assert child_config.mcp_list_page_size == 17
    assert child_config.mcp_tool_providers == ["orders_api", "customer-tools"]
    assert child_config.tool_exposure.mode == "flat"
    assert child_config.capability.snapshot_ttl_seconds == 120
    assert child_config.capability.probe_timeout_seconds == 7
    assert child_config.capability.stale_grace_seconds == 480
    assert child_config.governance.max_sample_ratio == 0.15
    assert child_config.governance.max_audit_window_days == 45
    assert child_config.governance.max_lineage_edges == 750
    assert (
        child_config.governance.lineage_store_table
        == "governance.lineage_events"
    )
    assert child_config.governance.lineage_recent_event_minutes == 180
    assert child_config.lakehouse.max_catalog_objects == 80
    assert child_config.lakehouse.max_catalog_databases == 30
    assert child_config.lakehouse.max_snapshots == 90
    assert child_config.lakehouse.max_partitions == 150
    assert child_config.lakehouse.max_variant_sample_rows == 40
    assert child_config.lakehouse.max_variant_paths == 300
    assert (
        child_config.mcp_state_handle_secret
        == "parent-shared-state-handle-secret-value"
    )
    assert child_config.mcp_state_handle_ttl_seconds == 45
    assert child_config.server_name == "doris-mcp-server"
    assert child_config.server_version == __version__
    assert child_config.transport == "http"
    assert child_config.workers == 2


@pytest.mark.asyncio
async def test_multiworker_http_identity_reports_product_version():
    for handler in (health_check, live_check, root_info):
        response = await handler(None)
        payload = json.loads(response.body)
        assert payload["service"] == "doris-mcp-server"
        assert payload["version"] == __version__
        assert "mcp_version" not in payload


@pytest.mark.asyncio
async def test_multiworker_readiness_requires_initialization(monkeypatch):
    from doris_mcp_server import multiworker_app

    readiness_probe = AsyncMock(
        side_effect=AssertionError("uninitialized worker must not probe Doris")
    )
    manager = SimpleNamespace(check_readiness=readiness_probe)
    monkeypatch.setattr(multiworker_app, "_worker_initialized", False)
    monkeypatch.setattr(multiworker_app, "_worker_connection_manager", manager)

    response = await readiness_check(None)
    payload = json.loads(response.body)
    assert response.status_code == 503
    assert payload["status"] == "not_ready"
    assert payload["checks"]["service"] == "not_ready"
    readiness_probe.assert_not_awaited()


@pytest.mark.asyncio
async def test_multiworker_readiness_uses_worker_database_probe(monkeypatch):
    from doris_mcp_server import multiworker_app

    readiness_probe = AsyncMock(return_value=True)
    manager = SimpleNamespace(check_readiness=readiness_probe)
    monkeypatch.setattr(multiworker_app, "_worker_initialized", True)
    monkeypatch.setattr(multiworker_app, "_worker_connection_manager", manager)

    response = await readiness_check(None)
    payload = json.loads(response.body)
    assert response.status_code == 200
    assert payload["status"] == "ready"
    assert payload["checks"]["doris"] == "ready"
    readiness_probe.assert_awaited_once_with(timeout_seconds=2.0)


@pytest.mark.asyncio
async def test_multiworker_routes_legacy_path_only_when_adapter_is_enabled(
    monkeypatch,
):
    from doris_mcp_server import multiworker_app

    async def fake_mcp_app(scope, receive, send):
        await Response(status_code=204)(scope, receive, send)

    monkeypatch.setattr(multiworker_app, "mcp_asgi_app", fake_mcp_app)
    monkeypatch.setattr(
        multiworker_app,
        "_worker_http_transport",
        SimpleNamespace(legacy_adapter_enabled=False),
    )

    transport = httpx.ASGITransport(app=multiworker_app.app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://127.0.0.1",
    ) as client:
        assert (await client.post("/mcp")).status_code == 204
        assert (await client.post("/mcp/legacy")).status_code == 404

        monkeypatch.setattr(
            multiworker_app,
            "_worker_http_transport",
            SimpleNamespace(legacy_adapter_enabled=True),
        )
        assert (await client.post("/mcp/legacy")).status_code == 204

# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Fail-closed tests for the reserved Doris administration domain."""

from __future__ import annotations

from typing import Any
from unittest.mock import Mock

import pytest
from pydantic import ValidationError

from doris_mcp_server.main import _multiworker_environment
from doris_mcp_server.tools.admin_domain import (
    ADMIN_ACTION_ANNOTATIONS,
    ADMIN_DOMAIN_DISCOVERY_SCOPE,
    ADMIN_DOMAIN_NAME,
    DORIS_ADMIN_DOMAIN_RESERVATION,
    AdminActionContract,
    AdminConfirmationContract,
    AdminDomainReservation,
    AdminRiskLevel,
)
from doris_mcp_server.tools.domain_catalog import DORIS_DOMAIN_CATALOG
from doris_mcp_server.tools.domain_dispatcher import (
    ToolExposureMode,
    ToolNotFoundError,
)
from doris_mcp_server.tools.domain_models import (
    Availability,
    AvailabilityStatus,
    ChildToolDefinition,
    DomainDefinition,
)
from doris_mcp_server.tools.tools_manager import DorisToolsManager
from doris_mcp_server.utils.config import DorisConfig


class _UnavailableProvider:
    async def availability_for(
        self,
        domain: DomainDefinition,
        child: ChildToolDefinition,
        auth_context: Any | None,
    ) -> Availability:
        del domain, child, auth_context
        return Availability(
            status=AvailabilityStatus.UNKNOWN,
            callable=False,
            reason_code="TEST_CAPABILITY_DISABLED",
        )


def _manager(mode: ToolExposureMode) -> DorisToolsManager:
    connection_manager = Mock()
    connection_manager.config = DorisConfig()
    return DorisToolsManager(
        connection_manager,
        domain_availability_provider=_UnavailableProvider(),
        tool_exposure_mode=mode,
    )


def _action(**updates: Any) -> AdminActionContract:
    values: dict[str, Any] = {
        "name": "cancel_query",
        "title": "Cancel a Doris query",
        "description": "Future reviewed action contract used only for validation.",
        "risk_level": AdminRiskLevel.HIGH,
        "preview_scope": "child:preview:doris_admin:cancel_query",
        "execute_scope": "child:call:doris_admin:cancel_query",
        "preview_handler_name": "admin:preview:cancel_query",
        "execute_handler_name": "admin:execute:cancel_query",
    }
    values.update(updates)
    return AdminActionContract(**values)


def test_reservation_has_no_actions_and_cannot_be_enabled() -> None:
    assert DORIS_ADMIN_DOMAIN_RESERVATION.to_wire() == {
        "name": ADMIN_DOMAIN_NAME,
        "title": "Doris Administration",
        "description": (
            "Reserved boundary for separately reviewed Doris-changing actions."
        ),
        "status": "reserved",
        "enabled": False,
        "discovery_scope": ADMIN_DOMAIN_DISCOVERY_SCOPE,
        "require_confirmation": True,
        "actions": [],
    }

    with pytest.raises(ValidationError, match="Input should be False"):
        AdminDomainReservation(enabled=True)


def test_future_action_contract_requires_canonical_scopes_and_handlers() -> None:
    action = _action()

    assert action.annotations == ADMIN_ACTION_ANNOTATIONS
    assert action.confirmation == AdminConfirmationContract()
    assert action.idempotency_key_field == "idempotency_key"

    with pytest.raises(ValidationError, match="preview_scope"):
        _action(preview_scope="child:preview:doris_admin:other")

    with pytest.raises(ValidationError, match="execute_handler_name"):
        _action(execute_handler_name="admin:execute:other")


def test_future_action_contract_requires_confirmation_and_rollback_pairing() -> None:
    with pytest.raises(ValidationError, match="Input should be True"):
        _action(confirmation={"required": False})

    with pytest.raises(ValidationError, match="rollback scope"):
        _action(
            rollback_supported=True,
            rollback_scope="child:rollback:doris_admin:cancel_query",
        )

    rollback = _action(
        rollback_supported=True,
        rollback_scope="child:rollback:doris_admin:cancel_query",
        rollback_handler_name="admin:rollback:cancel_query",
    )
    assert rollback.rollback_supported is True


def test_administration_config_is_reserved_and_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    default = DorisConfig.from_env()
    assert default.administration.enabled is False
    assert default.administration.require_confirmation is True
    assert not [
        error
        for error in default.validate()
        if error.startswith("Administration")
    ]

    monkeypatch.setenv("MCP_ADMIN_DOMAIN_ENABLED", "true")
    enabled = DorisConfig.from_env()
    assert enabled.administration.enabled is True
    assert (
        "Administration domain is reserved and cannot be enabled in 1.0"
        in enabled.validate()
    )

    monkeypatch.delenv("MCP_ADMIN_DOMAIN_ENABLED")
    monkeypatch.setenv("MCP_ADMIN_REQUIRE_CONFIRMATION", "false")
    unsafe = DorisConfig.from_env()
    assert unsafe.administration.require_confirmation is False
    assert (
        "Administration domain confirmation requirement cannot be disabled"
        in unsafe.validate()
    )


def test_administration_config_is_serialized_without_enabling_actions() -> None:
    config = DorisConfig()

    assert config.to_dict()["administration"] == {
        "enabled": False,
        "require_confirmation": True,
    }
    assert config.get_config_summary()["administration"] == {
        "enabled": False,
        "require_confirmation": True,
        "status": "reserved",
    }


def test_multiworker_environment_preserves_the_disabled_reservation() -> None:
    config = DorisConfig()

    environment = _multiworker_environment(
        config,
        host="127.0.0.1",
        port=3000,
        workers=2,
    )

    assert environment["MCP_ADMIN_DOMAIN_ENABLED"] == "false"
    assert environment["MCP_ADMIN_REQUIRE_CONFIRMATION"] == "true"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    (ToolExposureMode.HIERARCHICAL, ToolExposureMode.FLAT),
)
async def test_admin_domain_is_not_listed_or_callable(
    mode: ToolExposureMode,
) -> None:
    manager = _manager(mode)
    listed_names = {tool.name for tool in await manager.list_tools()}

    assert ADMIN_DOMAIN_NAME not in listed_names
    assert not any(name.startswith(f"{ADMIN_DOMAIN_NAME}_") for name in listed_names)
    assert ADMIN_DOMAIN_NAME not in {
        domain.name for domain in DORIS_DOMAIN_CATALOG.domains
    }
    assert not any(
        name.startswith(f"{ADMIN_DOMAIN_NAME}_")
        for name in manager.domain_dispatcher.formal_flat_names
    )

    with pytest.raises(ToolNotFoundError, match="Tool not found"):
        await manager.call_tool(ADMIN_DOMAIN_NAME, {})
    with pytest.raises(ToolNotFoundError, match="Tool not found"):
        await manager.call_tool(
            f"{ADMIN_DOMAIN_NAME}_cancel_query",
            {},
        )

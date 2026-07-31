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

"""Fail-closed contracts reserved for a future Doris administration domain."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import Field, model_validator

from .domain_models import (
    BindingName,
    ContractModel,
    Identifier,
    NonEmptyText,
    ToolContractAnnotations,
)

ADMIN_DOMAIN_NAME = "doris_admin"
ADMIN_DOMAIN_DISCOVERY_SCOPE = "domain:discover:doris_admin"
ADMIN_ACTION_ANNOTATIONS = ToolContractAnnotations(
    read_only=False,
    idempotent=False,
    destructive=True,
    open_world=False,
    requires_confirmation=True,
)


class AdminRiskLevel(StrEnum):
    """Allowed risk classifications for a future administrative action."""

    HIGH = "high"
    CRITICAL = "critical"


class AdminConfirmationContract(ContractModel):
    """Single-use confirmation bound to a preview and exact arguments."""

    required: Literal[True] = True
    method: Literal["explicit_token"] = "explicit_token"
    token_field: Identifier = "confirmation_token"
    preview_revision_field: Identifier = "preview_revision"
    argument_digest_algorithm: Literal["sha256"] = "sha256"
    single_use: Literal[True] = True
    expires_seconds: Annotated[int, Field(ge=30, le=900)] = 300


class AdminActionContract(ContractModel):
    """Future preview/execute boundary; this release registers no actions."""

    name: Identifier
    title: NonEmptyText
    description: NonEmptyText
    risk_level: AdminRiskLevel
    preview_scope: BindingName
    execute_scope: BindingName
    preview_handler_name: BindingName
    execute_handler_name: BindingName
    confirmation: AdminConfirmationContract = Field(
        default_factory=AdminConfirmationContract
    )
    idempotency_key_field: Identifier = "idempotency_key"
    rollback_supported: bool = False
    rollback_scope: BindingName | None = None
    rollback_handler_name: BindingName | None = None
    annotations: ToolContractAnnotations = ADMIN_ACTION_ANNOTATIONS

    @model_validator(mode="after")
    def _validate_action_boundary(self) -> Self:
        expected_values = {
            "preview_scope": f"child:preview:{ADMIN_DOMAIN_NAME}:{self.name}",
            "execute_scope": f"child:call:{ADMIN_DOMAIN_NAME}:{self.name}",
            "preview_handler_name": f"admin:preview:{self.name}",
            "execute_handler_name": f"admin:execute:{self.name}",
        }
        for field_name, expected in expected_values.items():
            if getattr(self, field_name) != expected:
                raise ValueError(f"{field_name} must be {expected!r}")
        if self.annotations != ADMIN_ACTION_ANNOTATIONS:
            raise ValueError(
                "administrative actions must be destructive, closed-world, "
                "non-read-only, and confirmation-required"
            )

        rollback_values = (
            self.rollback_scope,
            self.rollback_handler_name,
        )
        if self.rollback_supported:
            expected_rollback = (
                f"child:rollback:{ADMIN_DOMAIN_NAME}:{self.name}",
                f"admin:rollback:{self.name}",
            )
            if rollback_values != expected_rollback:
                raise ValueError(
                    "rollback-enabled actions require canonical rollback "
                    "scope and handler bindings"
                )
        elif any(value is not None for value in rollback_values):
            raise ValueError(
                "rollback scope and handler require rollback_supported=true"
            )
        return self


class AdminDomainReservation(ContractModel):
    """Versioned reservation that cannot expose actions in the 1.0 release."""

    name: Identifier = ADMIN_DOMAIN_NAME
    title: NonEmptyText = "Doris Administration"
    description: NonEmptyText = (
        "Reserved boundary for separately reviewed Doris-changing actions."
    )
    status: Literal["reserved"] = "reserved"
    enabled: Literal[False] = False
    discovery_scope: BindingName = ADMIN_DOMAIN_DISCOVERY_SCOPE
    require_confirmation: Literal[True] = True
    actions: tuple[AdminActionContract, ...] = ()

    @model_validator(mode="after")
    def _validate_release_reservation(self) -> Self:
        if self.name != ADMIN_DOMAIN_NAME:
            raise ValueError(f"administration domain name must be {ADMIN_DOMAIN_NAME!r}")
        if self.discovery_scope != ADMIN_DOMAIN_DISCOVERY_SCOPE:
            raise ValueError(
                "administration discovery scope must use the reserved domain scope"
            )
        if self.actions:
            raise ValueError(
                "the Doris MCP 1.0 administration reservation cannot register actions"
            )
        return self


def administration_config_errors(
    *,
    enabled: Any,
    require_confirmation: Any,
) -> tuple[str, ...]:
    """Return fail-closed runtime errors for the 1.0 reservation."""
    errors: list[str] = []
    if not isinstance(enabled, bool):
        errors.append("Administration domain enabled flag must be boolean")
    elif enabled:
        errors.append(
            "Administration domain is reserved and cannot be enabled in 1.0"
        )
    if not isinstance(require_confirmation, bool):
        errors.append("Administration confirmation flag must be boolean")
    elif not require_confirmation:
        errors.append(
            "Administration domain confirmation requirement cannot be disabled"
        )
    return tuple(errors)


DORIS_ADMIN_DOMAIN_RESERVATION = AdminDomainReservation()

__all__ = [
    "ADMIN_ACTION_ANNOTATIONS",
    "ADMIN_DOMAIN_DISCOVERY_SCOPE",
    "ADMIN_DOMAIN_NAME",
    "AdminActionContract",
    "AdminConfirmationContract",
    "AdminDomainReservation",
    "AdminRiskLevel",
    "DORIS_ADMIN_DOMAIN_RESERVATION",
    "administration_config_errors",
]

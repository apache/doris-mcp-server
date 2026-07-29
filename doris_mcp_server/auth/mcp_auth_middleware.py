#!/usr/bin/env python3
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
"""Shared ASGI authentication middleware for MCP HTTP routes."""

from typing import Any

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from ..utils.auth_credentials import BearerCredentials
from ..utils.config import EffectiveAuthConfig
from ..utils.logger import get_logger
from ..utils.redaction import redact_error_payload
from ..utils.security import (
    clear_current_auth_context,
    get_current_auth_context,
    reset_auth_context,
    set_current_auth_context,
)
from .doris_oauth_handlers import (
    insufficient_scope_response,
    protected_resource_error_response,
)
from .oauth_resource import (
    external_oauth_error_response,
    external_oauth_insufficient_scope_response,
)
from .operation_policy import OperationAuthorizationError

logger = get_logger(__name__)


async def extract_bearer_credentials_from_scope(
    scope: Scope,
) -> BearerCredentials:
    """Extract canonical bearer credentials from an ASGI scope."""
    headers = dict(scope.get("headers", []))
    authorization = headers.get(b"authorization", b"").decode("utf-8")
    client = scope.get("client") or ("unknown", 0)
    client_ip = client[0] if client else "unknown"

    return BearerCredentials.from_authorization(
        authorization,
        client_ip=client_ip,
        session_id=scope.get("session_id", ""),
    )


class MCPAuthASGIMiddleware:
    """Authenticate protected /mcp ASGI requests and manage AuthContext lifecycle."""

    def __init__(self, security_manager: Any, downstream: ASGIApp, effective_auth: EffectiveAuthConfig):
        self.security_manager = security_manager
        self.downstream = downstream
        self.effective_auth = effective_auth

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        credentials: BearerCredentials | None = None
        try:
            credentials = await extract_bearer_credentials_from_scope(scope)
            auth_context = await self.security_manager.authenticate_request(credentials)
        except Exception as exc:
            if self.effective_auth.oauth_discovery_mode == "doris_oauth":
                response = protected_resource_error_response(
                    exc,
                    self.effective_auth.doris_oauth_base_url,
                )
            elif self.effective_auth.oauth_discovery_mode == "external_oauth":
                response = external_oauth_error_response(
                    exc,
                    self.effective_auth,
                    credentials_present=bool(
                        credentials and credentials.is_bearer
                    ),
                )
            else:
                response = JSONResponse(
                    {
                        "error": "Authentication required",
                        "message": "Authentication failed",
                    },
                    status_code=401,
                )
            await response(scope, receive, send)
            return

        scoped_request = dict(scope)
        scoped_request["auth_context"] = auth_context

        context_token = None
        try:
            context_token = set_current_auth_context(auth_context)
            if get_current_auth_context() is not auth_context:
                raise RuntimeError("AuthContext ContextVar verification failed")
        except Exception:
            if context_token is not None:
                try:
                    reset_auth_context(context_token)
                except Exception as reset_exc:
                    logger.error(
                        "Failed to reset auth context after verification failure (%s)",
                        type(reset_exc).__name__,
                    )
                    clear_current_auth_context()
            response = JSONResponse(
                {
                    "error": "auth_context_unavailable",
                    "message": "Authentication context unavailable",
                },
                status_code=500,
            )
            await response(scope, receive, send)
            return

        try:
            await self.downstream(scoped_request, receive, send)
        except OperationAuthorizationError as exc:
            body = redact_error_payload(exc.to_dict())
            if (
                self.effective_auth.oauth_discovery_mode == "doris_oauth"
                and exc.required_scope
                and exc.error_code == "PERMISSION_DENIED"
            ):
                response = insufficient_scope_response(
                    self.effective_auth.doris_oauth_base_url,
                    exc.required_scope,
                    body,
                )
            elif (
                self.effective_auth.oauth_discovery_mode == "external_oauth"
                and exc.required_scope
                and exc.error_code == "PERMISSION_DENIED"
            ):
                response = external_oauth_insufficient_scope_response(
                    self.effective_auth,
                    exc.required_scope,
                    body,
                )
            else:
                response = JSONResponse(body, status_code=exc.status_code)
            await response(scope, receive, send)
        finally:
            try:
                reset_auth_context(context_token)
            except Exception as exc:
                logger.error(
                    "Failed to reset auth context after request (%s)",
                    type(exc).__name__,
                )
                clear_current_auth_context()

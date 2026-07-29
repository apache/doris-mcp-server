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
"""Fail-closed validation for externally issued OAuth access tokens."""

import math
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from hmac import compare_digest
from typing import Any


class OAuthAccessTokenValidationError(ValueError):
    """An external access token failed resource-server validation."""

    def __init__(
        self,
        error: str,
        description: str,
        *,
        required_scopes: Sequence[str] = (),
    ):
        super().__init__(description)
        self.error = error
        self.description = description
        self.required_scopes = tuple(dict.fromkeys(required_scopes))
        self.status_code = 403 if error == "insufficient_scope" else 401


@dataclass(frozen=True, slots=True)
class OAuthAccessTokenContext:
    """Validated, non-secret claims used to build an authentication context."""

    issuer: str
    resource: str
    audiences: tuple[str, ...]
    scopes: tuple[str, ...]
    subject: str
    client_id: str = ""
    token_id: str = ""
    expires_at: int = 0


def _claim_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return tuple(part for part in value.split() if part)
    if isinstance(value, Sequence) and not isinstance(
        value,
        str | bytes | bytearray,
    ):
        return tuple(str(part) for part in value if str(part))
    return ()


class ExternalOAuthTokenValidator:
    """Validate RFC 7662 claims for this MCP protected resource."""

    def __init__(
        self,
        *,
        issuer: str,
        resource: str,
        audience: str,
        allowed_scopes: Sequence[str],
        required_scopes: Sequence[str],
    ):
        self.issuer = issuer
        self.resource = resource
        self.audience = audience
        self.allowed_scopes = frozenset(allowed_scopes)
        self.required_scopes = frozenset(required_scopes)

    def validate(
        self,
        claims: Mapping[str, Any],
        *,
        current_time: float | None = None,
    ) -> OAuthAccessTokenContext:
        """Validate active state and bind claims to this issuer and resource."""
        if claims.get("active") is not True:
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token is inactive",
            )

        token_issuer = str(claims.get("iss") or "")
        if not token_issuer or not compare_digest(token_issuer, self.issuer):
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token issuer mismatch",
            )

        audiences = _claim_values(claims.get("aud"))
        if not any(compare_digest(value, self.audience) for value in audiences):
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token audience mismatch",
            )

        token_resources = _claim_values(claims.get("resource"))
        if token_resources and not any(
            compare_digest(value, self.resource) for value in token_resources
        ):
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token resource mismatch",
            )

        now = time.time() if current_time is None else current_time
        expires_at = claims.get("exp")
        if (
            isinstance(expires_at, bool)
            or not isinstance(expires_at, int | float)
            or not math.isfinite(expires_at)
        ):
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token expiration is missing",
            )
        if float(expires_at) <= now:
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token has expired",
            )

        not_before = claims.get("nbf")
        if not_before is not None:
            if (
                isinstance(not_before, bool)
                or not isinstance(not_before, int | float)
                or not math.isfinite(not_before)
            ):
                raise OAuthAccessTokenValidationError(
                    "invalid_token",
                    "OAuth access token not-before claim is invalid",
                )
            if float(not_before) > now:
                raise OAuthAccessTokenValidationError(
                    "invalid_token",
                    "OAuth access token is not yet valid",
                )

        token_scopes = frozenset(
            _claim_values(claims.get("scope") or claims.get("scp"))
        )
        if not self.required_scopes <= token_scopes:
            raise OAuthAccessTokenValidationError(
                "insufficient_scope",
                "OAuth access token is missing a required scope",
                required_scopes=tuple(sorted(self.required_scopes)),
            )
        granted_scopes = tuple(sorted(token_scopes & self.allowed_scopes))
        if not granted_scopes:
            raise OAuthAccessTokenValidationError(
                "insufficient_scope",
                "OAuth access token has no allowed scope",
                required_scopes=tuple(
                    sorted(self.required_scopes or self.allowed_scopes)
                ),
            )

        subject = str(claims.get("sub") or "")
        if not subject:
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth access token subject is missing",
            )

        return OAuthAccessTokenContext(
            issuer=token_issuer,
            resource=self.resource,
            audiences=audiences,
            scopes=granted_scopes,
            subject=subject,
            client_id=str(claims.get("client_id") or ""),
            token_id=str(claims.get("jti") or ""),
            expires_at=int(expires_at),
        )

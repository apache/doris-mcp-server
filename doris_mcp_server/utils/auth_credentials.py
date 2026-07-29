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
"""Canonical request credentials for MCP bearer authentication."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class BearerCredentials:
    """Normalized credentials passed to every bearer authentication provider."""

    scheme: str = ""
    token: str = field(default="", repr=False)
    client_ip: str = "unknown"
    session_id: str = ""

    @property
    def is_bearer(self) -> bool:
        return self.scheme == "bearer" and bool(self.token)

    @property
    def is_static_token(self) -> bool:
        return self.scheme in {"bearer", "token"} and bool(self.token)

    @classmethod
    def from_authorization(
        cls,
        authorization: str | None,
        *,
        client_ip: str = "unknown",
        session_id: str = "",
    ) -> "BearerCredentials":
        """Normalize an Authorization header without retaining the raw header."""
        raw_header = str(authorization or "").strip()
        scheme, separator, token = raw_header.partition(" ")
        normalized_scheme = scheme.lower()
        if (
            not separator
            or normalized_scheme not in {"bearer", "token"}
            or not token.strip()
        ):
            token = ""
        return cls(
            scheme=normalized_scheme,
            token=token.strip(),
            client_ip=str(client_ip or "unknown"),
            session_id=str(session_id or ""),
        )


def normalize_bearer_credentials(
    auth_input: BearerCredentials | Mapping[str, Any],
) -> BearerCredentials:
    """Convert a legacy auth mapping once at the authentication boundary."""
    if isinstance(auth_input, BearerCredentials):
        return auth_input

    client_ip = str(auth_input.get("client_ip") or "unknown")
    session_id = str(auth_input.get("session_id") or "")
    credentials = BearerCredentials.from_authorization(
        auth_input.get("authorization"),
        client_ip=client_ip,
        session_id=session_id,
    )
    explicit_token = str(
        auth_input.get("token") or auth_input.get("access_token") or ""
    ).strip()
    if not explicit_token:
        return credentials

    scheme = credentials.scheme
    if scheme not in {"bearer", "token"}:
        scheme = "bearer"
    return BearerCredentials(
        scheme=scheme,
        token=explicit_token,
        client_ip=client_ip,
        session_id=session_id,
    )

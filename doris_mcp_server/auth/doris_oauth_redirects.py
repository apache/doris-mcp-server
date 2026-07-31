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

"""Redirect URI policy for Doris-backed OAuth."""

import ipaddress
import re
from urllib.parse import urlparse

from .doris_oauth_types import TokenEndpointError

URI_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")


def is_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    normalized = hostname.lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def is_loopback_url(url: str) -> bool:
    parsed = urlparse(url)
    return is_loopback_host(parsed.hostname)


class DorisOAuthRedirectPolicy:
    """Validate and match OAuth redirect URIs."""

    def __init__(self, allow_production_wildcards: bool = False):
        self.allow_production_wildcards = allow_production_wildcards

    def validate_redirect_uri(
        self,
        uri: str,
        *,
        application_type: str,
        source: str = "dcr",
    ) -> str:
        if not isinstance(uri, str) or not uri:
            raise TokenEndpointError(
                "invalid_redirect_uri", "Redirect URI must be absolute", status_code=400
            )
        try:
            parsed = urlparse(uri)
            hostname = parsed.hostname
            username = parsed.username
            password = parsed.password
            _ = parsed.port
        except ValueError as exc:
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "Redirect URI is malformed",
                status_code=400,
            ) from exc

        scheme = parsed.scheme.lower()
        if not scheme or not URI_SCHEME_PATTERN.fullmatch(scheme):
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "Redirect URI must be absolute",
                status_code=400,
            )
        if parsed.fragment:
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "Redirect URI must not contain a fragment",
                status_code=400,
            )
        if username or password:
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "Redirect URI credentials are not allowed",
                status_code=400,
            )
        if "*" in uri:
            if source == "dcr" or not self.allow_production_wildcards:
                raise TokenEndpointError(
                    "invalid_redirect_uri",
                    "Wildcard redirect URI is not allowed",
                    status_code=400,
                )

        if application_type == "native":
            if scheme == "http" and parsed.netloc and is_loopback_host(hostname):
                return uri
            if scheme in {"http", "https"}:
                raise TokenEndpointError(
                    "invalid_redirect_uri",
                    "Native redirect URI must use a custom scheme or loopback HTTP",
                    status_code=400,
                )
            if "." not in scheme:
                raise TokenEndpointError(
                    "invalid_redirect_uri",
                    "Native custom redirect URI scheme must be reverse-domain based",
                    status_code=400,
                )
            scheme_specific_part = uri.split(":", 1)[1]
            if not scheme_specific_part or not (parsed.netloc or parsed.path):
                raise TokenEndpointError(
                    "invalid_redirect_uri",
                    "Native redirect URI must be absolute",
                    status_code=400,
                )
            return uri

        if application_type == "web":
            if scheme == "https" and parsed.netloc and hostname:
                if is_loopback_host(hostname):
                    raise TokenEndpointError(
                        "invalid_redirect_uri",
                        "Web redirect URI must not use a loopback host",
                        status_code=400,
                    )
                return uri
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "Web redirect URI must use non-loopback HTTPS",
                status_code=400,
            )

        raise TokenEndpointError(
            "invalid_client_metadata",
            "application_type must be native or web",
            status_code=400,
        )

    def validate_redirect_uris(
        self,
        uris: list[str] | tuple[str, ...],
        *,
        application_type: str,
        source: str = "dcr",
    ) -> tuple[str, ...]:
        if not uris:
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "At least one redirect URI is required",
                status_code=400,
            )
        if not isinstance(uris, list | tuple):
            raise TokenEndpointError(
                "invalid_redirect_uri",
                "redirect_uris must be an array",
                status_code=400,
            )
        return tuple(
            self.validate_redirect_uri(
                uri,
                application_type=application_type,
                source=source,
            )
            for uri in uris
        )

    def choose_redirect_uri(
        self, registered_uris: tuple[str, ...], requested_uri: str | None
    ) -> str:
        if requested_uri:
            if requested_uri not in registered_uris:
                raise TokenEndpointError(
                    "invalid_redirect_uri",
                    "Redirect URI is not registered",
                    status_code=400,
                )
            return requested_uri
        if len(registered_uris) == 1:
            return registered_uris[0]
        raise TokenEndpointError(
            "invalid_request", "redirect_uri is required", status_code=400
        )

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
"""OAuth protected-resource metadata and Bearer challenge helpers."""

from urllib.parse import urlsplit, urlunsplit

from starlette.responses import JSONResponse

from ..utils.config import EffectiveAuthConfig
from .oauth_token_validation import OAuthAccessTokenValidationError


def external_oauth_resource_metadata_url(resource: str) -> str:
    """Return the root RFC 9728 metadata URL served by this MCP server."""
    parsed = urlsplit(resource)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("External OAuth resource must be an absolute URI")
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            "/.well-known/oauth-protected-resource",
            "",
            "",
        )
    )


def _quote_challenge_value(value: str) -> str:
    """Escape one RFC 7235 quoted-string value and reject header injection."""
    sanitized = str(value).replace("\r", "").replace("\n", "")
    return sanitized.replace("\\", "\\\\").replace('"', '\\"')


def bearer_challenge_header(
    resource_metadata_url: str,
    *,
    error: str | None = None,
    scopes: tuple[str, ...] = (),
) -> str:
    """Build an RFC 6750 Bearer challenge with RFC 9728 discovery metadata."""
    parameters = [
        f'resource_metadata="{_quote_challenge_value(resource_metadata_url)}"'
    ]
    if error:
        parameters.append(f'error="{_quote_challenge_value(error)}"')
    if scopes:
        scope = " ".join(dict.fromkeys(scopes))
        parameters.append(f'scope="{_quote_challenge_value(scope)}"')
    return f"Bearer {', '.join(parameters)}"


def external_oauth_protected_resource_metadata(
    effective_auth: EffectiveAuthConfig,
) -> dict[str, object]:
    """Build the RFC 9728 document for an external authorization server."""
    return {
        "resource": effective_auth.external_oauth_resource,
        "authorization_servers": [effective_auth.external_oauth_issuer],
        "scopes_supported": list(effective_auth.external_oauth_scopes),
        "bearer_methods_supported": ["header"],
    }


def external_oauth_error_response(
    error: Exception,
    effective_auth: EffectiveAuthConfig,
    *,
    credentials_present: bool,
) -> JSONResponse:
    """Map external OAuth authentication failures to OAuth resource errors."""
    default_scopes = (
        effective_auth.external_oauth_required_scopes
        or effective_auth.external_oauth_scopes
    )
    challenge_error = "invalid_token" if credentials_present else None
    status_code = 401
    body = {
        "error": "invalid_token" if credentials_present else "authentication_required",
        "error_description": (
            "Invalid access token" if credentials_present else "Authentication required"
        ),
    }

    if isinstance(error, OAuthAccessTokenValidationError):
        challenge_error = error.error
        status_code = error.status_code
        body = {
            "error": error.error,
            "error_description": error.description,
        }
        default_scopes = error.required_scopes or default_scopes

    metadata_url = external_oauth_resource_metadata_url(
        effective_auth.external_oauth_resource
    )
    return JSONResponse(
        body,
        status_code=status_code,
        headers={
            "WWW-Authenticate": bearer_challenge_header(
                metadata_url,
                error=challenge_error,
                scopes=default_scopes,
            )
        },
    )


def external_oauth_insufficient_scope_response(
    effective_auth: EffectiveAuthConfig,
    required_scope: str,
    body: dict[str, object],
) -> JSONResponse:
    """Return a standards-compliant runtime step-up challenge."""
    metadata_url = external_oauth_resource_metadata_url(
        effective_auth.external_oauth_resource
    )
    return JSONResponse(
        body,
        status_code=403,
        headers={
            "WWW-Authenticate": bearer_challenge_header(
                metadata_url,
                error="insufficient_scope",
                scopes=(required_scope,),
            )
        },
    )

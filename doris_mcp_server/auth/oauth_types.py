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
"""
OAuth 2.0/OIDC Type Definitions
Provides data types and models for OAuth authentication flow
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any

from ..utils.datetime_utils import utc_now


class OAuthProvider(Enum):
    """OAuth provider enumeration"""
    GOOGLE = "google"
    MICROSOFT = "microsoft"
    GITHUB = "github"
    CUSTOM = "custom"


class OAuthGrantType(Enum):
    """OAuth grant type enumeration"""
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"


@dataclass
class OAuthState:
    """OAuth state parameter for CSRF protection"""
    state: str
    nonce: str | None = None
    pkce_verifier: str | None = None
    pkce_challenge: str | None = None
    redirect_uri: str = ""
    created_at: datetime = None
    expires_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = utc_now()


@dataclass
class OAuthTokens:
    """OAuth token response"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None  # OIDC ID token
    created_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = utc_now()


@dataclass
class OAuthUserInfo:
    """OAuth/OIDC user information"""
    sub: str  # Subject identifier
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    picture: str | None = None
    locale: str | None = None
    roles: list[str] = None
    raw_claims: dict[str, Any] = None

    def __post_init__(self):
        if self.roles is None:
            self.roles = []
        if self.raw_claims is None:
            self.raw_claims = {}


@dataclass
class OIDCDiscovery:
    """OIDC Discovery document"""
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: str | None = None
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None
    scopes_supported: list[str] = None
    response_types_supported: list[str] = None
    subject_types_supported: list[str] = None
    id_token_signing_alg_values_supported: list[str] = None

    def __post_init__(self):
        if self.scopes_supported is None:
            self.scopes_supported = ["openid"]
        if self.response_types_supported is None:
            self.response_types_supported = ["code"]
        if self.subject_types_supported is None:
            self.subject_types_supported = ["public"]
        if self.id_token_signing_alg_values_supported is None:
            self.id_token_signing_alg_values_supported = ["RS256"]


@dataclass
class OAuthError:
    """OAuth error response"""
    error: str
    error_description: str | None = None
    error_uri: str | None = None
    state: str | None = None


@dataclass
class OAuthProviderConfig:
    """OAuth provider configuration"""
    provider: OAuthProvider
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list[str]
    required_scopes: list[str]
    issuer: str
    resource: str
    audience: str

    # Endpoints
    authorization_endpoint: str
    token_endpoint: str
    introspection_endpoint: str | None = None
    introspection_client_id: str = ""
    introspection_client_secret: str = ""
    userinfo_endpoint: str | None = None
    jwks_uri: str | None = None

    # Discovery
    discovery_url: str | None = None

    # Settings
    pkce_enabled: bool = True
    nonce_enabled: bool = True

    # User mapping
    user_id_claim: str = "sub"
    email_claim: str = "email"
    name_claim: str = "name"
    roles_claim: str = "roles"
    default_roles: list[str] = None

    def __post_init__(self):
        if self.default_roles is None:
            self.default_roles = ["oauth_user"]


# Pre-defined provider configurations
OAUTH_PROVIDERS = {
    OAuthProvider.GOOGLE: {
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "discovery_url": "https://accounts.google.com/.well-known/openid_configuration",
        "scopes": ["openid", "email", "profile"],
        "user_id_claim": "sub",
        "email_claim": "email",
        "name_claim": "name"
    },
    OAuthProvider.MICROSOFT: {
        "authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_endpoint": "https://graph.microsoft.com/v1.0/me",
        "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
        "discovery_url": "https://login.microsoftonline.com/common/v2.0/.well-known/openid_configuration",
        "scopes": ["openid", "profile", "email", "User.Read"],
        "user_id_claim": "sub",
        "email_claim": "email",
        "name_claim": "name"
    },
    OAuthProvider.GITHUB: {
        "authorization_endpoint": "https://github.com/login/oauth/authorize",
        "token_endpoint": "https://github.com/login/oauth/access_token",
        "userinfo_endpoint": "https://api.github.com/user",
        "scopes": ["user:email", "read:user"],
        "user_id_claim": "id",
        "email_claim": "email",
        "name_claim": "name"
    }
}

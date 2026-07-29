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
OAuth Authentication Provider
Integrates OAuth 2.0/OIDC authentication with the existing authentication framework
"""

from typing import Dict, Any, Optional, Tuple
from .oauth_client import OAuthClient
from .oauth_token_validation import (
    OAuthAccessTokenContext,
    OAuthAccessTokenValidationError,
)
from .oauth_types import OAuthTokens, OAuthUserInfo, OAuthState
from ..utils.security import AuthContext, SecurityLevel
from ..utils.logger import get_logger
from ..utils.datetime_utils import utc_now

logger = get_logger(__name__)


class OAuthAuthenticationProvider:
    """OAuth authentication provider for Doris MCP Server"""
    
    def __init__(self, config):
        """Initialize OAuth authentication provider
        
        Args:
            config: DorisConfig with OAuth configuration
        """
        self.config = config
        self.oauth_client = OAuthClient(config)
        self.enabled = self.oauth_client.enabled
        
        logger.info(f"OAuthAuthenticationProvider initialized (enabled: {self.enabled})")
    
    async def initialize(self) -> bool:
        """Initialize OAuth authentication provider
        
        Returns:
            True if initialization successful
        """
        if not self.enabled:
            return True
            
        success = await self.oauth_client.initialize()
        if success:
            logger.info("OAuth authentication provider initialized successfully")
        else:
            logger.error("Failed to initialize OAuth authentication provider")
        return success
    
    async def shutdown(self):
        """Shutdown OAuth authentication provider"""
        if self.enabled:
            await self.oauth_client.shutdown()
            logger.info("OAuth authentication provider shutdown completed")
    
    def get_authorization_url(self) -> Tuple[str, str]:
        """Get OAuth authorization URL
        
        Returns:
            Tuple of (authorization_url, state)
        """
        if not self.enabled:
            raise ValueError("OAuth authentication is not enabled")
            
        authorization_url, oauth_state = self.oauth_client.build_authorization_url()
        return authorization_url, oauth_state.state
    
    async def handle_callback(self, code: str, state: str) -> AuthContext:
        """Handle OAuth callback and create authentication context
        
        Args:
            code: Authorization code from OAuth provider
            state: State parameter for CSRF protection
            
        Returns:
            AuthContext for the authenticated user
            
        Raises:
            ValueError: If authentication fails
        """
        if not self.enabled:
            raise ValueError("OAuth authentication is not enabled")
        
        try:
            # Exchange code for tokens
            tokens, oauth_state = await self.oauth_client.exchange_code_for_tokens(code, state)

            # Validate the access token for this issuer and MCP resource
            token_context = await self.oauth_client.introspect_access_token(
                tokens.access_token
            )
            
            # Get user information
            user_info = await self.oauth_client.get_user_info(tokens)
            
            # Create authentication context
            auth_context = await self._create_auth_context(
                user_info,
                tokens,
                token_context,
            )
            
            logger.info(f"OAuth authentication successful for user: {auth_context.user_id}")
            return auth_context
            
        except OAuthAccessTokenValidationError:
            logger.warning("OAuth callback access token was rejected")
            raise
        except Exception as e:
            logger.error(f"OAuth callback handling failed: {e}")
            raise ValueError(f"OAuth authentication failed: {str(e)}") from e
    
    async def authenticate_with_token(self, access_token: str) -> AuthContext:
        """Authenticate using OAuth access token
        
        Args:
            access_token: OAuth access token
            
        Returns:
            AuthContext for the authenticated user
        """
        if not self.enabled:
            raise ValueError("OAuth authentication is not enabled")
        
        try:
            # Create token object
            tokens = OAuthTokens(access_token=access_token)

            # Validate the access token before using identity information
            token_context = await self.oauth_client.introspect_access_token(
                access_token
            )
            
            # Get user information
            user_info = await self.oauth_client.get_user_info(tokens)
            
            # Create authentication context
            auth_context = await self._create_auth_context(
                user_info,
                tokens,
                token_context,
            )
            
            logger.info(f"OAuth token authentication successful for user: {auth_context.user_id}")
            return auth_context
            
        except OAuthAccessTokenValidationError:
            logger.warning("OAuth bearer access token was rejected")
            raise
        except Exception as e:
            logger.error(f"OAuth token authentication failed: {e}")
            raise ValueError(f"OAuth token authentication failed: {str(e)}") from e
    
    async def refresh_authentication(self, refresh_token: str) -> Tuple[AuthContext, str]:
        """Refresh OAuth authentication
        
        Args:
            refresh_token: OAuth refresh token
            
        Returns:
            Tuple of (AuthContext, new_access_token)
        """
        if not self.enabled:
            raise ValueError("OAuth authentication is not enabled")
        
        try:
            # Refresh tokens
            tokens = await self.oauth_client.refresh_tokens(refresh_token)

            # Validate the replacement token before using it
            token_context = await self.oauth_client.introspect_access_token(
                tokens.access_token
            )
            
            # Get updated user information
            user_info = await self.oauth_client.get_user_info(tokens)
            
            # Create authentication context
            auth_context = await self._create_auth_context(
                user_info,
                tokens,
                token_context,
            )
            
            logger.info(f"OAuth refresh successful for user: {auth_context.user_id}")
            return auth_context, tokens.access_token
            
        except OAuthAccessTokenValidationError:
            logger.warning("OAuth refreshed access token was rejected")
            raise
        except Exception as e:
            logger.error(f"OAuth refresh failed: {e}")
            raise ValueError(f"OAuth refresh failed: {str(e)}") from e
    
    async def _create_auth_context(
        self,
        user_info: OAuthUserInfo,
        tokens: OAuthTokens,
        token_context: OAuthAccessTokenContext,
    ) -> AuthContext:
        """Create authentication context from OAuth user info
        
        Args:
            user_info: OAuth user information
            tokens: OAuth tokens
            token_context: Validated access-token claims
            
        Returns:
            AuthContext for the user
        """
        if user_info.sub != token_context.subject:
            raise OAuthAccessTokenValidationError(
                "invalid_token",
                "OAuth userinfo subject does not match the access token",
            )

        # Determine security level based on roles or email domain
        security_level = await self._determine_security_level(user_info)
        
        # Map OAuth roles to application permissions
        permissions = await self._map_permissions(user_info.roles)
        
        # Generate session ID
        now = utc_now()
        session_id = f"oauth_{user_info.sub}_{now.timestamp()}"
        
        return AuthContext(
            token_id=token_context.token_id or f"oauth_{user_info.sub}",
            user_id=user_info.sub,
            roles=user_info.roles,
            permissions=permissions,
            security_level=security_level,
            session_id=session_id,
            login_time=now,
            last_activity=now,
            token="",  # OAuth doesn't have raw token, use empty string
            auth_method="external_oauth",
            oauth_client_id=token_context.client_id,
            oauth_scopes=list(token_context.scopes),
            oauth_token_id=token_context.token_id,
            oauth_issuer=token_context.issuer,
            oauth_resource=token_context.resource,
            oauth_audiences=list(token_context.audiences),
            pool_key="global",
        )
    
    async def _determine_security_level(self, user_info: OAuthUserInfo) -> SecurityLevel:
        """Determine security level for OAuth user
        
        Args:
            user_info: OAuth user information
            
        Returns:
            SecurityLevel for the user
        """
        # Check if user has admin roles
        admin_roles = {"admin", "administrator", "data_admin", "super_admin"}
        if any(role.lower() in admin_roles for role in user_info.roles):
            return SecurityLevel.SECRET
        
        # Check email domain for internal users
        if user_info.email:
            # You can configure trusted domains for internal access
            trusted_domains = ["yourcompany.com", "internal.org"]  # Configure as needed
            email_domain = user_info.email.split("@")[-1].lower()
            if email_domain in trusted_domains:
                return SecurityLevel.CONFIDENTIAL
        
        # Check for special roles
        elevated_roles = {"data_analyst", "developer", "manager"}
        if any(role.lower() in elevated_roles for role in user_info.roles):
            return SecurityLevel.CONFIDENTIAL
        
        # Default to internal level for OAuth users
        return SecurityLevel.INTERNAL
    
    async def _map_permissions(self, roles: list[str]) -> list[str]:
        """Map OAuth roles to application permissions
        
        Args:
            roles: OAuth user roles
            
        Returns:
            List of application permissions
        """
        permissions = set()
        
        # Role to permission mapping
        role_permissions = {
            "admin": ["admin", "read_data", "write_data", "manage_users"],
            "administrator": ["admin", "read_data", "write_data", "manage_users"],
            "data_admin": ["admin", "read_data", "write_data"],
            "super_admin": ["admin", "read_data", "write_data", "manage_users", "system_admin"],
            "data_analyst": ["read_data", "query_database"],
            "developer": ["read_data", "query_database", "debug"],
            "viewer": ["read_data"],
            "user": ["read_data"],
            "oauth_user": ["read_data"]  # Default OAuth user permission
        }
        
        # Map roles to permissions
        for role in roles:
            role_lower = role.lower()
            if role_lower in role_permissions:
                permissions.update(role_permissions[role_lower])
        
        # Ensure OAuth users have at least basic permissions
        if not permissions:
            permissions.add("read_data")
        
        return list(permissions)
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get OAuth provider information
        
        Returns:
            Provider information dictionary
        """
        if not self.enabled:
            return {"enabled": False}
        
        config = self.oauth_client.provider_config
        return {
            "enabled": True,
            "provider": config.provider.value,
            "client_id": config.client_id,
            "scopes": config.scopes,
            "redirect_uri": config.redirect_uri,
            "pkce_enabled": config.pkce_enabled,
            "nonce_enabled": config.nonce_enabled
        }

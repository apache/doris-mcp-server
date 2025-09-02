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
OAuth 2.0/OIDC Client Manager
Provides OAuth authentication client implementation with PKCE and OIDC support
"""

import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Dict, Optional, Any, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import asyncio
import json

try:
    import aiohttp
except ImportError:
    raise ImportError("aiohttp is required for OAuth functionality. Install with: pip install aiohttp")

from .oauth_types import (
    OAuthProvider, OAuthState, OAuthTokens, OAuthUserInfo, 
    OIDCDiscovery, OAuthError, OAuthProviderConfig, OAUTH_PROVIDERS
)
from ..utils.logger import get_logger

logger = get_logger(__name__)


class OAuthStateManager:
    """Manages OAuth state parameters for CSRF protection"""
    
    def __init__(self, state_expiry: int = 600):
        """Initialize state manager
        
        Args:
            state_expiry: State expiry time in seconds
        """
        self.state_expiry = state_expiry
        self._states: Dict[str, OAuthState] = {}
        self._cleanup_task = None
        
        logger.info("OAuthStateManager initialized")
    
    async def start(self):
        """Start periodic cleanup task"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        logger.info("OAuth state manager started")
    
    async def stop(self):
        """Stop periodic cleanup task"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("OAuth state manager stopped")
    
    def create_state(self, redirect_uri: str, pkce_enabled: bool = True, 
                    nonce_enabled: bool = True) -> OAuthState:
        """Create new OAuth state
        
        Args:
            redirect_uri: OAuth redirect URI
            pkce_enabled: Whether to enable PKCE
            nonce_enabled: Whether to enable nonce (for OIDC)
            
        Returns:
            OAuth state object
        """
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32) if nonce_enabled else None
        
        pkce_verifier = None
        pkce_challenge = None
        if pkce_enabled:
            pkce_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
            challenge_bytes = hashlib.sha256(pkce_verifier.encode()).digest()
            pkce_challenge = base64.urlsafe_b64encode(challenge_bytes).decode('utf-8').rstrip('=')
        
        oauth_state = OAuthState(
            state=state,
            nonce=nonce,
            pkce_verifier=pkce_verifier,
            pkce_challenge=pkce_challenge,
            redirect_uri=redirect_uri,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(seconds=self.state_expiry)
        )
        
        self._states[state] = oauth_state
        logger.debug(f"Created OAuth state: {state}")
        return oauth_state
    
    def get_state(self, state: str) -> Optional[OAuthState]:
        """Get OAuth state by state parameter
        
        Args:
            state: State parameter
            
        Returns:
            OAuth state object or None if not found/expired
        """
        oauth_state = self._states.get(state)
        if oauth_state and oauth_state.expires_at > datetime.utcnow():
            return oauth_state
        elif oauth_state:
            # Remove expired state
            del self._states[state]
            logger.debug(f"Removed expired OAuth state: {state}")
        return None
    
    def consume_state(self, state: str) -> Optional[OAuthState]:
        """Get and remove OAuth state
        
        Args:
            state: State parameter
            
        Returns:
            OAuth state object or None if not found/expired
        """
        oauth_state = self.get_state(state)
        if oauth_state:
            del self._states[state]
            logger.debug(f"Consumed OAuth state: {state}")
        return oauth_state
    
    async def _periodic_cleanup(self):
        """Periodic cleanup of expired states"""
        while True:
            try:
                await asyncio.sleep(300)  # Clean up every 5 minutes
                current_time = datetime.utcnow()
                expired_states = [
                    state for state, oauth_state in self._states.items()
                    if oauth_state.expires_at <= current_time
                ]
                
                for state in expired_states:
                    del self._states[state]
                
                if expired_states:
                    logger.info(f"Cleaned up {len(expired_states)} expired OAuth states")
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error during OAuth state cleanup: {e}")


class OAuthClient:
    """OAuth 2.0/OIDC Client implementation"""
    
    def __init__(self, config):
        """Initialize OAuth client
        
        Args:
            config: DorisConfig with OAuth configuration
        """
        self.config = config
        
        # Access OAuth settings through security configuration
        if hasattr(config, 'security'):
            security_config = config.security
        else:
            security_config = config
            
        self.enabled = security_config.oauth_enabled
        if not self.enabled:
            logger.info("OAuth client disabled by configuration")
            return
            
        # Build provider configuration
        self.provider_config = self._build_provider_config(security_config)
        self.state_manager = OAuthStateManager(security_config.oauth_state_expiry)
        
        # HTTP client session
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Discovery cache
        self._discovery_cache: Optional[OIDCDiscovery] = None
        self._discovery_cache_time: Optional[datetime] = None
        
        logger.info(f"OAuthClient initialized for provider: {self.provider_config.provider.value}")
    
    def _build_provider_config(self, security_config) -> OAuthProviderConfig:
        """Build OAuth provider configuration
        
        Args:
            security_config: Security configuration object
            
        Returns:
            OAuth provider configuration
        """
        try:
            provider = OAuthProvider(security_config.oauth_provider)
        except ValueError:
            provider = OAuthProvider.CUSTOM
        
        # Get default configuration for known providers
        defaults = OAUTH_PROVIDERS.get(provider, {})
        
        return OAuthProviderConfig(
            provider=provider,
            client_id=security_config.oauth_client_id,
            client_secret=security_config.oauth_client_secret,
            redirect_uri=security_config.oauth_redirect_uri,
            scopes=security_config.oauth_scopes or defaults.get("scopes", ["openid", "email", "profile"]),
            
            # Endpoints (use configured or defaults)
            authorization_endpoint=security_config.oauth_authorization_endpoint or defaults.get("authorization_endpoint", ""),
            token_endpoint=security_config.oauth_token_endpoint or defaults.get("token_endpoint", ""),
            userinfo_endpoint=security_config.oauth_userinfo_endpoint or defaults.get("userinfo_endpoint"),
            jwks_uri=security_config.oauth_jwks_uri or defaults.get("jwks_uri"),
            
            # Discovery
            discovery_url=security_config.oidc_discovery_url or defaults.get("discovery_url"),
            
            # Settings
            pkce_enabled=security_config.oauth_pkce_enabled,
            nonce_enabled=security_config.oauth_nonce_enabled,
            
            # User mapping
            user_id_claim=security_config.oauth_user_id_claim or defaults.get("user_id_claim", "sub"),
            email_claim=security_config.oauth_email_claim or defaults.get("email_claim", "email"),
            name_claim=security_config.oauth_name_claim or defaults.get("name_claim", "name"),
            roles_claim=security_config.oauth_roles_claim,
            default_roles=security_config.oauth_default_roles
        )
    
    async def initialize(self) -> bool:
        """Initialize OAuth client
        
        Returns:
            True if initialization successful
        """
        if not self.enabled:
            return True
            
        try:
            # Create HTTP session
            self._session = aiohttp.ClientSession()
            
            # Start state manager
            await self.state_manager.start()
            
            # Perform OIDC discovery if configured
            if self.provider_config.discovery_url:
                await self._discover_oidc_endpoints()
            
            logger.info("OAuth client initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize OAuth client: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown OAuth client"""
        if not self.enabled:
            return
            
        try:
            # Stop state manager
            await self.state_manager.stop()
            
            # Close HTTP session
            if self._session:
                await self._session.close()
            
            logger.info("OAuth client shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during OAuth client shutdown: {e}")
    
    async def _discover_oidc_endpoints(self):
        """Discover OIDC endpoints using discovery URL"""
        try:
            # Check cache first
            if (self._discovery_cache and self._discovery_cache_time and 
                datetime.utcnow() - self._discovery_cache_time < timedelta(hours=1)):
                return self._discovery_cache
            
            logger.info(f"Discovering OIDC endpoints: {self.provider_config.discovery_url}")
            
            async with self._session.get(self.provider_config.discovery_url) as response:
                response.raise_for_status()
                data = await response.json()
            
            discovery = OIDCDiscovery(
                issuer=data["issuer"],
                authorization_endpoint=data["authorization_endpoint"],
                token_endpoint=data["token_endpoint"],
                userinfo_endpoint=data.get("userinfo_endpoint"),
                jwks_uri=data.get("jwks_uri"),
                scopes_supported=data.get("scopes_supported"),
                response_types_supported=data.get("response_types_supported"),
                subject_types_supported=data.get("subject_types_supported"),
                id_token_signing_alg_values_supported=data.get("id_token_signing_alg_values_supported")
            )
            
            # Update provider configuration with discovered endpoints
            if not self.provider_config.authorization_endpoint:
                self.provider_config.authorization_endpoint = discovery.authorization_endpoint
            if not self.provider_config.token_endpoint:
                self.provider_config.token_endpoint = discovery.token_endpoint
            if not self.provider_config.userinfo_endpoint:
                self.provider_config.userinfo_endpoint = discovery.userinfo_endpoint
            if not self.provider_config.jwks_uri:
                self.provider_config.jwks_uri = discovery.jwks_uri
            
            # Cache discovery result
            self._discovery_cache = discovery
            self._discovery_cache_time = datetime.utcnow()
            
            logger.info("OIDC endpoint discovery completed successfully")
            return discovery
            
        except Exception as e:
            logger.error(f"OIDC endpoint discovery failed: {e}")
            raise
    
    def build_authorization_url(self) -> Tuple[str, OAuthState]:
        """Build OAuth authorization URL
        
        Returns:
            Tuple of (authorization_url, oauth_state)
        """
        if not self.enabled:
            raise ValueError("OAuth client is not enabled")
            
        # Create state for CSRF protection
        oauth_state = self.state_manager.create_state(
            redirect_uri=self.provider_config.redirect_uri,
            pkce_enabled=self.provider_config.pkce_enabled,
            nonce_enabled=self.provider_config.nonce_enabled
        )
        
        # Build authorization parameters
        params = {
            'response_type': 'code',
            'client_id': self.provider_config.client_id,
            'redirect_uri': self.provider_config.redirect_uri,
            'scope': ' '.join(self.provider_config.scopes),
            'state': oauth_state.state
        }
        
        # Add PKCE challenge
        if oauth_state.pkce_challenge:
            params['code_challenge'] = oauth_state.pkce_challenge
            params['code_challenge_method'] = 'S256'
        
        # Add nonce for OIDC
        if oauth_state.nonce:
            params['nonce'] = oauth_state.nonce
        
        # Build URL
        authorization_url = f"{self.provider_config.authorization_endpoint}?{urlencode(params)}"
        
        logger.info(f"Built OAuth authorization URL for state: {oauth_state.state}")
        return authorization_url, oauth_state
    
    async def exchange_code_for_tokens(self, code: str, state: str) -> Tuple[OAuthTokens, OAuthState]:
        """Exchange authorization code for tokens
        
        Args:
            code: Authorization code
            state: State parameter
            
        Returns:
            Tuple of (OAuth tokens, OAuth state)
            
        Raises:
            ValueError: If state is invalid or exchange fails
        """
        if not self.enabled:
            raise ValueError("OAuth client is not enabled")
        
        # Validate and consume state
        oauth_state = self.state_manager.consume_state(state)
        if not oauth_state:
            raise ValueError("Invalid or expired state parameter")
        
        try:
            # Prepare token request
            data = {
                'grant_type': 'authorization_code',
                'client_id': self.provider_config.client_id,
                'client_secret': self.provider_config.client_secret,
                'code': code,
                'redirect_uri': oauth_state.redirect_uri
            }
            
            # Add PKCE verifier
            if oauth_state.pkce_verifier:
                data['code_verifier'] = oauth_state.pkce_verifier
            
            # Make token request
            async with self._session.post(
                self.provider_config.token_endpoint,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                response_data = await response.json()
                
                if response.status != 200:
                    error_msg = response_data.get('error_description', response_data.get('error', 'Token exchange failed'))
                    raise ValueError(f"Token exchange failed: {error_msg}")
                
                tokens = OAuthTokens(
                    access_token=response_data['access_token'],
                    token_type=response_data.get('token_type', 'Bearer'),
                    expires_in=response_data.get('expires_in'),
                    refresh_token=response_data.get('refresh_token'),
                    scope=response_data.get('scope'),
                    id_token=response_data.get('id_token')
                )
                
                logger.info("Successfully exchanged authorization code for tokens")
                return tokens, oauth_state
                
        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            raise ValueError(f"Token exchange failed: {str(e)}")
    
    async def get_user_info(self, tokens: OAuthTokens) -> OAuthUserInfo:
        """Get user information from OAuth provider
        
        Args:
            tokens: OAuth tokens
            
        Returns:
            OAuth user information
        """
        if not self.enabled:
            raise ValueError("OAuth client is not enabled")
        
        if not self.provider_config.userinfo_endpoint:
            raise ValueError("Userinfo endpoint not configured")
        
        try:
            # Make userinfo request
            headers = {'Authorization': f'{tokens.token_type} {tokens.access_token}'}
            
            async with self._session.get(
                self.provider_config.userinfo_endpoint,
                headers=headers
            ) as response:
                response.raise_for_status()
                user_data = await response.json()
            
            # Extract user information using configured claims
            user_info = OAuthUserInfo(
                sub=str(user_data.get(self.provider_config.user_id_claim, '')),
                email=user_data.get(self.provider_config.email_claim),
                name=user_data.get(self.provider_config.name_claim),
                given_name=user_data.get('given_name'),
                family_name=user_data.get('family_name'),
                picture=user_data.get('picture'),
                locale=user_data.get('locale'),
                email_verified=user_data.get('email_verified'),
                roles=user_data.get(self.provider_config.roles_claim, self.provider_config.default_roles.copy()),
                raw_claims=user_data
            )
            
            logger.info(f"Retrieved user info for user: {user_info.sub}")
            return user_info
            
        except Exception as e:
            logger.error(f"Failed to get user info: {e}")
            raise ValueError(f"Failed to get user info: {str(e)}")
    
    async def refresh_tokens(self, refresh_token: str) -> OAuthTokens:
        """Refresh OAuth tokens
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New OAuth tokens
        """
        if not self.enabled:
            raise ValueError("OAuth client is not enabled")
        
        try:
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.provider_config.client_id,
                'client_secret': self.provider_config.client_secret,
                'refresh_token': refresh_token
            }
            
            async with self._session.post(
                self.provider_config.token_endpoint,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'}
            ) as response:
                response_data = await response.json()
                
                if response.status != 200:
                    error_msg = response_data.get('error_description', response_data.get('error', 'Token refresh failed'))
                    raise ValueError(f"Token refresh failed: {error_msg}")
                
                tokens = OAuthTokens(
                    access_token=response_data['access_token'],
                    token_type=response_data.get('token_type', 'Bearer'),
                    expires_in=response_data.get('expires_in'),
                    refresh_token=response_data.get('refresh_token', refresh_token),  # Keep old if not provided
                    scope=response_data.get('scope'),
                    id_token=response_data.get('id_token')
                )
                
                logger.info("Successfully refreshed OAuth tokens")
                return tokens
                
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise ValueError(f"Token refresh failed: {str(e)}")
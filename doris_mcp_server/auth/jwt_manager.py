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
JWT Manager Module
Provides comprehensive JWT token management including generation, validation, refresh and revocation
"""

import time
import uuid
import asyncio
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

try:
    import jwt
except ImportError:
    raise ImportError("PyJWT is required for JWT functionality. Install with: pip install PyJWT[crypto]")

from .key_manager import KeyManager
from .token_validators import TokenValidator, TokenBlacklist
from ..utils.logger import get_logger

logger = get_logger(__name__)


class JWTManager:
    """JWT Token Manager
    
    Provides comprehensive JWT token lifecycle management, including:
    - Token generation and signing
    - Token validation and parsing
    - Token refresh mechanism
    - Token revocation and blacklist
    - Automatic key rotation
    """
    
    def __init__(self, config):
        """Initialize JWT manager
        
        Args:
            config: DorisConfig configuration object (with security attribute)
        """
        self.config = config
        # Access JWT settings through the security configuration
        if hasattr(config, 'security'):
            security_config = config.security
        else:
            # Fallback if config is passed directly as SecurityConfig
            security_config = config
            
        self.algorithm = security_config.jwt_algorithm
        self.issuer = security_config.jwt_issuer
        self.audience = security_config.jwt_audience
        self.access_token_expiry = security_config.jwt_access_token_expiry
        self.refresh_token_expiry = security_config.jwt_refresh_token_expiry
        self.enable_refresh = security_config.enable_token_refresh
        self.enable_revocation = security_config.enable_token_revocation
        
        # Initialize components
        self.key_manager = KeyManager(config)
        self.token_blacklist = TokenBlacklist()
        self.validator = TokenValidator(config, self.token_blacklist)
        
        # Automatic key rotation task
        self._key_rotation_task = None
        
        logger.info(f"JWTManager initialized with algorithm: {self.algorithm}")
    
    async def initialize(self) -> bool:
        """Initialize JWT manager"""
        try:
            # Initialize key manager
            if not await self.key_manager.initialize():
                logger.error("Failed to initialize key manager")
                return False
            
            # Start token validator
            await self.validator.start()
            
            # Start automatic key rotation
            if self.key_manager.key_rotation_interval > 0:
                self._key_rotation_task = asyncio.create_task(self._auto_key_rotation())
            
            logger.info("JWTManager initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize JWTManager: {e}")
            return False
    
    async def shutdown(self):
        """Shutdown JWT manager"""
        try:
            # Stop key rotation task
            if self._key_rotation_task:
                self._key_rotation_task.cancel()
                try:
                    await self._key_rotation_task
                except asyncio.CancelledError:
                    pass
            
            # Stop validator
            await self.validator.stop()
            
            logger.info("JWTManager shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during JWTManager shutdown: {e}")
    
    async def generate_tokens(self, user_info: Dict[str, Any], 
                            custom_claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate access token and refresh token
        
        Args:
            user_info: User information dictionary, containing user_id, roles, permissions, etc.
            custom_claims: Custom claims
            
        Returns:
            Dictionary containing access_token and refresh_token
        """
        try:
            current_time = int(time.time())
            jti = str(uuid.uuid4())
            
            # Build base payload
            base_payload = {
                'iss': self.issuer,
                'aud': self.audience,
                'iat': current_time,
                'jti': jti,
                'sub': user_info.get('user_id'),
                'roles': user_info.get('roles', []),
                'permissions': user_info.get('permissions', []),
                'security_level': user_info.get('security_level', 'internal')
            }
            
            # Add custom claims
            if custom_claims:
                base_payload.update(custom_claims)
            
            # Generate access token
            access_payload = base_payload.copy()
            access_payload.update({
                'exp': current_time + self.access_token_expiry,
                'token_type': 'access'
            })
            
            access_token = await self._sign_token(access_payload)
            
            result = {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': self.access_token_expiry,
                'user_id': user_info.get('user_id'),
                'issued_at': current_time
            }
            
            # Generate refresh token (if enabled)
            if self.enable_refresh:
                refresh_jti = str(uuid.uuid4())
                refresh_payload = {
                    'iss': self.issuer,
                    'aud': self.audience,
                    'iat': current_time,
                    'exp': current_time + self.refresh_token_expiry,
                    'jti': refresh_jti,
                    'sub': user_info.get('user_id'),
                    'token_type': 'refresh',
                    'access_jti': jti  # Associated access token ID
                }
                
                refresh_token = await self._sign_token(refresh_payload)
                result.update({
                    'refresh_token': refresh_token,
                    'refresh_expires_in': self.refresh_token_expiry
                })
            
            logger.info(f"Generated tokens for user: {user_info.get('user_id')}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to generate tokens: {e}")
            raise
    
    async def _sign_token(self, payload: Dict[str, Any]) -> str:
        """Sign JWT token
        
        Args:
            payload: JWT payload
            
        Returns:
            Signed JWT token
        """
        try:
            signing_key = self.key_manager.get_private_key()
            
            if self.algorithm == "HS256":
                # Symmetric key signing
                token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
            else:
                # Asymmetric key signing
                token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
            
            return token
            
        except Exception as e:
            logger.error(f"Failed to sign token: {e}")
            raise
    
    async def validate_token(self, token: str, token_type: str = 'access') -> Dict[str, Any]:
        """Validate JWT token
        
        Args:
            token: JWT token string
            token_type: Token type ('access' or 'refresh')
            
        Returns:
            Validation result and user information
            
        Raises:
            ValueError: Token validation failed
        """
        try:
            # Decode token
            verification_key = self.key_manager.get_public_key()
            
            # Get security configuration
            if hasattr(self.config, 'security'):
                security_config = self.config.security
            else:
                security_config = self.config
            
            # JWT decoding options
            options = {
                'verify_signature': security_config.jwt_verify_signature,
                'verify_exp': security_config.jwt_require_exp,
                'verify_iat': security_config.jwt_require_iat,
                'verify_nbf': security_config.jwt_require_nbf,
                'verify_aud': security_config.jwt_verify_audience,
                'verify_iss': security_config.jwt_verify_issuer,
            }
            
            # Decode JWT
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                audience=self.audience if security_config.jwt_verify_audience else None,
                issuer=self.issuer if security_config.jwt_verify_issuer else None,
                leeway=security_config.jwt_leeway,
                options=options
            )
            
            # Check token type
            if payload.get('token_type') != token_type:
                raise ValueError(f"Invalid token type: expected {token_type}")
            
            # Use validator for additional checks
            validation_result = await self.validator.validate_claims(payload)
            
            logger.info(f"Token validation successful for user: {payload.get('sub')}")
            return validation_result
            
        except jwt.ExpiredSignatureError:
            raise ValueError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Invalid token: {str(e)}")
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            raise ValueError(f"Token validation failed: {str(e)}")
    
    async def refresh_token(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh access token
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New token pair
        """
        if not self.enable_refresh:
            raise ValueError("Token refresh is disabled")
        
        try:
            # Validate refresh token
            refresh_result = await self.validate_token(refresh_token, 'refresh')
            refresh_payload = refresh_result['payload']
            
            # Revoke associated access token (if revocation is enabled)
            if self.enable_revocation:
                access_jti = refresh_payload.get('access_jti')
                if access_jti:
                    # Should revoke old access token here, but since we don't know its expiration time,
                    # in practice might need to store more information or use different strategy
                    pass
            
            # Build new user information
            user_info = {
                'user_id': refresh_payload.get('sub'),
                'roles': refresh_payload.get('roles', []),
                'permissions': refresh_payload.get('permissions', []),
                'security_level': refresh_payload.get('security_level', 'internal')
            }
            
            # Generate new token pair
            new_tokens = await self.generate_tokens(user_info)
            
            logger.info(f"Token refreshed for user: {user_info['user_id']}")
            return new_tokens
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise
    
    async def revoke_token(self, token: str) -> bool:
        """Revoke token
        
        Args:
            token: Token to revoke
            
        Returns:
            Whether revocation was successful
        """
        if not self.enable_revocation:
            logger.warning("Token revocation is disabled")
            return False
        
        try:
            # Decode token to get JTI and expiration time
            verification_key = self.key_manager.get_public_key()
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                options={'verify_exp': False}  # Allow decoding expired tokens
            )
            
            jti = payload.get('jti')
            exp = payload.get('exp')
            
            if not jti or not exp:
                logger.error("Token missing required claims for revocation")
                return False
            
            # Add to blacklist
            await self.validator.revoke_token(jti, exp)
            
            logger.info(f"Token {jti} revoked successfully")
            return True
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    async def decode_token_unsafe(self, token: str) -> Dict[str, Any]:
        """Decode token without verifying signature (for debugging only)
        
        Args:
            token: JWT token
            
        Returns:
            Token payload
        """
        try:
            payload = jwt.decode(token, options={'verify_signature': False})
            return payload
        except Exception as e:
            logger.error(f"Failed to decode token: {e}")
            raise
    
    async def get_token_info(self, token: str) -> Dict[str, Any]:
        """Get token information (without verifying signature)
        
        Args:
            token: JWT token
            
        Returns:
            Token information
        """
        try:
            payload = await self.decode_token_unsafe(token)
            
            return {
                'jti': payload.get('jti'),
                'sub': payload.get('sub'),
                'iss': payload.get('iss'),
                'aud': payload.get('aud'),
                'iat': payload.get('iat'),
                'exp': payload.get('exp'),
                'token_type': payload.get('token_type'),
                'roles': payload.get('roles'),
                'permissions': payload.get('permissions'),
                'security_level': payload.get('security_level'),
                'is_expired': payload.get('exp', 0) < time.time() if payload.get('exp') else None
            }
            
        except Exception as e:
            logger.error(f"Failed to get token info: {e}")
            raise
    
    async def _auto_key_rotation(self):
        """Automatic key rotation task"""
        while True:
            try:
                # Check if key rotation is needed
                if await self.key_manager.is_key_expired():
                    logger.info("Key rotation needed, rotating keys...")
                    await self.key_manager.rotate_keys()
                
                # Wait until next check
                await asyncio.sleep(3600)  # Check every hour
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto key rotation: {e}")
                # Wait longer before retry after error
                await asyncio.sleep(3600)
    
    async def get_public_key_info(self) -> Dict[str, Any]:
        """Get public key information (for client verification)
        
        Returns:
            Public key information
        """
        key_info = await self.key_manager.get_key_info()
        public_key_pem = await self.key_manager.export_public_key_pem()
        
        return {
            'algorithm': self.algorithm,
            'public_key_pem': public_key_pem,
            'key_info': key_info
        }
    
    async def get_manager_stats(self) -> Dict[str, Any]:
        """Get manager statistics
        
        Returns:
            Statistics information
        """
        key_info = await self.key_manager.get_key_info()
        validation_stats = await self.validator.get_validation_stats()
        
        return {
            'jwt_config': {
                'algorithm': self.algorithm,
                'issuer': self.issuer,
                'audience': self.audience,
                'access_token_expiry': self.access_token_expiry,
                'refresh_token_expiry': self.refresh_token_expiry,
                'enable_refresh': self.enable_refresh,
                'enable_revocation': self.enable_revocation
            },
            'key_manager': key_info,
            'validator': validation_stats
        }
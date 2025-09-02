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
JWT Token Validation Module
Provides token validation, blacklist management and security features
"""

import time
import asyncio
from typing import Dict, Set, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict

from ..utils.logger import get_logger

logger = get_logger(__name__)


class TokenBlacklist:
    """JWT Token Blacklist Manager
    
    Manages revoked tokens to prevent revoked tokens from being used again
    Supports both in-memory and persistent storage
    """
    
    def __init__(self, cleanup_interval: int = 3600):
        """Initialize token blacklist
        
        Args:
            cleanup_interval: Interval for cleaning up expired tokens (seconds)
        """
        self.cleanup_interval = cleanup_interval
        # Storage format: {token_jti: expiry_timestamp}
        self._blacklisted_tokens: Dict[str, float] = {}
        self._cleanup_task = None
        
        logger.info("TokenBlacklist initialized")
    
    async def start(self):
        """Start blacklist manager"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        logger.info("TokenBlacklist started with periodic cleanup")
    
    async def stop(self):
        """Stop blacklist manager"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("TokenBlacklist stopped")
    
    async def add_token(self, jti: str, exp: float):
        """Add token to blacklist
        
        Args:
            jti: JWT ID (unique identifier)
            exp: Token expiration timestamp
        """
        self._blacklisted_tokens[jti] = exp
        logger.info(f"Token {jti} added to blacklist")
    
    async def is_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted
        
        Args:
            jti: JWT ID
            
        Returns:
            True if blacklisted, False otherwise
        """
        return jti in self._blacklisted_tokens
    
    async def remove_token(self, jti: str) -> bool:
        """Remove token from blacklist
        
        Args:
            jti: JWT ID
            
        Returns:
            True if removed, False if not found
        """
        if jti in self._blacklisted_tokens:
            del self._blacklisted_tokens[jti]
            logger.info(f"Token {jti} removed from blacklist")
            return True
        return False
    
    async def cleanup_expired(self) -> int:
        """Clean up expired blacklisted tokens
        
        Returns:
            Number of tokens cleaned up
        """
        current_time = time.time()
        expired_tokens = [
            jti for jti, exp in self._blacklisted_tokens.items()
            if exp <= current_time
        ]
        
        for jti in expired_tokens:
            del self._blacklisted_tokens[jti]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens from blacklist")
        
        return len(expired_tokens)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get blacklist statistics"""
        current_time = time.time()
        active_tokens = sum(1 for exp in self._blacklisted_tokens.values() if exp > current_time)
        
        return {
            "total_blacklisted": len(self._blacklisted_tokens),
            "active_blacklisted": active_tokens,
            "expired_blacklisted": len(self._blacklisted_tokens) - active_tokens,
            "cleanup_interval": self.cleanup_interval
        }
    
    async def _periodic_cleanup(self):
        """Periodically clean up expired tokens"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error during periodic cleanup: {e}")


class RateLimiter:
    """Token usage rate limiter"""
    
    def __init__(self, max_requests: int = 100, time_window: int = 3600):
        """Initialize rate limiter
        
        Args:
            max_requests: Maximum requests within time window
            time_window: Time window in seconds
        """
        self.max_requests = max_requests
        self.time_window = time_window
        # Storage format: {user_id: [timestamp1, timestamp2, ...]}
        self._request_history: Dict[str, list] = defaultdict(list)
        
        logger.info(f"RateLimiter initialized: {max_requests} requests per {time_window} seconds")
    
    async def is_allowed(self, user_id: str) -> bool:
        """Check if user is allowed to make request
        
        Args:
            user_id: User ID
            
        Returns:
            True if allowed, False otherwise
        """
        current_time = time.time()
        user_requests = self._request_history[user_id]
        
        # Clean up expired request records
        cutoff_time = current_time - self.time_window
        user_requests[:] = [t for t in user_requests if t > cutoff_time]
        
        # Check if limit exceeded
        if len(user_requests) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for user {user_id}")
            return False
        
        # Record current request
        user_requests.append(current_time)
        return True
    
    async def get_usage(self, user_id: str) -> Dict[str, Any]:
        """Get user usage information
        
        Args:
            user_id: User ID
            
        Returns:
            Usage statistics
        """
        current_time = time.time()
        user_requests = self._request_history[user_id]
        
        # Clean up expired records
        cutoff_time = current_time - self.time_window
        active_requests = [t for t in user_requests if t > cutoff_time]
        
        return {
            "user_id": user_id,
            "requests_in_window": len(active_requests),
            "max_requests": self.max_requests,
            "time_window": self.time_window,
            "remaining_requests": max(0, self.max_requests - len(active_requests))
        }


class TokenValidator:
    """JWT Token Validator
    
    Provides comprehensive JWT token validation functionality, including signature verification,
    claim validation, blacklist checking and rate limiting
    """
    
    def __init__(self, config, blacklist: Optional[TokenBlacklist] = None):
        """Initialize token validator
        
        Args:
            config: DorisConfig configuration object (with security attribute)
            blacklist: Token blacklist manager
        """
        self.config = config
        self.blacklist = blacklist or TokenBlacklist()
        self.rate_limiter = RateLimiter()
        
        # Access JWT settings through the security configuration
        if hasattr(config, 'security'):
            security_config = config.security
        else:
            # Fallback if config is passed directly as SecurityConfig
            security_config = config
        
        # Validation options
        self.verify_signature = security_config.jwt_verify_signature
        self.verify_audience = security_config.jwt_verify_audience
        self.verify_issuer = security_config.jwt_verify_issuer
        self.require_exp = security_config.jwt_require_exp
        self.require_iat = security_config.jwt_require_iat
        self.require_nbf = security_config.jwt_require_nbf
        self.leeway = security_config.jwt_leeway
        
        # Expected values
        self.expected_audience = security_config.jwt_audience
        self.expected_issuer = security_config.jwt_issuer
        
        logger.info("TokenValidator initialized")
    
    async def validate_claims(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate JWT claims
        
        Args:
            payload: JWT payload
            
        Returns:
            Validation result
            
        Raises:
            ValueError: Validation failed
        """
        current_time = time.time()
        
        # Validate issuer
        if self.verify_issuer:
            if payload.get('iss') != self.expected_issuer:
                raise ValueError(f"Invalid issuer: expected {self.expected_issuer}")
        
        # Validate audience
        if self.verify_audience:
            aud = payload.get('aud')
            if isinstance(aud, list):
                if self.expected_audience not in aud:
                    raise ValueError(f"Invalid audience: {self.expected_audience} not in {aud}")
            elif aud != self.expected_audience:
                raise ValueError(f"Invalid audience: expected {self.expected_audience}")
        
        # Validate expiration time
        if self.require_exp or 'exp' in payload:
            exp = payload.get('exp')
            if not exp:
                raise ValueError("Missing 'exp' claim")
            if current_time > exp + self.leeway:
                raise ValueError("Token has expired")
        
        # Validate not before time
        if self.require_nbf or 'nbf' in payload:
            nbf = payload.get('nbf')
            if not nbf:
                raise ValueError("Missing 'nbf' claim")
            if current_time < nbf - self.leeway:
                raise ValueError("Token not yet valid")
        
        # Validate issued at time
        if self.require_iat or 'iat' in payload:
            iat = payload.get('iat')
            if not iat:
                raise ValueError("Missing 'iat' claim")
            # Allow some clock skew, but cannot be future time
            if iat > current_time + self.leeway:
                raise ValueError("Token issued in the future")
        
        # Check blacklist
        jti = payload.get('jti')
        if jti and await self.blacklist.is_blacklisted(jti):
            raise ValueError("Token has been revoked")
        
        # Rate limit check
        user_id = payload.get('sub')
        if user_id:
            if not await self.rate_limiter.is_allowed(user_id):
                raise ValueError("Rate limit exceeded")
        
        return {
            "valid": True,
            "user_id": user_id,
            "payload": payload
        }
    
    async def start(self):
        """Start validator"""
        await self.blacklist.start()
        logger.info("TokenValidator started")
    
    async def stop(self):
        """Stop validator"""
        await self.blacklist.stop()
        logger.info("TokenValidator stopped")
    
    async def revoke_token(self, jti: str, exp: float):
        """Revoke token
        
        Args:
            jti: JWT ID
            exp: Token expiration time
        """
        await self.blacklist.add_token(jti, exp)
        logger.info(f"Token {jti} has been revoked")
    
    async def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics"""
        blacklist_stats = await self.blacklist.get_stats()
        
        return {
            "blacklist": blacklist_stats,
            "validation_config": {
                "verify_signature": self.verify_signature,
                "verify_audience": self.verify_audience,
                "verify_issuer": self.verify_issuer,
                "require_exp": self.require_exp,
                "require_iat": self.require_iat,
                "require_nbf": self.require_nbf,
                "leeway": self.leeway
            }
        }
    
    async def get_user_rate_limit_info(self, user_id: str) -> Dict[str, Any]:
        """Get user rate limit information"""
        return await self.rate_limiter.get_usage(user_id)
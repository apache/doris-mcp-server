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
    """JWT令牌黑名单管理器
    
    管理已撤销的令牌，防止被撤销的令牌继续使用
    支持内存和持久化存储
    """
    
    def __init__(self, cleanup_interval: int = 3600):
        """初始化令牌黑名单
        
        Args:
            cleanup_interval: 清理过期令牌的间隔(秒)
        """
        self.cleanup_interval = cleanup_interval
        # 存储格式: {token_jti: expiry_timestamp}
        self._blacklisted_tokens: Dict[str, float] = {}
        self._cleanup_task = None
        
        logger.info("TokenBlacklist initialized")
    
    async def start(self):
        """启动黑名单管理器"""
        self._cleanup_task = asyncio.create_task(self._periodic_cleanup())
        logger.info("TokenBlacklist started with periodic cleanup")
    
    async def stop(self):
        """停止黑名单管理器"""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("TokenBlacklist stopped")
    
    async def add_token(self, jti: str, exp: float):
        """添加令牌到黑名单
        
        Args:
            jti: JWT ID (唯一标识符)
            exp: 令牌过期时间戳
        """
        self._blacklisted_tokens[jti] = exp
        logger.info(f"Token {jti} added to blacklist")
    
    async def is_blacklisted(self, jti: str) -> bool:
        """检查令牌是否在黑名单中
        
        Args:
            jti: JWT ID
            
        Returns:
            True if blacklisted, False otherwise
        """
        return jti in self._blacklisted_tokens
    
    async def remove_token(self, jti: str) -> bool:
        """从黑名单移除令牌
        
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
        """清理过期的黑名单令牌
        
        Returns:
            清理的令牌数量
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
        """获取黑名单统计信息"""
        current_time = time.time()
        active_tokens = sum(1 for exp in self._blacklisted_tokens.values() if exp > current_time)
        
        return {
            "total_blacklisted": len(self._blacklisted_tokens),
            "active_blacklisted": active_tokens,
            "expired_blacklisted": len(self._blacklisted_tokens) - active_tokens,
            "cleanup_interval": self.cleanup_interval
        }
    
    async def _periodic_cleanup(self):
        """定期清理过期令牌"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error during periodic cleanup: {e}")


class RateLimiter:
    """令牌使用率限制器"""
    
    def __init__(self, max_requests: int = 100, time_window: int = 3600):
        """初始化速率限制器
        
        Args:
            max_requests: 时间窗口内最大请求数
            time_window: 时间窗口(秒)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        # 存储格式: {user_id: [timestamp1, timestamp2, ...]}
        self._request_history: Dict[str, list] = defaultdict(list)
        
        logger.info(f"RateLimiter initialized: {max_requests} requests per {time_window} seconds")
    
    async def is_allowed(self, user_id: str) -> bool:
        """检查用户是否允许请求
        
        Args:
            user_id: 用户ID
            
        Returns:
            True if allowed, False otherwise
        """
        current_time = time.time()
        user_requests = self._request_history[user_id]
        
        # 清理过期的请求记录
        cutoff_time = current_time - self.time_window
        user_requests[:] = [t for t in user_requests if t > cutoff_time]
        
        # 检查是否超过限制
        if len(user_requests) >= self.max_requests:
            logger.warning(f"Rate limit exceeded for user {user_id}")
            return False
        
        # 记录当前请求
        user_requests.append(current_time)
        return True
    
    async def get_usage(self, user_id: str) -> Dict[str, Any]:
        """获取用户使用情况
        
        Args:
            user_id: 用户ID
            
        Returns:
            使用情况统计
        """
        current_time = time.time()
        user_requests = self._request_history[user_id]
        
        # 清理过期记录
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
    """JWT令牌验证器
    
    提供全面的JWT令牌验证功能，包括签名验证、声明验证、
    黑名单检查和速率限制
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
        """验证JWT声明
        
        Args:
            payload: JWT载荷
            
        Returns:
            验证结果
            
        Raises:
            ValueError: 验证失败
        """
        current_time = time.time()
        
        # 验证issuer
        if self.verify_issuer:
            if payload.get('iss') != self.expected_issuer:
                raise ValueError(f"Invalid issuer: expected {self.expected_issuer}")
        
        # 验证audience
        if self.verify_audience:
            aud = payload.get('aud')
            if isinstance(aud, list):
                if self.expected_audience not in aud:
                    raise ValueError(f"Invalid audience: {self.expected_audience} not in {aud}")
            elif aud != self.expected_audience:
                raise ValueError(f"Invalid audience: expected {self.expected_audience}")
        
        # 验证过期时间
        if self.require_exp or 'exp' in payload:
            exp = payload.get('exp')
            if not exp:
                raise ValueError("Missing 'exp' claim")
            if current_time > exp + self.leeway:
                raise ValueError("Token has expired")
        
        # 验证生效时间
        if self.require_nbf or 'nbf' in payload:
            nbf = payload.get('nbf')
            if not nbf:
                raise ValueError("Missing 'nbf' claim")
            if current_time < nbf - self.leeway:
                raise ValueError("Token not yet valid")
        
        # 验证签发时间
        if self.require_iat or 'iat' in payload:
            iat = payload.get('iat')
            if not iat:
                raise ValueError("Missing 'iat' claim")
            # 允许一定的时钟偏差，但不能是未来的时间
            if iat > current_time + self.leeway:
                raise ValueError("Token issued in the future")
        
        # 检查黑名单
        jti = payload.get('jti')
        if jti and await self.blacklist.is_blacklisted(jti):
            raise ValueError("Token has been revoked")
        
        # 速率限制检查
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
        """启动验证器"""
        await self.blacklist.start()
        logger.info("TokenValidator started")
    
    async def stop(self):
        """停止验证器"""
        await self.blacklist.stop()
        logger.info("TokenValidator stopped")
    
    async def revoke_token(self, jti: str, exp: float):
        """撤销令牌
        
        Args:
            jti: JWT ID
            exp: 令牌过期时间
        """
        await self.blacklist.add_token(jti, exp)
        logger.info(f"Token {jti} has been revoked")
    
    async def get_validation_stats(self) -> Dict[str, Any]:
        """获取验证统计信息"""
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
        """获取用户速率限制信息"""
        return await self.rate_limiter.get_usage(user_id)
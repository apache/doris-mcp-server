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
    """JWT令牌管理器
    
    提供完整的JWT令牌生命周期管理，包括：
    - 令牌生成和签名
    - 令牌验证和解析
    - 令牌刷新机制
    - 令牌撤销和黑名单
    - 自动密钥轮换
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
        
        # 初始化组件
        self.key_manager = KeyManager(config)
        self.token_blacklist = TokenBlacklist()
        self.validator = TokenValidator(config, self.token_blacklist)
        
        # 自动密钥轮换任务
        self._key_rotation_task = None
        
        logger.info(f"JWTManager initialized with algorithm: {self.algorithm}")
    
    async def initialize(self) -> bool:
        """初始化JWT管理器"""
        try:
            # 初始化密钥管理器
            if not await self.key_manager.initialize():
                logger.error("Failed to initialize key manager")
                return False
            
            # 启动令牌验证器
            await self.validator.start()
            
            # 启动自动密钥轮换
            if self.key_manager.key_rotation_interval > 0:
                self._key_rotation_task = asyncio.create_task(self._auto_key_rotation())
            
            logger.info("JWTManager initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize JWTManager: {e}")
            return False
    
    async def shutdown(self):
        """关闭JWT管理器"""
        try:
            # 停止密钥轮换任务
            if self._key_rotation_task:
                self._key_rotation_task.cancel()
                try:
                    await self._key_rotation_task
                except asyncio.CancelledError:
                    pass
            
            # 停止验证器
            await self.validator.stop()
            
            logger.info("JWTManager shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during JWTManager shutdown: {e}")
    
    async def generate_tokens(self, user_info: Dict[str, Any], 
                            custom_claims: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """生成访问令牌和刷新令牌
        
        Args:
            user_info: 用户信息字典，包含user_id, roles, permissions等
            custom_claims: 自定义声明
            
        Returns:
            包含access_token和refresh_token的字典
        """
        try:
            current_time = int(time.time())
            jti = str(uuid.uuid4())
            
            # 构建基础载荷
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
            
            # 添加自定义声明
            if custom_claims:
                base_payload.update(custom_claims)
            
            # 生成访问令牌
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
            
            # 生成刷新令牌（如果启用）
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
                    'access_jti': jti  # 关联的访问令牌ID
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
        """签名JWT令牌
        
        Args:
            payload: JWT载荷
            
        Returns:
            签名后的JWT令牌
        """
        try:
            signing_key = self.key_manager.get_private_key()
            
            if self.algorithm == "HS256":
                # 对称密钥签名
                token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
            else:
                # 非对称密钥签名
                token = jwt.encode(payload, signing_key, algorithm=self.algorithm)
            
            return token
            
        except Exception as e:
            logger.error(f"Failed to sign token: {e}")
            raise
    
    async def validate_token(self, token: str, token_type: str = 'access') -> Dict[str, Any]:
        """验证JWT令牌
        
        Args:
            token: JWT令牌字符串
            token_type: 令牌类型 ('access' 或 'refresh')
            
        Returns:
            验证结果和用户信息
            
        Raises:
            ValueError: 令牌验证失败
        """
        try:
            # 解码令牌
            verification_key = self.key_manager.get_public_key()
            
            # Get security configuration
            if hasattr(self.config, 'security'):
                security_config = self.config.security
            else:
                security_config = self.config
            
            # JWT解码选项
            options = {
                'verify_signature': security_config.jwt_verify_signature,
                'verify_exp': security_config.jwt_require_exp,
                'verify_iat': security_config.jwt_require_iat,
                'verify_nbf': security_config.jwt_require_nbf,
                'verify_aud': security_config.jwt_verify_audience,
                'verify_iss': security_config.jwt_verify_issuer,
            }
            
            # 解码JWT
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                audience=self.audience if security_config.jwt_verify_audience else None,
                issuer=self.issuer if security_config.jwt_verify_issuer else None,
                leeway=security_config.jwt_leeway,
                options=options
            )
            
            # 检查令牌类型
            if payload.get('token_type') != token_type:
                raise ValueError(f"Invalid token type: expected {token_type}")
            
            # 使用验证器进行额外检查
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
        """刷新访问令牌
        
        Args:
            refresh_token: 刷新令牌
            
        Returns:
            新的令牌对
        """
        if not self.enable_refresh:
            raise ValueError("Token refresh is disabled")
        
        try:
            # 验证刷新令牌
            refresh_result = await self.validate_token(refresh_token, 'refresh')
            refresh_payload = refresh_result['payload']
            
            # 撤销关联的访问令牌（如果启用撤销功能）
            if self.enable_revocation:
                access_jti = refresh_payload.get('access_jti')
                if access_jti:
                    # 这里应该撤销旧的访问令牌，但由于我们无法知道其过期时间，
                    # 在实际应用中可能需要存储更多信息或使用不同的策略
                    pass
            
            # 构建新的用户信息
            user_info = {
                'user_id': refresh_payload.get('sub'),
                'roles': refresh_payload.get('roles', []),
                'permissions': refresh_payload.get('permissions', []),
                'security_level': refresh_payload.get('security_level', 'internal')
            }
            
            # 生成新的令牌对
            new_tokens = await self.generate_tokens(user_info)
            
            logger.info(f"Token refreshed for user: {user_info['user_id']}")
            return new_tokens
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise
    
    async def revoke_token(self, token: str) -> bool:
        """撤销令牌
        
        Args:
            token: 要撤销的令牌
            
        Returns:
            撤销是否成功
        """
        if not self.enable_revocation:
            logger.warning("Token revocation is disabled")
            return False
        
        try:
            # 解码令牌获取JTI和过期时间
            verification_key = self.key_manager.get_public_key()
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[self.algorithm],
                options={'verify_exp': False}  # 允许解码过期令牌
            )
            
            jti = payload.get('jti')
            exp = payload.get('exp')
            
            if not jti or not exp:
                logger.error("Token missing required claims for revocation")
                return False
            
            # 添加到黑名单
            await self.validator.revoke_token(jti, exp)
            
            logger.info(f"Token {jti} revoked successfully")
            return True
            
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False
    
    async def decode_token_unsafe(self, token: str) -> Dict[str, Any]:
        """不验证签名地解码令牌（仅用于调试）
        
        Args:
            token: JWT令牌
            
        Returns:
            令牌载荷
        """
        try:
            payload = jwt.decode(token, options={'verify_signature': False})
            return payload
        except Exception as e:
            logger.error(f"Failed to decode token: {e}")
            raise
    
    async def get_token_info(self, token: str) -> Dict[str, Any]:
        """获取令牌信息（不验证签名）
        
        Args:
            token: JWT令牌
            
        Returns:
            令牌信息
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
        """自动密钥轮换任务"""
        while True:
            try:
                # 检查密钥是否需要轮换
                if await self.key_manager.is_key_expired():
                    logger.info("Key rotation needed, rotating keys...")
                    await self.key_manager.rotate_keys()
                
                # 等待到下次检查
                await asyncio.sleep(3600)  # 每小时检查一次
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in auto key rotation: {e}")
                # 出错后等待较长时间再重试
                await asyncio.sleep(3600)
    
    async def get_public_key_info(self) -> Dict[str, Any]:
        """获取公钥信息（用于客户端验证）
        
        Returns:
            公钥信息
        """
        key_info = await self.key_manager.get_key_info()
        public_key_pem = await self.key_manager.export_public_key_pem()
        
        return {
            'algorithm': self.algorithm,
            'public_key_pem': public_key_pem,
            'key_info': key_info
        }
    
    async def get_manager_stats(self) -> Dict[str, Any]:
        """获取管理器统计信息
        
        Returns:
            统计信息
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
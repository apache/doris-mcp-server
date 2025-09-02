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
Authentication Middleware Module
Provides middleware for JWT authentication in HTTP and MCP contexts
"""

from typing import Optional, Dict, Any, Callable, Awaitable
from datetime import datetime

from .jwt_manager import JWTManager
from ..utils.security import AuthContext, SecurityLevel
from ..utils.logger import get_logger

logger = get_logger(__name__)


class AuthMiddleware:
    """认证中间件
    
    为HTTP和MCP请求提供JWT认证功能
    """
    
    def __init__(self, jwt_manager: JWTManager):
        """初始化认证中间件
        
        Args:
            jwt_manager: JWT管理器实例
        """
        self.jwt_manager = jwt_manager
        logger.info("AuthMiddleware initialized")
    
    def extract_token_from_header(self, authorization: str) -> Optional[str]:
        """从Authorization头提取JWT令牌
        
        Args:
            authorization: Authorization头的值
            
        Returns:
            JWT令牌字符串，如果没有则返回None
        """
        if not authorization:
            return None
        
        # 支持 Bearer 格式
        if authorization.startswith('Bearer '):
            return authorization[7:]  # 去除 "Bearer " 前缀
        
        # 支持直接的token格式
        if not authorization.startswith('Basic '):
            return authorization
        
        return None
    
    async def authenticate_request(self, auth_info: Dict[str, Any]) -> AuthContext:
        """认证请求并返回认证上下文
        
        Args:
            auth_info: 认证信息字典
            
        Returns:
            AuthContext认证上下文
            
        Raises:
            ValueError: 认证失败
        """
        try:
            auth_type = auth_info.get("type", "jwt")
            
            if auth_type == "jwt" or auth_type == "token":
                return await self._authenticate_jwt(auth_info)
            else:
                raise ValueError(f"Unsupported authentication type: {auth_type}")
                
        except Exception as e:
            logger.error(f"Request authentication failed: {e}")
            raise
    
    async def _authenticate_jwt(self, auth_info: Dict[str, Any]) -> AuthContext:
        """JWT认证处理
        
        Args:
            auth_info: 包含JWT令牌的认证信息
            
        Returns:
            AuthContext认证上下文
        """
        # 获取令牌
        token = auth_info.get("token")
        if not token:
            # 尝试从Authorization头获取
            authorization = auth_info.get("authorization")
            token = self.extract_token_from_header(authorization)
        
        if not token:
            raise ValueError("Missing JWT token")
        
        try:
            # 验证令牌
            validation_result = await self.jwt_manager.validate_token(token, 'access')
            payload = validation_result['payload']
            
            # 构建认证上下文
            auth_context = AuthContext(
                user_id=payload.get('sub'),
                roles=payload.get('roles', []),
                permissions=payload.get('permissions', []),
                session_id=payload.get('jti'),  # 使用JWT ID作为会话ID
                login_time=datetime.fromtimestamp(payload.get('iat', 0)),
                last_activity=datetime.utcnow(),
                security_level=SecurityLevel(payload.get('security_level', 'internal'))
            )
            
            logger.info(f"JWT authentication successful for user: {auth_context.user_id}")
            return auth_context
            
        except Exception as e:
            logger.error(f"JWT authentication failed: {e}")
            raise ValueError(f"JWT authentication failed: {str(e)}")
    
    async def create_auth_response_headers(self, auth_context: AuthContext) -> Dict[str, str]:
        """创建认证响应头
        
        Args:
            auth_context: 认证上下文
            
        Returns:
            响应头字典
        """
        return {
            'X-Auth-User': auth_context.user_id,
            'X-Auth-Roles': ','.join(auth_context.roles),
            'X-Auth-Session': auth_context.session_id,
            'X-Auth-Security-Level': auth_context.security_level.value
        }
    
    def create_http_middleware(self, skip_paths: Optional[list] = None):
        """创建HTTP中间件函数
        
        Args:
            skip_paths: 跳过认证的路径列表
            
        Returns:
            ASGI中间件函数
        """
        skip_paths = skip_paths or ['/health', '/docs', '/openapi.json']
        
        async def middleware(scope, receive, send):
            """HTTP认证中间件"""
            if scope['type'] != 'http':
                # 非HTTP请求直接传递
                return await self.app(scope, receive, send)
            
            path = scope.get('path', '')
            
            # 检查是否跳过认证
            if any(path.startswith(skip) for skip in skip_paths):
                return await self.app(scope, receive, send)
            
            # 提取认证信息
            headers = dict(scope.get('headers', []))
            authorization = headers.get(b'authorization', b'').decode()
            
            try:
                # 进行认证
                auth_info = {
                    'type': 'jwt',
                    'authorization': authorization
                }
                auth_context = await self.authenticate_request(auth_info)
                
                # 将认证上下文添加到scope
                scope['auth_context'] = auth_context
                
                # 创建响应包装器来添加认证头
                async def send_wrapper(message):
                    if message['type'] == 'http.response.start':
                        headers = dict(message.get('headers', []))
                        auth_headers = await self.create_auth_response_headers(auth_context)
                        
                        for key, value in auth_headers.items():
                            headers[key.encode()] = value.encode()
                        
                        message['headers'] = list(headers.items())
                    
                    await send(message)
                
                return await self.app(scope, receive, send_wrapper)
                
            except Exception as e:
                # 认证失败，返回401错误
                response_body = f'{{"error": "Authentication failed", "message": "{str(e)}"}}'
                
                await send({
                    'type': 'http.response.start',
                    'status': 401,
                    'headers': [
                        (b'content-type', b'application/json'),
                        (b'www-authenticate', b'Bearer')
                    ]
                })
                await send({
                    'type': 'http.response.body',
                    'body': response_body.encode()
                })
        
        return middleware
    
    async def authenticate_mcp_request(self, headers: Dict[str, str]) -> AuthContext:
        """认证MCP请求
        
        Args:
            headers: MCP请求头
            
        Returns:
            AuthContext认证上下文
        """
        try:
            # 从多个可能的头字段提取认证信息
            authorization = (
                headers.get('Authorization') or 
                headers.get('authorization') or
                headers.get('X-Auth-Token') or
                headers.get('x-auth-token')
            )
            
            auth_info = {
                'type': 'jwt',
                'authorization': authorization
            }
            
            return await self.authenticate_request(auth_info)
            
        except Exception as e:
            logger.error(f"MCP request authentication failed: {e}")
            raise


class AuthenticationError(Exception):
    """认证错误异常"""
    
    def __init__(self, message: str, error_code: str = "AUTH_FAILED"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class AuthorizationError(Exception):
    """授权错误异常"""
    
    def __init__(self, message: str, error_code: str = "ACCESS_DENIED"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)
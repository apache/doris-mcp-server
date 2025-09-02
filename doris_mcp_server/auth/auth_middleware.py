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
    """Authentication Middleware
    
    Provides JWT authentication functionality for HTTP and MCP requests
    """
    
    def __init__(self, jwt_manager: JWTManager):
        """Initialize authentication middleware
        
        Args:
            jwt_manager: JWT manager instance
        """
        self.jwt_manager = jwt_manager
        logger.info("AuthMiddleware initialized")
    
    def extract_token_from_header(self, authorization: str) -> Optional[str]:
        """Extract JWT token from Authorization header
        
        Args:
            authorization: Authorization header value
            
        Returns:
            JWT token string, or None if not found
        """
        if not authorization:
            return None
        
        # Support Bearer format
        if authorization.startswith('Bearer '):
            return authorization[7:]  # Remove "Bearer " prefix
        
        # Support direct token format
        if not authorization.startswith('Basic '):
            return authorization
        
        return None
    
    async def authenticate_request(self, auth_info: Dict[str, Any]) -> AuthContext:
        """Authenticate request and return authentication context
        
        Args:
            auth_info: Authentication information dictionary
            
        Returns:
            AuthContext authentication context
            
        Raises:
            ValueError: Authentication failed
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
        """JWT authentication processing
        
        Args:
            auth_info: Authentication information containing JWT token
            
        Returns:
            AuthContext authentication context
        """
        # Get token
        token = auth_info.get("token")
        if not token:
            # Try to get from Authorization header
            authorization = auth_info.get("authorization")
            token = self.extract_token_from_header(authorization)
        
        if not token:
            raise ValueError("Missing JWT token")
        
        try:
            # Validate token
            validation_result = await self.jwt_manager.validate_token(token, 'access')
            payload = validation_result['payload']
            
            # Build authentication context
            auth_context = AuthContext(
                token_id=payload.get('jti', ''),
                user_id=payload.get('sub'),
                roles=payload.get('roles', []),
                permissions=payload.get('permissions', []),
                security_level=SecurityLevel(payload.get('security_level', 'internal')),
                session_id=payload.get('jti'),  # Use JWT ID as session ID
                login_time=datetime.fromtimestamp(payload.get('iat', 0)),
                last_activity=datetime.utcnow(),
                token=token  # Store raw token for token-bound database configuration
            )
            
            logger.info(f"JWT authentication successful for user: {auth_context.user_id}")
            return auth_context
            
        except Exception as e:
            logger.error(f"JWT authentication failed: {e}")
            raise ValueError(f"JWT authentication failed: {str(e)}")
    
    async def create_auth_response_headers(self, auth_context: AuthContext) -> Dict[str, str]:
        """Create authentication response headers
        
        Args:
            auth_context: Authentication context
            
        Returns:
            Response headers dictionary
        """
        return {
            'X-Auth-User': auth_context.user_id,
            'X-Auth-Roles': ','.join(auth_context.roles),
            'X-Auth-Session': auth_context.session_id,
            'X-Auth-Security-Level': auth_context.security_level.value
        }
    
    def create_http_middleware(self, skip_paths: Optional[list] = None):
        """Create HTTP middleware function
        
        Args:
            skip_paths: List of paths to skip authentication
            
        Returns:
            ASGI middleware function
        """
        skip_paths = skip_paths or ['/health', '/docs', '/openapi.json']
        
        async def middleware(scope, receive, send):
            """HTTP authentication middleware"""
            if scope['type'] != 'http':
                # Pass through non-HTTP requests directly
                return await self.app(scope, receive, send)
            
            path = scope.get('path', '')
            
            # Check if authentication should be skipped
            if any(path.startswith(skip) for skip in skip_paths):
                return await self.app(scope, receive, send)
            
            # Extract authentication information
            headers = dict(scope.get('headers', []))
            authorization = headers.get(b'authorization', b'').decode()
            
            try:
                # Perform authentication
                auth_info = {
                    'type': 'jwt',
                    'authorization': authorization
                }
                auth_context = await self.authenticate_request(auth_info)
                
                # Add authentication context to scope
                scope['auth_context'] = auth_context
                
                # Create response wrapper to add authentication headers
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
                # Authentication failed, return 401 error
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
        """Authenticate MCP request
        
        Args:
            headers: MCP request headers
            
        Returns:
            AuthContext authentication context
        """
        try:
            # Extract authentication information from multiple possible header fields
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
    """Authentication error exception"""
    
    def __init__(self, message: str, error_code: str = "AUTH_FAILED"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)


class AuthorizationError(Exception):
    """Authorization error exception"""
    
    def __init__(self, message: str, error_code: str = "ACCESS_DENIED"):
        self.message = message
        self.error_code = error_code
        super().__init__(message)
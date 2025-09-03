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
Token Management Security Middleware

Provides comprehensive security controls for token management endpoints including
IP restrictions, admin authentication, and configuration-based access control.
"""

import hashlib
import hmac
import ipaddress
import secrets
import time
from typing import Optional, List, Dict, Any
from starlette.requests import Request
from starlette.responses import JSONResponse

from ..utils.logger import get_logger
from ..utils.config import DorisConfig


class TokenSecurityMiddleware:
    """Security middleware for token management endpoints"""
    
    def __init__(self, config: DorisConfig):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Initialize admin token hash if provided
        self._admin_token_hash = None
        if config.security.token_management_admin_token:
            self._admin_token_hash = self._hash_token(config.security.token_management_admin_token)
            
        # Normalize allowed IPs
        self._allowed_networks = self._parse_allowed_networks(
            config.security.token_management_allowed_ips
        )
        
        self.logger.info(f"Token management security initialized: "
                        f"HTTP endpoints {'enabled' if config.security.enable_http_token_management else 'disabled'}, "
                        f"Admin auth {'required' if config.security.require_admin_auth else 'optional'}, "
                        f"Allowed networks: {len(self._allowed_networks)}")
    
    def _hash_token(self, token: str) -> str:
        """Hash token using SHA-256"""
        return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    def _parse_allowed_networks(self, allowed_ips: List[str]) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse allowed IP addresses and networks"""
        networks = []
        for ip_str in allowed_ips:
            try:
                # Try to parse as network (CIDR notation)
                if '/' in ip_str:
                    networks.append(ipaddress.ip_network(ip_str, strict=False))
                else:
                    # Parse as single IP and convert to /32 network
                    ip = ipaddress.ip_address(ip_str)
                    if isinstance(ip, ipaddress.IPv4Address):
                        networks.append(ipaddress.IPv4Network(f"{ip}/32"))
                    else:
                        networks.append(ipaddress.IPv6Network(f"{ip}/128"))
            except ValueError as e:
                self.logger.warning(f"Invalid IP/network '{ip_str}': {e}")
        
        return networks
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, considering proxies"""
        # Check X-Forwarded-For header first (for proxy setups)
        forwarded_for = request.headers.get('X-Forwarded-For')
        if forwarded_for:
            # Take the first IP (original client)
            client_ip = forwarded_for.split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            client_ip = request.headers.get('X-Real-IP')
        else:
            # Direct connection
            client_ip = request.client.host if request.client else "unknown"
        
        return client_ip
    
    def _is_ip_allowed(self, client_ip: str) -> bool:
        """Check if client IP is in allowed networks"""
        try:
            client_addr = ipaddress.ip_address(client_ip)
            
            for network in self._allowed_networks:
                if client_addr in network:
                    return True
                    
            return False
            
        except ValueError:
            self.logger.warning(f"Invalid client IP format: {client_ip}")
            return False
    
    def _extract_admin_token(self, request: Request) -> Optional[str]:
        """Extract admin token from request headers"""
        # Try Authorization header first
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]
        elif auth_header.startswith('Token '):
            return auth_header[6:]
        
        # Try X-Admin-Token header
        admin_token = request.headers.get('X-Admin-Token', '')
        if admin_token:
            return admin_token
        
        # Try query parameter as fallback (not recommended for production)
        admin_token = request.query_params.get('admin_token', '')
        if admin_token:
            self.logger.warning("Admin token passed via query parameter - this is insecure for production")
            return admin_token
        
        return None
    
    def _verify_admin_token(self, provided_token: str) -> bool:
        """Verify provided admin token against configured token"""
        if not self._admin_token_hash:
            self.logger.warning("No admin token configured for token management")
            return False
        
        provided_hash = self._hash_token(provided_token)
        
        # Use constant-time comparison to prevent timing attacks
        return hmac.compare_digest(self._admin_token_hash, provided_hash)
    
    async def check_token_management_access(self, request: Request) -> Optional[JSONResponse]:
        """
        Check if request is authorized for token management operations
        
        Returns:
            None if access is granted
            JSONResponse with error if access is denied
        """
        
        # Check if HTTP token management is enabled
        if not self.config.security.enable_http_token_management:
            self.logger.warning(f"Token management endpoint access denied - HTTP management disabled: {request.url.path}")
            return JSONResponse({
                "error": "Token management endpoints are disabled for security",
                "message": "HTTP token management is disabled. Use file-based token management instead.",
                "suggestion": "Edit tokens.json file directly or enable HTTP management with proper security configuration"
            }, status_code=403)
        
        # Extract client IP
        client_ip = self._get_client_ip(request)
        
        # Check IP restrictions
        if not self._is_ip_allowed(client_ip):
            self.logger.warning(f"Token management access denied for IP {client_ip}: not in allowed list")
            return JSONResponse({
                "error": "Access denied - IP not allowed",
                "client_ip": client_ip,
                "message": "Token management is restricted to specific IP addresses",
                "allowed_networks": [str(net) for net in self._allowed_networks]
            }, status_code=403)
        
        # Check admin authentication if required
        if self.config.security.require_admin_auth:
            admin_token = self._extract_admin_token(request)
            
            if not admin_token:
                self.logger.warning(f"Token management access denied for IP {client_ip}: missing admin token")
                return JSONResponse({
                    "error": "Admin authentication required",
                    "message": "Token management requires admin authentication",
                    "hint": "Provide admin token in Authorization header: 'Bearer <admin_token>' or 'X-Admin-Token: <admin_token>'"
                }, status_code=401)
            
            if not self._verify_admin_token(admin_token):
                self.logger.warning(f"Token management access denied for IP {client_ip}: invalid admin token")
                return JSONResponse({
                    "error": "Invalid admin token",
                    "message": "The provided admin token is invalid"
                }, status_code=401)
        
        # Log successful access
        self.logger.info(f"Token management access granted for IP {client_ip} to {request.url.path}")
        
        # Access granted
        return None
    
    def get_security_info(self) -> Dict[str, Any]:
        """Get current security configuration info (for demo/status pages)"""
        return {
            "http_token_management_enabled": self.config.security.enable_http_token_management,
            "admin_auth_required": self.config.security.require_admin_auth,
            "admin_token_configured": bool(self._admin_token_hash),
            "allowed_networks_count": len(self._allowed_networks),
            "allowed_networks": [str(net) for net in self._allowed_networks],
            "security_features": [
                "IP address restrictions",
                "Admin token authentication" if self.config.security.require_admin_auth else "Optional admin authentication",
                "Secure token hashing",
                "Request logging and auditing"
            ]
        }
    
    def generate_admin_token(self) -> str:
        """Generate a secure admin token"""
        return secrets.token_urlsafe(32)


# Convenience function for middleware creation
def create_token_security_middleware(config: DorisConfig) -> TokenSecurityMiddleware:
    """Create token security middleware with configuration"""
    return TokenSecurityMiddleware(config)
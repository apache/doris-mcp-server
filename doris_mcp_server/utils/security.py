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
Doris Security Management Module
Implements enterprise-level authentication, authorization, SQL security validation and data masking functionality
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

import sqlparse
from sqlparse.sql import Statement
from sqlparse.tokens import Keyword, Name

from .logger import get_logger


class SecurityLevel(Enum):
    """Security level enumeration"""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SECRET = "secret"


@dataclass
class AuthContext:
    """Authentication context for audit and session tracking"""

    token_id: str  # Token identifier for audit logging
    client_ip: str = "unknown"  # Client IP address
    session_id: str = ""  # Session identifier
    login_time: datetime = field(default_factory=datetime.utcnow)
    last_activity: datetime | None = None


@dataclass
class ValidationResult:
    """Validation result"""

    is_valid: bool
    error_message: str | None = None
    risk_level: str = "low"
    blocked_operations: list[str] = None
    
    def __post_init__(self):
        if self.blocked_operations is None:
            self.blocked_operations = []


@dataclass
class MaskingRule:
    """Data masking rule"""

    column_pattern: str
    algorithm: str
    parameters: dict[str, Any]
    security_level: SecurityLevel


class DorisSecurityManager:
    """Doris security manager

    Provides complete security control functionality, including authentication, authorization, SQL security validation and data masking
    """

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)

        # Initialize security components
        self.auth_provider = AuthenticationProvider(config)
        self.authz_provider = AuthorizationProvider(config)
        self.sql_validator = SQLSecurityValidator(config)
        self.masking_processor = DataMaskingProcessor(config)

        # Security rule configuration
        self.blocked_keywords = self._load_blocked_keywords()
        self.sensitive_tables = self._load_sensitive_tables()
        self.masking_rules = self._load_masking_rules()
        
        # Track initialization state
        self._initialized = False

    async def initialize(self):
        """Initialize security manager components"""
        if self._initialized:
            return
            
        try:
            # Initialize authentication provider (for JWT setup)
            await self.auth_provider.initialize()
            
            self._initialized = True
            self.logger.info("DorisSecurityManager initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize DorisSecurityManager: {e}")
            raise

    async def shutdown(self):
        """Shutdown security manager components"""
        try:
            await self.auth_provider.shutdown()
            self._initialized = False
            self.logger.info("DorisSecurityManager shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during DorisSecurityManager shutdown: {e}")
            raise

    def _load_blocked_keywords(self) -> set[str]:
        """Load blocked SQL keywords from configuration"""
        # Load keywords from configuration, unified source of truth
        if hasattr(self.config, 'get'):
            # Dictionary-style configuration
            blocked_keywords = self.config.get("blocked_keywords", [])
        elif hasattr(self.config, 'security') and hasattr(self.config.security, 'blocked_keywords'):
            # DorisConfig object, get through security.blocked_keywords
            blocked_keywords = self.config.security.blocked_keywords
        else:
            # Fallback to default if no configuration available
            blocked_keywords = [
                "DROP", "CREATE", "ALTER", "TRUNCATE",
                "DELETE", "INSERT", "UPDATE", 
                "GRANT", "REVOKE",
                "EXEC", "EXECUTE", "SHUTDOWN", "KILL"
            ]

        return set(blocked_keywords)

    def _load_sensitive_tables(self) -> dict[str, SecurityLevel]:
        """Load sensitive table configuration"""
        default_tables = {
            "user_info": SecurityLevel.CONFIDENTIAL,
            "payment_records": SecurityLevel.SECRET,
            "employee_data": SecurityLevel.CONFIDENTIAL,
            "public_reports": SecurityLevel.PUBLIC,
        }
        
        if hasattr(self.config, 'get'):
            config_tables = self.config.get("sensitive_tables", {})
            # Convert string values to SecurityLevel enum
            for table_name, level in config_tables.items():
                if isinstance(level, str):
                    try:
                        default_tables[table_name] = SecurityLevel(level.lower())
                    except ValueError:
                        default_tables[table_name] = SecurityLevel.INTERNAL
                else:
                    default_tables[table_name] = level
            return default_tables
        else:
            return default_tables

    def _load_masking_rules(self) -> list[MaskingRule]:
        """Load data masking rules"""
        default_rules = [
            MaskingRule(
                column_pattern=r".*phone.*|.*mobile.*",
                algorithm="phone_mask",
                parameters={"mask_char": "*", "keep_prefix": 3, "keep_suffix": 4},
                security_level=SecurityLevel.INTERNAL,
            ),
            MaskingRule(
                column_pattern=r".*email.*",
                algorithm="email_mask",
                parameters={"mask_char": "*"},
                security_level=SecurityLevel.INTERNAL,
            ),
            MaskingRule(
                column_pattern=r".*id_card.*|.*identity.*",
                algorithm="id_mask",
                parameters={"mask_char": "*", "keep_prefix": 6, "keep_suffix": 4},
                security_level=SecurityLevel.CONFIDENTIAL,
            ),
        ]

        # Load custom rules from configuration
        custom_rules = []
        if hasattr(self.config, 'get'):
            custom_rules = self.config.get("masking_rules", [])
        elif hasattr(self.config, 'security') and hasattr(self.config.security, 'masking_rules'):
            custom_rules = self.config.security.masking_rules
        
        for rule_config in custom_rules:
            if isinstance(rule_config, dict):
                default_rules.append(MaskingRule(**rule_config))
            elif isinstance(rule_config, MaskingRule):
                default_rules.append(rule_config)

        return default_rules

    async def authenticate_request(self, auth_info: dict[str, Any]) -> AuthContext:
        """Validate request authentication information
        
        Tries authentication methods in order: Token -> JWT -> OAuth
        Any one method succeeding allows access
        If all methods are disabled, returns anonymous context
        """
        # Check if any authentication method is enabled
        if not (self.config.security.enable_token_auth or 
                self.config.security.enable_jwt_auth or 
                self.config.security.enable_oauth_auth):
            self.logger.debug("All authentication methods are disabled")
            # Return anonymous context when no authentication is enabled
            return AuthContext(
                token_id="anonymous",
                client_ip=auth_info.get("client_ip", "unknown"),
                session_id="anonymous_session"
            )
        
        # Try authentication methods in order of preference
        last_error = None
        
        # 1. Try Token authentication first (most common)
        if self.config.security.enable_token_auth:
            try:
                return await self.auth_provider.authenticate_token(auth_info)
            except Exception as e:
                self.logger.debug(f"Token authentication failed: {e}")
                last_error = e
        
        # 2. Try JWT authentication
        if self.config.security.enable_jwt_auth:
            try:
                return await self.auth_provider.authenticate_jwt(auth_info)
            except Exception as e:
                self.logger.debug(f"JWT authentication failed: {e}")
                last_error = e
        
        # 3. Try OAuth authentication
        if self.config.security.enable_oauth_auth:
            try:
                return await self.auth_provider.authenticate_oauth(auth_info)
            except Exception as e:
                self.logger.debug(f"OAuth authentication failed: {e}")
                last_error = e
        
        # All enabled authentication methods failed
        error_message = f"Authentication failed: {str(last_error)}" if last_error else "No authentication method succeeded"
        self.logger.warning(f"Authentication failed for client {auth_info.get('client_ip', 'unknown')}: {error_message}")
        raise ValueError(error_message)

    async def authorize_resource_access(
        self, auth_context: AuthContext, resource_uri: str
    ) -> bool:
        """Validate resource access permissions"""
        return await self.authz_provider.check_permission(
            auth_context, resource_uri, "read"
        )

    async def validate_sql_security(
        self, sql: str, auth_context: AuthContext
    ) -> ValidationResult:
        """Validate SQL query security"""
        return await self.sql_validator.validate(sql, auth_context)

    async def apply_data_masking(
        self, data: list[dict[str, Any]], auth_context: AuthContext
    ) -> list[dict[str, Any]]:
        """Apply data masking processing"""
        return await self.masking_processor.process(data, auth_context)

    # OAuth-specific methods
    def get_oauth_authorization_url(self) -> tuple[str, str]:
        """Get OAuth authorization URL
        
        Returns:
            Tuple of (authorization_url, state)
        """
        if not self.auth_provider.oauth_provider:
            raise ValueError("OAuth is not enabled")
        return self.auth_provider.oauth_provider.get_authorization_url()

    async def handle_oauth_callback(self, code: str, state: str) -> AuthContext:
        """Handle OAuth callback
        
        Args:
            code: Authorization code from OAuth provider
            state: State parameter for CSRF protection
            
        Returns:
            AuthContext for authenticated user
        """
        if not self.auth_provider.oauth_provider:
            raise ValueError("OAuth is not enabled")
        return await self.auth_provider.oauth_provider.handle_callback(code, state)

    def get_oauth_provider_info(self) -> dict[str, Any]:
        """Get OAuth provider information
        
        Returns:
            OAuth provider information
        """
        if not self.auth_provider.oauth_provider:
            return {"enabled": False}
        return self.auth_provider.oauth_provider.get_provider_info()

    # Token management methods
    async def create_token(
        self,
        token_id: str,
        expires_hours: Optional[int] = None,
        description: str = "",
        custom_token: Optional[str] = None
    ) -> str:
        """Create a new API access token
        
        Args:
            token_id: Unique token identifier for audit and management
            expires_hours: Token expiration in hours (None for no expiration)
            description: Token description for management purposes
            custom_token: Custom token string (if None, generates random token)
            
        Returns:
            Generated token string
        """
        if not self.auth_provider.token_manager:
            raise ValueError("Token manager not initialized")
        
        return await self.auth_provider.token_manager.create_token(
            token_id=token_id,
            expires_hours=expires_hours,
            description=description,
            custom_token=custom_token
        )
    
    async def revoke_token(self, token_id: str) -> bool:
        """Revoke a token by token ID
        
        Args:
            token_id: Token ID to revoke
            
        Returns:
            True if token was revoked successfully
        """
        if not self.auth_provider.token_manager:
            raise ValueError("Token manager not initialized")
        
        return await self.auth_provider.token_manager.revoke_token(token_id)
    
    async def list_tokens(self) -> list[dict[str, Any]]:
        """List all tokens (without sensitive data)
        
        Returns:
            List of token information
        """
        if not self.auth_provider.token_manager:
            raise ValueError("Token manager not initialized")
        
        return await self.auth_provider.token_manager.list_tokens()
    
    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens and return count
        
        Returns:
            Number of expired tokens removed
        """
        if not self.auth_provider.token_manager:
            return 0
        
        return await self.auth_provider.token_manager.cleanup_expired_tokens()
    
    def get_token_stats(self) -> dict[str, Any]:
        """Get token statistics
        
        Returns:
            Token statistics dictionary
        """
        if not self.auth_provider.token_manager:
            return {"error": "Token manager not initialized"}
        
        return self.auth_provider.token_manager.get_token_stats()


class AuthenticationProvider:
    """Authentication provider"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)
        self.session_cache = {}
        self.jwt_manager = None
        self.oauth_provider = None
        self.token_manager = None
        
        # Initialize authentication providers based on individual switches
        auth_methods_enabled = []
        
        # Initialize Token manager if enabled
        if config.security.enable_token_auth:
            self._initialize_token_manager()
            auth_methods_enabled.append("Token")
            
        # Initialize JWT manager if enabled
        if config.security.enable_jwt_auth:
            self._initialize_jwt_manager()
            auth_methods_enabled.append("JWT")
            
        # Initialize OAuth provider if enabled
        if config.security.enable_oauth_auth or (hasattr(config.security, 'oauth_enabled') and config.security.oauth_enabled):
            self._initialize_oauth_provider()
            auth_methods_enabled.append("OAuth")
            
        if auth_methods_enabled:
            self.logger.info(f"Authentication enabled with methods: {', '.join(auth_methods_enabled)}")
        else:
            self.logger.info("All authentication methods are disabled - anonymous access allowed")

    def _initialize_jwt_manager(self):
        """Initialize JWT manager"""
        try:
            from ..auth.jwt_manager import JWTManager
            self.jwt_manager = JWTManager(self.config)
            self.logger.info("JWT manager initialized")
        except ImportError as e:
            self.logger.error(f"Failed to import JWT manager: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize JWT manager: {e}")
            raise

    def _initialize_token_manager(self):
        """Initialize Token manager"""
        try:
            from ..auth.token_manager import TokenManager
            self.token_manager = TokenManager(self.config)
            self.logger.info("Token manager initialized")
        except ImportError as e:
            self.logger.error(f"Failed to import Token manager: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize Token manager: {e}")
            raise

    def _initialize_oauth_provider(self):
        """Initialize OAuth provider"""
        try:
            from ..auth.oauth_provider import OAuthAuthenticationProvider
            self.oauth_provider = OAuthAuthenticationProvider(self.config)
            self.logger.info("OAuth provider initialized")
        except ImportError as e:
            self.logger.error(f"Failed to import OAuth provider: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Failed to initialize OAuth provider: {e}")
            raise

    async def initialize(self):
        """Initialize authentication provider asynchronously"""
        if self.jwt_manager:
            success = await self.jwt_manager.initialize()
            if not success:
                raise RuntimeError("Failed to initialize JWT manager")
            self.logger.info("JWT authentication provider initialized successfully")
        
        if self.token_manager:
            # Token manager doesn't need async initialization, just log success
            self.logger.info("Token authentication provider initialized successfully")
            
        if self.oauth_provider:
            success = await self.oauth_provider.initialize()
            if not success:
                raise RuntimeError("Failed to initialize OAuth provider")
            self.logger.info("OAuth authentication provider initialized successfully")

    async def shutdown(self):
        """Shutdown authentication provider"""
        if self.jwt_manager:
            await self.jwt_manager.shutdown()
            self.logger.info("JWT authentication provider shutdown completed")
        
        if self.token_manager:
            # Token manager doesn't need async shutdown, just log
            self.logger.info("Token authentication provider shutdown completed")
            
        if self.oauth_provider:
            await self.oauth_provider.shutdown()
            self.logger.info("OAuth authentication provider shutdown completed")

    async def authenticate_token(self, auth_info: dict[str, Any]) -> AuthContext:
        """Perform token authentication"""
        if not self.config.security.enable_token_auth:
            raise ValueError("Token authentication is not enabled")
        return await self._authenticate_token(auth_info)
    
    async def authenticate_jwt(self, auth_info: dict[str, Any]) -> AuthContext:
        """Perform JWT authentication"""
        if not self.config.security.enable_jwt_auth:
            raise ValueError("JWT authentication is not enabled")
        return await self._authenticate_jwt(auth_info)
    
    async def authenticate_oauth(self, auth_info: dict[str, Any]) -> AuthContext:
        """Perform OAuth authentication"""
        if not self.config.security.enable_oauth_auth:
            raise ValueError("OAuth authentication is not enabled")
        return await self._authenticate_oauth(auth_info)

    async def _authenticate_jwt(self, auth_info: dict[str, Any]) -> AuthContext:
        """JWT authentication"""
        if not self.jwt_manager:
            raise ValueError("JWT manager not initialized")
        
        token = auth_info.get("token")
        if not token:
            # Try to extract from Authorization header
            authorization = auth_info.get("authorization")
            if authorization and authorization.startswith('Bearer '):
                token = authorization[7:]
            
        if not token:
            raise ValueError("Missing JWT token")

        try:
            # Use JWT middleware for authentication
            from ..auth.auth_middleware import AuthMiddleware
            middleware = AuthMiddleware(self.jwt_manager)
            return await middleware.authenticate_request(auth_info)
            
        except Exception as e:
            self.logger.error(f"JWT authentication failed: {e}")
            raise ValueError(f"JWT authentication failed: {str(e)}")

    async def _authenticate_oauth(self, auth_info: dict[str, Any]) -> AuthContext:
        """OAuth authentication"""
        if not self.oauth_provider:
            raise ValueError("OAuth provider not initialized")
        
        # Handle different OAuth authentication scenarios
        if "access_token" in auth_info:
            # Direct OAuth access token authentication
            return await self.oauth_provider.authenticate_with_token(auth_info["access_token"])
        elif "code" in auth_info and "state" in auth_info:
            # OAuth callback authentication
            return await self.oauth_provider.handle_callback(auth_info["code"], auth_info["state"])
        else:
            raise ValueError("OAuth authentication requires either access_token or code+state")

    async def _authenticate_token(self, auth_info: dict[str, Any]) -> AuthContext:
        """Token authentication"""
        if not self.token_manager:
            raise ValueError("Token manager not initialized")
            
        token = auth_info.get("token")
        if not token:
            # Try to extract from Authorization header
            authorization = auth_info.get("authorization")
            if authorization and authorization.startswith('Bearer '):
                token = authorization[7:]
            elif authorization and authorization.startswith('Token '):
                token = authorization[6:]
                
        if not token:
            raise ValueError("Missing authentication token")

        try:
            # Validate token using TokenManager
            validation_result = await self.token_manager.validate_token(token)
            
            if not validation_result.is_valid:
                raise ValueError(f"Token validation failed: {validation_result.error_message}")
            
            token_info = validation_result.token_info
            
            return AuthContext(
                token_id=token_info.token_id,
                client_ip=auth_info.get("client_ip", "unknown"),
                session_id=auth_info.get("session_id", f"session_{token_info.token_id}"),
                login_time=datetime.utcnow(),
                last_activity=token_info.last_used
            )
            
        except Exception as e:
            self.logger.error(f"Token authentication failed: {e}")
            raise ValueError(f"Token authentication failed: {str(e)}")

    async def _authenticate_basic(self, auth_info: dict[str, Any]) -> AuthContext:
        """Basic authentication (username password)"""
        username = auth_info.get("username")
        password = auth_info.get("password")

        if not username or not password:
            raise ValueError("Missing username or password")

        # Validate username password (simplified implementation)
        user_info = await self._validate_credentials(username, password)

        return AuthContext(
            user_id=user_info["user_id"],
            roles=user_info["roles"],
            permissions=user_info["permissions"],
            session_id=auth_info.get("session_id", "default"),
            login_time=datetime.utcnow(),
            security_level=SecurityLevel(user_info.get("security_level", "internal")),
        )

    async def _validate_token(self, token: str) -> dict[str, Any]:
        """Validate token validity"""
        # Simplified implementation for testing, should parse JWT or query authentication service in practice
        valid_tokens = {
            "valid_token_123": {
                "user_id": "test_user",
                "roles": ["data_analyst"],
                "permissions": ["read_data"],
                "security_level": SecurityLevel.INTERNAL,
            },
            "admin_token_456": {
                "user_id": "admin_user",
                "roles": ["data_admin"],
                "permissions": ["admin"],
                "security_level": SecurityLevel.SECRET,
            }
        }
        
        if token in valid_tokens:
            return valid_tokens[token]
        else:
            raise ValueError("Invalid token")

    async def _validate_credentials(
        self, username: str, password: str
    ) -> dict[str, Any]:
        """Validate user credentials"""
        # Simplified implementation for testing, should query user database in practice
        valid_users = {
            "admin": {
                "password": "admin123",
                "user_id": "admin_user",
                "roles": ["data_admin"],
                "permissions": ["admin", "read_data", "write_data"],
                "security_level": SecurityLevel.SECRET,
            },
            "analyst": {
                "password": "analyst123",
                "user_id": "analyst_user",
                "roles": ["data_analyst"],
                "permissions": ["read_data"],
                "security_level": SecurityLevel.INTERNAL,
            }
        }

        if username in valid_users and valid_users[username]["password"] == password:
            user_info = valid_users[username].copy()
            del user_info["password"]  # Remove password from returned info
            return user_info
        else:
            raise ValueError("Incorrect username or password")


class AuthorizationProvider:
    """Authorization provider"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)
        self.permission_cache = {}
        
        # Load sensitive tables configuration
        self.sensitive_tables = self._load_sensitive_tables()
    
    def _load_sensitive_tables(self) -> dict[str, SecurityLevel]:
        """Load sensitive table configuration"""
        default_tables = {
            "user_info": SecurityLevel.CONFIDENTIAL,
            "payment_records": SecurityLevel.SECRET,
            "employee_data": SecurityLevel.CONFIDENTIAL,
            "public_reports": SecurityLevel.PUBLIC,
        }
        
        if hasattr(self.config, 'get'):
            config_tables = self.config.get("sensitive_tables", {})
            # Convert string values to SecurityLevel enum
            for table_name, level in config_tables.items():
                if isinstance(level, str):
                    try:
                        default_tables[table_name] = SecurityLevel(level.lower())
                    except ValueError:
                        default_tables[table_name] = SecurityLevel.INTERNAL
                else:
                    default_tables[table_name] = level
            return default_tables
        else:
            return default_tables

    async def check_permission(
        self, auth_context: AuthContext, resource_uri: str, action: str
    ) -> bool:
        """Check permissions"""
        # Parse resource information
        resource_info = self._parse_resource_uri(resource_uri)

        # First check security level - this is mandatory
        if not await self._check_security_level_permission(auth_context, resource_info):
            return False

        # Then check role-based permissions
        if await self._check_role_permission(auth_context, resource_info, action):
            return True

        # Finally check user-based permissions
        if await self._check_user_permission(auth_context, resource_info, action):
            return True

        return False

    def _parse_resource_uri(self, uri: str) -> dict[str, str]:
        """Parse resource URI"""
        parts = uri.split("/")
        if len(parts) >= 3:
            return {
                "type": parts[2],  # table, view, etc.
                "name": parts[3] if len(parts) > 3 else "",
                "schema": parts[4] if len(parts) > 4 else "default",
            }
        return {"type": "unknown", "name": "", "schema": "default"}

    async def _check_role_permission(
        self, auth_context: AuthContext, resource_info: dict[str, str], action: str
    ) -> bool:
        """Check role-based permissions"""
        # Role permission mapping
        role_permissions = {
            "data_analyst": {"table": ["read"], "view": ["read"]},
            "data_admin": {
                "table": ["read", "write", "admin"],
                "view": ["read", "write", "admin"],
            },
        }

        for role in auth_context.roles:
            role_perms = role_permissions.get(role, {})
            resource_perms = role_perms.get(resource_info["type"], [])
            if action in resource_perms:
                return True

        return False

    async def _check_user_permission(
        self, auth_context: AuthContext, resource_info: dict[str, str], action: str
    ) -> bool:
        """Check user-based permissions"""
        # User-specific permission check
        if "admin" in auth_context.permissions:
            return True

        if action == "read" and "read_data" in auth_context.permissions:
            return True

        return False

    async def _check_security_level_permission(
        self, auth_context: AuthContext, resource_info: dict[str, str]
    ) -> bool:
        """Check security level permissions"""
        # Get resource security level
        resource_security_level = self._get_resource_security_level(resource_info)

        # Check if user security level is sufficient
        security_hierarchy = {
            SecurityLevel.PUBLIC: 0,
            SecurityLevel.INTERNAL: 1,
            SecurityLevel.CONFIDENTIAL: 2,
            SecurityLevel.SECRET: 3,
        }

        user_level = security_hierarchy.get(auth_context.security_level, 0)
        resource_level = security_hierarchy.get(resource_security_level, 0)

        # User must have higher or equal security level to access resource
        return user_level >= resource_level

    def _get_resource_security_level(
        self, resource_info: dict[str, str]
    ) -> SecurityLevel:
        """Get resource security level"""
        # Get table security level from configuration
        table_name = resource_info.get("name", "")
        
        # Use the loaded sensitive tables
        sensitive_tables = self.sensitive_tables
            
        # Convert string values to SecurityLevel enum if needed
        security_level = sensitive_tables.get(table_name, SecurityLevel.INTERNAL)
        if isinstance(security_level, str):
            try:
                security_level = SecurityLevel(security_level.lower())
            except ValueError:
                security_level = SecurityLevel.INTERNAL
                
        return security_level


class SQLSecurityValidator:
    """SQL security validator"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Handle DorisConfig object or dictionary configuration
        if hasattr(config, 'get'):
            # Dictionary configuration
            self.blocked_keywords = set(config.get("blocked_keywords", []))
            self.max_query_complexity = config.get("max_query_complexity", 100)
            self.enable_security_check = config.get("enable_security_check", True)
        elif hasattr(config, 'security'):
            # DorisConfig object with security attribute - unified source from config
            self.blocked_keywords = set(config.security.blocked_keywords)
            self.max_query_complexity = config.security.max_query_complexity
            self.enable_security_check = getattr(config.security, 'enable_security_check', True)
        else:
            # Fallback to default if no configuration available
            self.blocked_keywords = set([
                "DROP", "CREATE", "ALTER", "TRUNCATE",
                "DELETE", "INSERT", "UPDATE", 
                "GRANT", "REVOKE",
                "EXEC", "EXECUTE", "SHUTDOWN", "KILL"
            ])
            self.max_query_complexity = 100
            self.enable_security_check = True

    async def validate(self, sql: str, auth_context: AuthContext) -> ValidationResult:
        """Validate SQL query security"""
        # If security check is disabled, always return valid
        if not self.enable_security_check:
            self.logger.debug("SQL security check is disabled, allowing all queries")
            return ValidationResult(is_valid=True)
            
        try:
            # Parse SQL statement
            parsed = sqlparse.parse(sql)[0]

            # Check blocked operations first (more specific)
            keyword_result = await self._check_blocked_keywords(parsed)
            if not keyword_result.is_valid:
                return keyword_result

            # Check SQL injection risks
            injection_result = await self._check_sql_injection(sql, parsed)
            if not injection_result.is_valid:
                return injection_result

            # Check query complexity
            complexity_result = await self._check_query_complexity(parsed)
            if not complexity_result.is_valid:
                return complexity_result

            # Check table access permissions
            table_result = await self._check_table_access(parsed, auth_context)
            if not table_result.is_valid:
                return table_result

            return ValidationResult(is_valid=True)

        except Exception as e:
            self.logger.error(f"SQL security validation failed: {e}")
            return ValidationResult(
                is_valid=False,
                error_message=f"SQL parsing error: {str(e)}",
                risk_level="high",
            )

    async def _check_sql_injection(
        self, sql: str, parsed: Statement
    ) -> ValidationResult:
        """Check SQL injection risks"""
        # Check common SQL injection patterns
        injection_patterns = [
            r"(?i)(?<![A-Za-z0-9_])(union|select|insert|update|delete|drop|create|alter)(?![A-Za-z0-9_])\s+[\s\S]*?\s+(?<![A-Za-z0-9_])(union|select|insert|update|delete|drop|create|alter)(?![A-Za-z0-9_])",
            r"(\s|^)(or|and)\s+\d+\s*=\s*\d+",
            r"(\s|^)(or|and)\s+['\"].*['\"]",
            r";\s*(drop|delete|truncate|alter|create)",
            r"(exec|execute|sp_|xp_)",
            r"(script|javascript|vbscript)",
            r"(char|ascii|substring|concat)\s*\(",
        ]

        sql_lower = sql.lower()
        for pattern in injection_patterns:
            if re.search(pattern, sql_lower, re.IGNORECASE):
                return ValidationResult(
                    is_valid=False,
                    error_message="Potential SQL injection risk detected",
                    risk_level="high",
                )

        # Check suspicious quotes and comments
        if self._has_suspicious_quotes_or_comments(sql):
            return ValidationResult(
                is_valid=False,
                error_message="Suspicious quote or comment pattern detected",
                risk_level="medium",
            )

        return ValidationResult(is_valid=True)

    def _has_suspicious_quotes_or_comments(self, sql: str) -> bool:
        """Check suspicious quote and comment patterns"""
        # Check unmatched quotes
        single_quotes = sql.count("'")
        double_quotes = sql.count('"')

        if single_quotes % 2 != 0 or double_quotes % 2 != 0:
            return True

        # Check SQL comments
        if "--" in sql or "/*" in sql:
            return True

        return False

    async def _check_blocked_keywords(self, parsed: Statement) -> ValidationResult:
        """Check blocked keywords"""
        blocked_operations = []

        # Check all tokens in the parsed statement
        for token in parsed.flatten():
            # Check if token is a keyword (including DML/DDL) or name that matches blocked operations
            if (token.ttype is Keyword or 
                token.ttype is Name or 
                (token.ttype and str(token.ttype).startswith('Token.Keyword'))):
                token_value = token.value.upper().strip()
                if token_value in self.blocked_keywords:
                    blocked_operations.append(token_value)
            # Also check for DDL/DML keywords in token values
            elif hasattr(token, 'value') and token.value:
                token_value = token.value.upper().strip()
                for blocked_keyword in self.blocked_keywords:
                    if blocked_keyword in token_value:
                        blocked_operations.append(blocked_keyword)

        if blocked_operations:
            return ValidationResult(
                is_valid=False,
                error_message=f"Contains blocked operations: {', '.join(set(blocked_operations))}",
                risk_level="high",
                blocked_operations=list(set(blocked_operations)),
            )

        return ValidationResult(is_valid=True)

    async def _check_query_complexity(self, parsed: Statement) -> ValidationResult:
        """Check query complexity"""
        complexity_score = 0

        # Calculate complexity score
        for token in parsed.flatten():
            if token.ttype is Keyword:
                keyword = token.value.upper()
                if keyword in ["JOIN", "INNER", "LEFT", "RIGHT", "FULL"]:
                    complexity_score += 10
                elif keyword in ["UNION", "INTERSECT", "EXCEPT"]:
                    complexity_score += 15
                elif keyword in ["GROUP BY", "ORDER BY", "HAVING"]:
                    complexity_score += 5
                elif keyword in ["SUBQUERY", "EXISTS", "IN"]:
                    complexity_score += 8

        if complexity_score > self.max_query_complexity:
            return ValidationResult(
                is_valid=False,
                error_message=f"Query complexity too high (score: {complexity_score}, limit: {self.max_query_complexity})",
                risk_level="medium",
            )

        return ValidationResult(is_valid=True)

    async def _check_table_access(
        self, parsed: Statement, auth_context: AuthContext
    ) -> ValidationResult:
        """Check table access permissions"""
        # Extract table names from query
        tables = self._extract_table_names(parsed)

        # Check access permissions for each table
        unauthorized_tables = []
        for table in tables:
            # Should call authorization provider to check permissions
            # Simplified implementation, assume some tables require special permissions
            if (
                table.lower() in ["sensitive_data", "admin_logs"]
                and "admin" not in auth_context.roles
            ):
                unauthorized_tables.append(table)

        if unauthorized_tables:
            return ValidationResult(
                is_valid=False,
                error_message=f"No access to tables: {', '.join(unauthorized_tables)}",
                risk_level="high",
            )

        return ValidationResult(is_valid=True)

    def _extract_table_names(self, parsed: Statement) -> list[str]:
        """Extract table names from SQL statement"""
        tables = []

        # Simplified table name extraction logic
        tokens = list(parsed.flatten())
        for i, token in enumerate(tokens):
            if token.ttype is Keyword and token.value.upper() == "FROM":
                # Find table name after FROM
                for j in range(i + 1, len(tokens)):
                    next_token = tokens[j]
                    if next_token.ttype is Name:
                        tables.append(next_token.value)
                        break
                    elif next_token.ttype is Keyword:
                        break

        return tables


class DataMaskingProcessor:
    """Data masking processor"""

    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)
        self.masking_algorithms = self._init_masking_algorithms()
        self.masking_rules = self._load_masking_rules()
    
    def _load_masking_rules(self) -> list[MaskingRule]:
        """Load data masking rules"""
        default_rules = [
            MaskingRule(
                column_pattern=r".*phone.*|.*mobile.*",
                algorithm="phone_mask",
                parameters={"mask_char": "*", "keep_prefix": 3, "keep_suffix": 4},
                security_level=SecurityLevel.INTERNAL,
            ),
            MaskingRule(
                column_pattern=r".*email.*",
                algorithm="email_mask",
                parameters={"mask_char": "*"},
                security_level=SecurityLevel.INTERNAL,
            ),
            MaskingRule(
                column_pattern=r".*id_card.*|.*identity.*",
                algorithm="id_mask",
                parameters={"mask_char": "*", "keep_prefix": 6, "keep_suffix": 4},
                security_level=SecurityLevel.CONFIDENTIAL,
            ),
        ]

        # Load custom rules from configuration
        if hasattr(self.config, 'get'):
            custom_rules = self.config.get("masking_rules", [])
            for rule_config in custom_rules:
                if isinstance(rule_config, dict):
                    # Convert string security level to enum
                    if 'security_level' in rule_config and isinstance(rule_config['security_level'], str):
                        try:
                            rule_config['security_level'] = SecurityLevel(rule_config['security_level'].lower())
                        except ValueError:
                            rule_config['security_level'] = SecurityLevel.INTERNAL
                    default_rules.append(MaskingRule(**rule_config))
                elif isinstance(rule_config, MaskingRule):
                    default_rules.append(rule_config)

        return default_rules

    def _init_masking_algorithms(self) -> dict[str, callable]:
        """Initialize masking algorithms"""
        return {
            "phone_mask": self._mask_phone,
            "email_mask": self._mask_email,
            "id_mask": self._mask_id_card,
            "name_mask": self._mask_name,
            "partial_mask": self._mask_partial,
        }

    async def process(
        self, data: list[dict[str, Any]], auth_context: AuthContext
    ) -> list[dict[str, Any]]:
        """Process data masking"""
        if not data:
            return data

        # Get applicable masking rules
        applicable_rules = self._get_applicable_rules(auth_context)

        masked_data = []
        for row in data:
            masked_row = {}
            for column, value in row.items():
                masked_value = await self._apply_masking_rules(
                    column, value, applicable_rules
                )
                masked_row[column] = masked_value
            masked_data.append(masked_row)

        return masked_data

    def _get_applicable_rules(self, auth_context: AuthContext) -> list[MaskingRule]:
        """Get applicable masking rules"""
        applicable_rules = []

        for rule in self.masking_rules:
            # Decide whether to apply masking rules based on user security level
            if self._should_apply_rule(rule, auth_context):
                applicable_rules.append(rule)

        return applicable_rules

    def _should_apply_rule(self, rule: MaskingRule, auth_context: AuthContext) -> bool:
        """Determine whether masking rule should be applied"""
        # Admin users can see original data
        if "admin" in auth_context.roles:
            return False

        # Decide based on security level
        security_hierarchy = {
            SecurityLevel.PUBLIC: 0,
            SecurityLevel.INTERNAL: 1,
            SecurityLevel.CONFIDENTIAL: 2,
            SecurityLevel.SECRET: 3,
        }

        user_level = security_hierarchy.get(auth_context.security_level, 0)
        rule_level = security_hierarchy.get(rule.security_level, 0)

        # Apply masking if user level is less than or equal to rule level
        return user_level <= rule_level

    async def _apply_masking_rules(
        self, column: str, value: Any, rules: list[MaskingRule]
    ) -> Any:
        """Apply masking rules"""
        if value is None:
            return value

        for rule in rules:
            if re.match(rule.column_pattern, column, re.IGNORECASE):
                algorithm = self.masking_algorithms.get(rule.algorithm)
                if algorithm:
                    return algorithm(str(value), rule.parameters)

        return value

    def _mask_phone(self, value: str, params: dict[str, Any]) -> str:
        """Phone number masking"""
        if len(value) < 7:
            return value

        mask_char = params.get("mask_char", "*")
        keep_prefix = params.get("keep_prefix", 3)
        keep_suffix = params.get("keep_suffix", 4)

        if len(value) <= keep_prefix + keep_suffix:
            return mask_char * len(value)

        prefix = value[:keep_prefix]
        suffix = value[-keep_suffix:]
        middle_length = len(value) - keep_prefix - keep_suffix

        return prefix + mask_char * middle_length + suffix

    def _mask_email(self, value: str, params: dict[str, Any]) -> str:
        """Email masking"""
        if "@" not in value:
            return value

        mask_char = params.get("mask_char", "*")
        local, domain = value.split("@", 1)

        if len(local) <= 2:
            masked_local = mask_char * len(local)
        else:
            masked_local = local[0] + mask_char * (len(local) - 2) + local[-1]

        return f"{masked_local}@{domain}"

    def _mask_id_card(self, value: str, params: dict[str, Any]) -> str:
        """ID card number masking"""
        if len(value) < 10:
            return value

        mask_char = params.get("mask_char", "*")
        keep_prefix = params.get("keep_prefix", 6)
        keep_suffix = params.get("keep_suffix", 4)

        if len(value) <= keep_prefix + keep_suffix:
            return mask_char * len(value)

        prefix = value[:keep_prefix]
        suffix = value[-keep_suffix:]
        middle_length = len(value) - keep_prefix - keep_suffix

        return prefix + mask_char * middle_length + suffix

    def _mask_name(self, value: str, params: dict[str, Any]) -> str:
        """Name masking"""
        if len(value) <= 1:
            return value

        mask_char = params.get("mask_char", "*")

        if len(value) == 2:
            return value[0] + mask_char
        else:
            return value[0] + mask_char * (len(value) - 2) + value[-1]

    def _mask_partial(self, value: str, params: dict[str, Any]) -> str:
        """Partial masking"""
        mask_char = params.get("mask_char", "*")
        mask_ratio = params.get("mask_ratio", 0.5)

        mask_length = int(len(value) * mask_ratio)
        start_pos = (len(value) - mask_length) // 2

        result = list(value)
        for i in range(start_pos, start_pos + mask_length):
            if i < len(result):
                result[i] = mask_char

        return "".join(result)

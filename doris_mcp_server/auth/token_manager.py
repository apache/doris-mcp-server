#!/usr/bin/env python3
"""
Token Authentication Management Module

Provides enterprise-grade token authentication system with configurable tokens,
expiration management, role-based access control and secure token storage.
"""

import hashlib
import json
import os
import secrets
import time
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.security import SecurityLevel


@dataclass
class DatabaseConfig:
    """Database connection configuration for token binding"""
    
    host: str
    port: int = 9030
    user: str = ""
    password: str = ""
    database: str = "information_schema"
    charset: str = "UTF8"
    fe_http_port: int = 8030


@dataclass
class TokenInfo:
    """Token information structure with optional database binding"""
    
    token_id: str  # Unique token identifier for audit and management
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    description: str = ""  # Optional description for token purpose
    is_active: bool = True
    database_config: Optional[DatabaseConfig] = None  # Optional database binding


@dataclass
class TokenValidationResult:
    """Token validation result"""
    
    is_valid: bool
    token_info: Optional[TokenInfo] = None
    error_message: Optional[str] = None


class TokenManager:
    """Enterprise Token Authentication Manager
    
    Features:
    - Configurable token storage (file-based or environment variables)
    - Token expiration management
    - Secure token hashing
    - Role-based access control
    - Token lifecycle management
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = get_logger(__name__)
        
        # Token storage
        self._tokens: Dict[str, TokenInfo] = {}  # token_hash -> TokenInfo
        self._token_ids: Dict[str, str] = {}     # token_id -> token_hash
        
        # Configuration
        self.token_file_path = getattr(config.security, 'token_file_path', 'tokens.json')
        self.enable_token_expiry = getattr(config.security, 'enable_token_expiry', True)
        self.default_token_expiry_hours = getattr(config.security, 'default_token_expiry_hours', 24 * 30)  # 30 days
        self.token_hash_algorithm = getattr(config.security, 'token_hash_algorithm', 'sha256')
        
        # Hot reload configuration
        self.enable_hot_reload = True
        self.hot_reload_interval = 10  # Check every 10 seconds
        self._file_last_modified = 0
        self._hot_reload_task = None
        
        # Initialize with default tokens if none exist
        self._initialize_default_tokens()
        
        # Load tokens from configuration
        self._load_tokens()
        
        # Start hot reload monitoring
        if self.enable_hot_reload:
            self._start_hot_reload()
        
        self.logger.info(f"TokenManager initialized with {len(self._tokens)} tokens, hot reload: {self.enable_hot_reload}")
    
    def _initialize_default_tokens(self):
        """Initialize default tokens for basic authentication (configurable via environment)"""
        # Default token configurations (can be overridden by environment variables)
        default_tokens = [
            {
                'token_id': 'admin-token',
                'token': os.getenv('DEFAULT_ADMIN_TOKEN', 'doris_admin_token_123456'),
                'description': os.getenv('DEFAULT_ADMIN_DESCRIPTION', 'Default admin API access token'),
                'expires_hours': None  # Never expires
            },
            {
                'token_id': 'analyst-token', 
                'token': os.getenv('DEFAULT_ANALYST_TOKEN', 'doris_analyst_token_123456'),
                'description': os.getenv('DEFAULT_ANALYST_DESCRIPTION', 'Default data analysis API access token'),
                'expires_hours': None  # Never expires
            },
            {
                'token_id': 'readonly-token',
                'token': os.getenv('DEFAULT_READONLY_TOKEN', 'doris_readonly_token_123456'),
                'description': os.getenv('DEFAULT_READONLY_DESCRIPTION', 'Default read-only API access token'),
                'expires_hours': None  # Never expires
            }
        ]
        
        
        # Only add default tokens if no custom tokens are defined via environment variables
        # Check if any TOKEN_* environment variables exist (excluding system and legacy configs)
        excluded_prefixes = ('DEFAULT_', 'TOKEN_FILE_PATH', 'TOKEN_HASH_')
        excluded_vars = {'TOKEN_SECRET', 'TOKEN_EXPIRY'}
        
        custom_tokens_exist = any(
            key.startswith('TOKEN_') and 
            not key.startswith(excluded_prefixes) and 
            not key.endswith(('_EXPIRES_HOURS', '_DESCRIPTION')) and
            key not in excluded_vars
            for key in os.environ.keys()
        )
        
        # Also check if token file exists and has content
        token_file_exists = False
        if os.path.exists(self.token_file_path):
            try:
                with open(self.token_file_path, 'r') as f:
                    content = f.read().strip()
                    if content and content != '{}':
                        token_file_exists = True
            except:
                pass
        
        # Add default tokens only if no custom configuration exists
        if not custom_tokens_exist and not token_file_exists:
            for token_config in default_tokens:
                self._add_token_from_config(token_config)
            
            self.logger.info(f"Initialized {len(default_tokens)} default tokens (no custom config found)")
        else:
            self.logger.info("Skipped default tokens initialization (custom tokens detected)")
    
    def _add_token_from_config(self, token_config: Dict[str, Any]):
        """Add token from configuration with optional database binding"""
        try:
            # Calculate expiration time
            expires_at = None
            if self.enable_token_expiry:
                expires_hours = token_config.get('expires_hours', self.default_token_expiry_hours)
                if expires_hours is not None:
                    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
            
            # Parse database configuration if provided
            database_config = None
            if 'database_config' in token_config:
                db_config = token_config['database_config']
                database_config = DatabaseConfig(
                    host=db_config.get('host', 'localhost'),
                    port=db_config.get('port', 9030),
                    user=db_config.get('user', 'root'),
                    password=db_config.get('password', ''),
                    database=db_config.get('database', 'information_schema'),
                    charset=db_config.get('charset', 'UTF8'),
                    fe_http_port=db_config.get('fe_http_port', 8030)
                )
            
            # Create token info
            token_info = TokenInfo(
                token_id=token_config['token_id'],
                expires_at=expires_at,
                description=token_config.get('description', ''),
                is_active=token_config.get('is_active', True),
                database_config=database_config
            )
            
            # Hash the token
            raw_token = token_config['token']
            token_hash = self._hash_token(raw_token)
            
            # Store token
            self._tokens[token_hash] = token_info
            self._token_ids[token_info.token_id] = token_hash
            
            db_info = f" with DB binding ({database_config.host})" if database_config else ""
            self.logger.debug(f"Added token '{token_info.token_id}'{db_info}")
            
        except Exception as e:
            self.logger.error(f"Failed to add token from config: {e}")
            raise
    
    def _load_tokens(self):
        """Load tokens from configuration sources"""
        # 1. Load from environment variables
        self._load_tokens_from_env()
        
        # 2. Load from token file if exists
        if os.path.exists(self.token_file_path):
            self._load_tokens_from_file()
        
        self.logger.info(f"Token loading completed, total tokens: {len(self._tokens)}")
    
    def _load_tokens_from_env(self):
        """Load tokens from environment variables
        
        Simplified format: 
        TOKEN_<ID>=<token>
        TOKEN_<ID>_EXPIRES_HOURS=<hours>
        TOKEN_<ID>_DESCRIPTION=<description>
        """
        token_prefixes = set()
        
        # Find all TOKEN_ environment variables (exclude legacy and system variables)
        excluded_token_vars = {
            'TOKEN_SECRET',           # Legacy token secret
            'TOKEN_EXPIRY',           # Legacy token expiry
            'TOKEN_FILE_PATH',        # System config
            'TOKEN_HASH_ALGORITHM'    # System config
        }
        
        for key in os.environ:
            if (key.startswith('TOKEN_') and 
                not key.endswith(('_EXPIRES_HOURS', '_DESCRIPTION')) and
                key not in excluded_token_vars):
                token_id = key[6:]  # Remove 'TOKEN_' prefix
                token_prefixes.add(token_id)
        
        # Load each token
        for token_id in token_prefixes:
            try:
                token = os.environ.get(f'TOKEN_{token_id}')
                if not token:
                    continue
                
                expires_hours_str = os.environ.get(f'TOKEN_{token_id}_EXPIRES_HOURS', str(self.default_token_expiry_hours))
                description = os.environ.get(f'TOKEN_{token_id}_DESCRIPTION', f'Environment token {token_id}')
                
                expires_hours = None
                try:
                    if expires_hours_str and expires_hours_str.lower() != 'none':
                        expires_hours = int(expires_hours_str)
                except ValueError:
                    expires_hours = self.default_token_expiry_hours
                
                # Add token
                token_config = {
                    'token_id': token_id.lower(),
                    'token': token,
                    'expires_hours': expires_hours,
                    'description': description
                }
                
                self._add_token_from_config(token_config)
                
            except Exception as e:
                self.logger.error(f"Failed to load token {token_id} from environment: {e}")
    
    def _load_tokens_from_file(self):
        """Load tokens from JSON file"""
        try:
            with open(self.token_file_path, 'r', encoding='utf-8') as f:
                tokens_data = json.load(f)
            
            if isinstance(tokens_data, dict) and 'tokens' in tokens_data:
                tokens_list = tokens_data['tokens']
            elif isinstance(tokens_data, list):
                tokens_list = tokens_data
            else:
                self.logger.error(f"Invalid token file format: {self.token_file_path}")
                return
            
            for token_config in tokens_list:
                self._add_token_from_config(token_config)
            
            self.logger.info(f"Loaded {len(tokens_list)} tokens from file: {self.token_file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load tokens from file {self.token_file_path}: {e}")
    
    def _hash_token(self, token: str) -> str:
        """Hash token for secure storage"""
        if self.token_hash_algorithm == 'sha256':
            return hashlib.sha256(token.encode('utf-8')).hexdigest()
        elif self.token_hash_algorithm == 'sha512':
            return hashlib.sha512(token.encode('utf-8')).hexdigest()
        else:
            # Fallback to sha256
            return hashlib.sha256(token.encode('utf-8')).hexdigest()
    
    async def validate_token(self, token: str) -> TokenValidationResult:
        """Validate token and return user information"""
        try:
            # Hash the provided token
            token_hash = self._hash_token(token)
            
            # Find token info
            token_info = self._tokens.get(token_hash)
            if not token_info:
                return TokenValidationResult(
                    is_valid=False,
                    error_message="Invalid token"
                )
            
            # Check if token is active
            if not token_info.is_active:
                return TokenValidationResult(
                    is_valid=False,
                    error_message="Token is inactive"
                )
            
            # Check expiration
            if token_info.expires_at and datetime.utcnow() > token_info.expires_at:
                return TokenValidationResult(
                    is_valid=False,
                    error_message="Token has expired"
                )
            
            # Update last used time
            token_info.last_used = datetime.utcnow()
            
            return TokenValidationResult(
                is_valid=True,
                token_info=token_info
            )
            
        except Exception as e:
            self.logger.error(f"Token validation error: {e}")
            return TokenValidationResult(
                is_valid=False,
                error_message=f"Token validation failed: {str(e)}"
            )
    
    def generate_token(self, length: int = 32) -> str:
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(length)
    
    async def create_token(
        self,
        token_id: str,
        expires_hours: Optional[int] = None,
        description: str = "",
        custom_token: Optional[str] = None
    ) -> str:
        """Create a new token"""
        try:
            # Check if token_id already exists
            if token_id in self._token_ids:
                raise ValueError(f"Token ID '{token_id}' already exists")
            
            # Generate or use provided token
            if custom_token:
                raw_token = custom_token
            else:
                raw_token = self.generate_token()
            
            # Calculate expiration
            expires_at = None
            if expires_hours is not None:
                expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
            elif self.enable_token_expiry:
                expires_at = datetime.utcnow() + timedelta(hours=self.default_token_expiry_hours)
            
            # Create token info
            token_info = TokenInfo(
                token_id=token_id,
                expires_at=expires_at,
                description=description
            )
            
            # Hash and store token
            token_hash = self._hash_token(raw_token)
            self._tokens[token_hash] = token_info
            self._token_ids[token_id] = token_hash
            
            self.logger.info(f"Created new token '{token_id}'")
            
            return raw_token
            
        except Exception as e:
            self.logger.error(f"Failed to create token: {e}")
            raise
    
    async def revoke_token(self, token_id: str) -> bool:
        """Revoke a token by token ID"""
        try:
            if token_id not in self._token_ids:
                self.logger.warning(f"Token ID '{token_id}' not found")
                return False
            
            # Get token hash and remove from storage
            token_hash = self._token_ids[token_id]
            if token_hash in self._tokens:
                del self._tokens[token_hash]
            del self._token_ids[token_id]
            
            self.logger.info(f"Revoked token '{token_id}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to revoke token '{token_id}': {e}")
            return False
    
    async def list_tokens(self) -> List[Dict[str, Any]]:
        """List all tokens (without sensitive data)"""
        tokens = []
        
        for token_hash, token_info in self._tokens.items():
            token_data = {
                'token_id': token_info.token_id,
                'created_at': token_info.created_at.isoformat(),
                'expires_at': token_info.expires_at.isoformat() if token_info.expires_at else None,
                'last_used': token_info.last_used.isoformat() if token_info.last_used else None,
                'is_active': token_info.is_active,
                'description': token_info.description,
                'is_expired': token_info.expires_at and datetime.utcnow() > token_info.expires_at if token_info.expires_at else False
            }
            
            # Add database binding info (without sensitive data)
            if token_info.database_config:
                token_data['database_binding'] = {
                    'host': token_info.database_config.host,
                    'port': token_info.database_config.port,
                    'user': token_info.database_config.user,
                    'database': token_info.database_config.database,
                    'has_password': bool(token_info.database_config.password)
                }
            else:
                token_data['database_binding'] = None
                
            tokens.append(token_data)
        
        # Sort by creation time
        tokens.sort(key=lambda x: x['created_at'], reverse=True)
        
        return tokens
    
    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens and return count"""
        if not self.enable_token_expiry:
            return 0
        
        now = datetime.utcnow()
        expired_tokens = []
        
        # Find expired tokens
        for token_hash, token_info in self._tokens.items():
            if token_info.expires_at and now > token_info.expires_at:
                expired_tokens.append((token_hash, token_info.token_id))
        
        # Remove expired tokens
        for token_hash, token_id in expired_tokens:
            del self._tokens[token_hash]
            if token_id in self._token_ids:
                del self._token_ids[token_id]
        
        if expired_tokens:
            self.logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")
        
        return len(expired_tokens)
    
    async def save_tokens_to_file(self, file_path: Optional[str] = None) -> bool:
        """Save current tokens to JSON file"""
        try:
            file_path = file_path or self.token_file_path
            tokens_list = await self.list_tokens()
            
            tokens_data = {
                'version': '1.0',
                'created_at': datetime.utcnow().isoformat(),
                'tokens': tokens_list
            }
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(tokens_data, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"Saved {len(tokens_list)} tokens to file: {file_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save tokens to file: {e}")
            return False
    
    def get_database_config_by_token(self, token: str) -> Optional[DatabaseConfig]:
        """Get database configuration bound to a token
        
        Args:
            token: The raw token string
            
        Returns:
            DatabaseConfig if token exists and has database binding, None otherwise
        """
        try:
            token_hash = self._hash_token(token)
            token_info = self._tokens.get(token_hash)
            
            if not token_info or not token_info.is_active:
                return None
                
            # Check expiration
            if token_info.expires_at and datetime.utcnow() > token_info.expires_at:
                return None
                
            return token_info.database_config
            
        except Exception as e:
            self.logger.error(f"Failed to get database config for token: {e}")
            return None
    
    def get_token_stats(self) -> Dict[str, Any]:
        """Get token statistics"""
        now = datetime.utcnow()
        total_tokens = len(self._tokens)
        active_tokens = sum(1 for info in self._tokens.values() if info.is_active)
        expired_tokens = sum(1 for info in self._tokens.values() 
                           if info.expires_at and now > info.expires_at)
        tokens_with_db = sum(1 for info in self._tokens.values() 
                           if info.database_config is not None)
        
        return {
            'total_tokens': total_tokens,
            'active_tokens': active_tokens,
            'expired_tokens': expired_tokens,
            'tokens_with_database_binding': tokens_with_db,
            'expiry_enabled': self.enable_token_expiry,
            'default_expiry_hours': self.default_token_expiry_hours,
            'hot_reload_enabled': self.enable_hot_reload,
            'last_file_check': datetime.fromtimestamp(self._file_last_modified).isoformat() if self._file_last_modified else None
        }
    
    def _start_hot_reload(self):
        """Start hot reload monitoring task"""
        if self._hot_reload_task:
            return  # Already running
        
        # Update initial file modification time
        self._update_file_modified_time()
        
        # Start monitoring task
        self._hot_reload_task = asyncio.create_task(self._hot_reload_monitor())
        self.logger.info(f"Started hot reload monitoring for {self.token_file_path}")
    
    def stop_hot_reload(self):
        """Stop hot reload monitoring"""
        if self._hot_reload_task:
            self._hot_reload_task.cancel()
            self._hot_reload_task = None
            self.logger.info("Stopped hot reload monitoring")
    
    def _update_file_modified_time(self):
        """Update the last modified time of tokens file"""
        try:
            if os.path.exists(self.token_file_path):
                self._file_last_modified = os.path.getmtime(self.token_file_path)
        except Exception as e:
            self.logger.debug(f"Failed to get file modification time: {e}")
    
    async def _hot_reload_monitor(self):
        """Background task to monitor tokens.json file changes"""
        while True:
            try:
                await asyncio.sleep(self.hot_reload_interval)
                
                if not os.path.exists(self.token_file_path):
                    continue
                
                # Check if file was modified
                current_mtime = os.path.getmtime(self.token_file_path)
                if current_mtime > self._file_last_modified:
                    self.logger.info(f"Detected changes in {self.token_file_path}, reloading tokens...")
                    
                    try:
                        # Backup current tokens
                        old_tokens = self._tokens.copy()
                        old_token_ids = self._token_ids.copy()
                        
                        # Clear and reload
                        self._tokens.clear()
                        self._token_ids.clear()
                        
                        # Reinitialize default tokens
                        self._initialize_default_tokens()
                        
                        # Load from file
                        self._load_tokens_from_file()
                        
                        # Update modification time
                        self._file_last_modified = current_mtime
                        
                        self.logger.info(f"Hot reload completed, {len(self._tokens)} tokens loaded")
                        
                    except Exception as reload_error:
                        # Restore backup on failure
                        self.logger.error(f"Hot reload failed, restoring previous tokens: {reload_error}")
                        self._tokens = old_tokens
                        self._token_ids = old_token_ids
                
            except asyncio.CancelledError:
                self.logger.info("Hot reload monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Error in hot reload monitor: {e}")
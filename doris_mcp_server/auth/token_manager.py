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
Token Authentication Management Module

Provides enterprise-grade token authentication system with configurable tokens,
expiration management, role-based access control and secure token storage.
"""

import asyncio
import json
import os
import secrets
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from pathlib import Path

from ..utils.logger import get_logger
from ..utils.secret_policy import (
    build_token_digest,
    is_static_token_environment_variable,
    normalize_token_digest,
    normalize_token_hash_algorithm,
    validate_high_entropy_secret,
)
from ..utils.security import RESERVED_DORIS_OAUTH_TOKEN_PREFIX, SecurityLevel


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
    
    def __init__(self, config: Any) -> None:
        self.config = config
        self.logger = get_logger(__name__)
        
        # Token storage
        self._tokens: Dict[str, TokenInfo] = {}  # token_hash -> TokenInfo
        self._token_ids: Dict[str, str] = {}     # token_id -> token_hash
        self._digest_algorithms: set[str] = set()
        
        # Configuration
        self.token_file_path = getattr(config.security, 'token_file_path', 'tokens.json')
        self.enable_token_expiry = getattr(config.security, 'enable_token_expiry', True)
        self.default_token_expiry_hours = getattr(config.security, 'default_token_expiry_hours', 24 * 30)  # 30 days
        self.token_hash_algorithm = normalize_token_hash_algorithm(
            getattr(config.security, 'token_hash_algorithm', 'sha256')
        )
        
        # Hot reload configuration
        self.enable_hot_reload = True
        self.hot_reload_interval = 10  # Check every 10 seconds
        self._file_last_modified = 0.0
        self._hot_reload_task: Optional[asyncio.Task[None]] = None
        
        # Load tokens from configuration
        self._load_tokens()

        effective_auth = getattr(config, "effective_auth", None)
        token_auth_enabled = getattr(
            effective_auth,
            "enable_token_auth",
            getattr(config.security, "enable_token_auth", False),
        )
        if token_auth_enabled and not any(
            token_info.is_active for token_info in self._tokens.values()
        ):
            raise ValueError(
                "Token authentication is enabled but no active static token is configured. "
                "Set a high-entropy TOKEN_<ID> environment variable or provide one in tokens.json."
            )
        
        # Start hot reload monitoring
        if self.enable_hot_reload:
            self._start_hot_reload()
        
        self.logger.info(f"TokenManager initialized with {len(self._tokens)} tokens, hot reload: {self.enable_hot_reload}")

    def _validate_static_token_prefix(self, token: str) -> None:
        if token.startswith(RESERVED_DORIS_OAUTH_TOKEN_PREFIX):
            raise ValueError(
                f"Static tokens cannot use reserved Doris OAuth prefix "
                f"'{RESERVED_DORIS_OAUTH_TOKEN_PREFIX}'"
            )

    @staticmethod
    def _parse_datetime(value: Any, *, setting: str) -> Optional[datetime]:
        """Parse an RFC 3339 timestamp into the manager's naive UTC form."""
        if value in (None, ""):
            return None
        if not isinstance(value, str):
            raise ValueError(f"{setting} must be an RFC 3339 timestamp")
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"{setting} must be an RFC 3339 timestamp") from exc
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed

    def _add_token_from_config(
        self,
        token_config: Dict[str, Any],
    ) -> tuple[str, TokenInfo, bool]:
        """Add token from configuration with optional database binding"""
        try:
            token_id = str(token_config.get('token_id') or '').strip()
            if not token_id:
                raise ValueError("Static token entry requires token_id")

            created_at = self._parse_datetime(
                token_config.get('created_at'),
                setting=f"static token '{token_id}' created_at",
            ) or datetime.utcnow()

            # Calculate expiration time
            if 'expires_at' in token_config:
                expires_at = self._parse_datetime(
                    token_config.get('expires_at'),
                    setting=f"static token '{token_id}' expires_at",
                )
            elif self.enable_token_expiry:
                expires_at = None
                expires_hours = token_config.get('expires_hours', self.default_token_expiry_hours)
                if expires_hours is not None:
                    expires_at = created_at + timedelta(hours=expires_hours)
            else:
                expires_at = None

            last_used = self._parse_datetime(
                token_config.get('last_used'),
                setting=f"static token '{token_id}' last_used",
            )
            
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
                token_id=token_id,
                created_at=created_at,
                expires_at=expires_at,
                last_used=last_used,
                description=token_config.get('description', ''),
                is_active=token_config.get('is_active', True),
                database_config=database_config
            )

            has_raw_token = 'token' in token_config
            has_token_digest = 'token_digest' in token_config
            if has_raw_token == has_token_digest:
                raise ValueError(
                    f"static token '{token_id}' must contain exactly one of "
                    "token or token_digest"
                )

            if has_token_digest:
                stored_digest = token_config.get('token_digest')
                if not isinstance(stored_digest, str):
                    raise ValueError(
                        f"static token '{token_id}' token_digest is required"
                    )
                token_hash = normalize_token_digest(
                    stored_digest,
                    setting=f"static token '{token_id}' token_digest",
                )
            else:
                raw_token = token_config.get('token')
                if not isinstance(raw_token, str):
                    raise ValueError(f"static token '{token_id}' is required")
                self._validate_static_token_prefix(raw_token)
                validate_high_entropy_secret(
                    raw_token,
                    setting=f"static token '{token_info.token_id}'",
                )
                token_hash = self._hash_token(raw_token)
            self._digest_algorithms.add(token_hash.partition(":")[0])
            
            # Store token
            self._tokens[token_hash] = token_info
            self._token_ids[token_info.token_id] = token_hash
            
            db_info = f" with DB binding ({database_config.host})" if database_config else ""
            self.logger.debug(f"Added token '{token_info.token_id}'{db_info}")
            return token_hash, token_info, has_raw_token

        except Exception as e:
            self.logger.error(f"Failed to add token from config: {e}")
            raise
    
    def _load_tokens(self) -> None:
        """Load tokens from configuration sources"""
        # 1. Load from environment variables
        self._load_tokens_from_env()
        
        # 2. Load from token file if exists
        if os.path.exists(self.token_file_path):
            self._load_tokens_from_file()
        
        self.logger.info(f"Token loading completed, total tokens: {len(self._tokens)}")
    
    def _load_tokens_from_env(self) -> None:
        """Load tokens from environment variables
        
        Simplified format: 
        TOKEN_<ID>=<token>
        TOKEN_<ID>_EXPIRES_HOURS=<hours>
        TOKEN_<ID>_DESCRIPTION=<description>
        """
        token_prefixes = set()
        
        # Find all TOKEN_ environment variables (exclude legacy and system variables)
        for key in os.environ:
            if is_static_token_environment_variable(key):
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
                
            except ValueError:
                raise
            except Exception as e:
                self.logger.error(f"Failed to load token {token_id} from environment: {e}")
    
    def _load_tokens_from_file(self) -> None:
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
            if not isinstance(tokens_list, list):
                raise ValueError("Static token file must contain a tokens array")

            persisted_tokens = []
            needs_migration = (
                not isinstance(tokens_data, dict)
                or tokens_data.get("version") != "2.0"
            )
            for token_config in tokens_list:
                if not isinstance(token_config, dict):
                    raise ValueError("Static token file entries must be objects")
                token_hash, token_info, had_raw_token = self._add_token_from_config(
                    token_config
                )
                persisted_tokens.append(
                    self._token_info_to_config(token_hash, token_info)
                )
                needs_migration = needs_migration or had_raw_token

            if needs_migration:
                migrated_data = self._token_file_document(persisted_tokens)
                try:
                    self._atomic_write_token_file(
                        Path(self.token_file_path),
                        migrated_data,
                    )
                except Exception as exc:
                    raise ValueError(
                        "Unable to migrate the static token file to digest-only "
                        "storage"
                    ) from exc
                self.logger.info(
                    "Migrated %s static token records to digest-only storage",
                    len(persisted_tokens),
                )

            self.logger.info(f"Loaded {len(tokens_list)} tokens from file: {self.token_file_path}")
            
        except ValueError:
            raise
        except Exception as e:
            self.logger.error(f"Failed to load tokens from file {self.token_file_path}: {e}")
    
    def _hash_token(self, token: str, algorithm: Optional[str] = None) -> str:
        """Hash token for secure storage"""
        return build_token_digest(token, algorithm or self.token_hash_algorithm)

    def _lookup_token(self, token: str) -> tuple[str, Optional[TokenInfo]]:
        """Look up a raw token against every digest algorithm in the store."""
        algorithms = self._digest_algorithms or {self.token_hash_algorithm}
        for algorithm in sorted(algorithms):
            token_hash = self._hash_token(token, algorithm)
            token_info = self._tokens.get(token_hash)
            if token_info is not None:
                return token_hash, token_info
        return "", None

    async def validate_token(self, token: str) -> TokenValidationResult:
        """Validate token and return user information"""
        try:
            # Find token info
            _token_hash, token_info = self._lookup_token(token)
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
        custom_token: Optional[str] = None,
        database_config: Optional[DatabaseConfig] = None
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
            self._validate_static_token_prefix(raw_token)
            validate_high_entropy_secret(
                raw_token,
                setting=f"static token '{token_id}'",
            )
            
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
                description=description,
                database_config=database_config
            )
            
            # Hash and store token
            token_hash = self._hash_token(raw_token)
            if token_hash in self._tokens:
                raise ValueError("Token value already exists")
            self._tokens[token_hash] = token_info
            self._token_ids[token_id] = token_hash
            self._digest_algorithms.add(self.token_hash_algorithm)
            
            self.logger.info(f"Created new token '{token_id}'")
            
            # Save token to file
            try:
                self._save_token_to_file(token_id, token_hash, token_info)
            except Exception:
                self._tokens.pop(token_hash, None)
                self._token_ids.pop(token_id, None)
                self._digest_algorithms = {
                    digest.partition(":")[0] for digest in self._tokens
                }
                raise
            
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
            
            # Persist the revocation before changing live state. Otherwise a
            # failed file write would let the token reappear after restart.
            token_hash = self._token_ids[token_id]
            self._remove_token_from_file(token_id)

            if token_hash in self._tokens:
                del self._tokens[token_hash]
            del self._token_ids[token_id]
            
            self.logger.info(f"Revoked token '{token_id}'")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to revoke token '{token_id}': {e}")
            return False
    
    def _save_tokens_to_file(self) -> None:
        """Save current tokens to JSON file"""
        try:
            tokens_list = [
                self._token_info_to_config(token_hash, token_info)
                for token_hash, token_info in self._tokens.items()
            ]
            file_content = self._token_file_document(tokens_list)
            self._atomic_write_token_file(
                Path(self.token_file_path),
                file_content,
            )
            self.logger.info(f"Saved {len(tokens_list)} tokens to file: {self.token_file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save tokens to file {self.token_file_path}: {e}")
    
    def _save_token_to_file(
        self,
        token_id: str,
        token_hash: str,
        token_info: TokenInfo,
    ) -> None:
        """Save one new token as a digest-only record."""
        try:
            # Load existing file
            existing_data: Dict[str, Any] = {"tokens": []}
            if os.path.exists(self.token_file_path):
                try:
                    with open(self.token_file_path, 'r', encoding='utf-8') as f:
                        existing_data = json.load(f)
                except Exception as e:
                    raise ValueError(
                        f"Could not load existing token file: {e}"
                    ) from e
            
            # Ensure tokens list exists
            if 'tokens' not in existing_data or not isinstance(existing_data['tokens'], list):
                existing_data['tokens'] = []
            
            # Check if token already exists in file
            token_exists = False
            for i, token_config in enumerate(existing_data['tokens']):
                if token_config.get('token_id') == token_id:
                    # Update existing token
                    existing_data['tokens'][i] = self._token_info_to_config(
                        token_hash,
                        token_info,
                    )
                    token_exists = True
                    break
            
            # Add new token if it doesn't exist
            if not token_exists:
                new_token_config = self._token_info_to_config(
                    token_hash,
                    token_info,
                )
                existing_data['tokens'].append(new_token_config)

            existing_data['tokens'] = [
                self._sanitize_persisted_token(token_config)
                for token_config in existing_data['tokens']
            ]

            # Update metadata
            existing_data = self._token_file_document(existing_data['tokens'])
            self._atomic_write_token_file(
                Path(self.token_file_path),
                existing_data,
            )
            self.logger.info(f"Saved token '{token_id}' to file: {self.token_file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save token '{token_id}' to file: {e}")
            raise
    
    def _token_file_document(self, tokens: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build the versioned digest-only token file document."""
        return {
            "version": "2.0",
            "description": "Doris MCP Server digest-only token configuration file",
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "tokens": tokens,
            "notes": [
                "Bearer token plaintext is returned only when a token is created.",
                "token_digest is self-describing and may use sha256 or sha512.",
                "Do not replace token_digest with a plaintext token.",
            ],
        }

    def _atomic_write_token_file(
        self,
        file_path: Path,
        file_content: Dict[str, Any],
    ) -> None:
        """Atomically replace a token file with owner-only permissions."""
        temporary_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=file_path.parent,
                prefix=f".{file_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as temporary_file:
                temporary_path = Path(temporary_file.name)
                os.chmod(temporary_path, 0o600)
                json.dump(file_content, temporary_file, indent=2, ensure_ascii=False)
                temporary_file.write("\n")
                temporary_file.flush()
                os.fsync(temporary_file.fileno())
            os.replace(temporary_path, file_path)
            os.chmod(file_path, 0o600)
            if file_path == Path(self.token_file_path):
                self._update_file_modified_time()
        except Exception:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise

    def _sanitize_persisted_token(
        self,
        token_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Remove legacy plaintext while preserving a token record's metadata."""
        token_id = str(token_config.get("token_id") or "").strip()
        if not token_id:
            raise ValueError("Static token entry requires token_id")
        has_raw_token = "token" in token_config
        has_token_digest = "token_digest" in token_config
        if has_raw_token == has_token_digest:
            raise ValueError(
                f"static token '{token_id}' must contain exactly one of "
                "token or token_digest"
            )

        sanitized = {
            key: token_config[key]
            for key in (
                "created_at",
                "expires_at",
                "expires_hours",
                "last_used",
                "description",
                "is_active",
                "database_config",
            )
            if key in token_config
        }
        sanitized["token_id"] = token_id
        if has_raw_token:
            raw_token = token_config["token"]
            if not isinstance(raw_token, str):
                raise ValueError(f"static token '{token_id}' is required")
            self._validate_static_token_prefix(raw_token)
            validate_high_entropy_secret(
                raw_token,
                setting=f"static token '{token_id}'",
            )
            sanitized["token_digest"] = self._hash_token(raw_token)
        else:
            sanitized["token_digest"] = normalize_token_digest(
                token_config["token_digest"],
                setting=f"static token '{token_id}' token_digest",
            )
        return sanitized

    def _token_info_to_config(
        self,
        token_hash: str,
        token_info: TokenInfo,
    ) -> Dict[str, Any]:
        """Convert TokenInfo to a digest-only file record."""
        token_config: Dict[str, Any] = {
            "token_id": token_info.token_id,
            "token_digest": normalize_token_digest(
                token_hash,
                setting=f"static token '{token_info.token_id}' token_digest",
            ),
            "created_at": token_info.created_at.isoformat() + "Z",
            "expires_at": (
                token_info.expires_at.isoformat() + "Z"
                if token_info.expires_at
                else None
            ),
            "last_used": (
                token_info.last_used.isoformat() + "Z"
                if token_info.last_used
                else None
            ),
            "description": token_info.description,
            "is_active": token_info.is_active
        }

        # Add database config if present
        if token_info.database_config:
            token_config["database_config"] = {
                "host": token_info.database_config.host,
                "port": token_info.database_config.port,
                "user": token_info.database_config.user,
                "password": token_info.database_config.password,
                "database": token_info.database_config.database,
                "charset": token_info.database_config.charset,
                "fe_http_port": token_info.database_config.fe_http_port
            }
        
        return token_config
    
    def _remove_token_from_file(self, token_id: str) -> None:
        """Remove a token from the JSON file"""
        try:
            if not os.path.exists(self.token_file_path):
                return
            
            # Load existing file
            with open(self.token_file_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
            
            if 'tokens' not in existing_data or not isinstance(existing_data['tokens'], list):
                return
            
            # Remove the token
            original_count = len(existing_data['tokens'])
            existing_data['tokens'] = [
                self._sanitize_persisted_token(token)
                for token in existing_data['tokens']
                if token.get('token_id') != token_id
            ]
            
            if len(existing_data['tokens']) < original_count:
                # Update metadata
                existing_data = self._token_file_document(existing_data['tokens'])
                self._atomic_write_token_file(
                    Path(self.token_file_path),
                    existing_data,
                )
                self.logger.info(f"Removed token '{token_id}' from file: {self.token_file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to remove token '{token_id}' from file: {e}")
            raise
    
    async def list_tokens(self) -> List[Dict[str, Any]]:
        """List all tokens (without sensitive data)"""
        tokens = []
        
        for token_hash, token_info in self._tokens.items():
            token_data: Dict[str, Any] = {
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
        tokens.sort(key=lambda item: str(item['created_at']), reverse=True)
        
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
            target_path = Path(file_path or self.token_file_path)
            tokens_list = [
                self._token_info_to_config(token_hash, token_info)
                for token_hash, token_info in self._tokens.items()
            ]
            self._atomic_write_token_file(
                target_path,
                self._token_file_document(tokens_list),
            )
            self.logger.info(f"Saved {len(tokens_list)} tokens to file: {target_path}")
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
            _token_hash, token_info = self._lookup_token(token)
            
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
    
    def _start_hot_reload(self) -> None:
        """Start hot reload monitoring task"""
        if self._hot_reload_task:
            return  # Already running
        
        # Update initial file modification time
        self._update_file_modified_time()
        
        # Start monitoring task
        self._hot_reload_task = asyncio.create_task(self._hot_reload_monitor())
        self.logger.info(f"Started hot reload monitoring for {self.token_file_path}")
    
    def stop_hot_reload(self) -> None:
        """Stop hot reload monitoring"""
        if self._hot_reload_task:
            self._hot_reload_task.cancel()
            self._hot_reload_task = None
            self.logger.info("Stopped hot reload monitoring")
    
    def _update_file_modified_time(self) -> None:
        """Update the last modified time of tokens file"""
        try:
            if os.path.exists(self.token_file_path):
                self._file_last_modified = os.path.getmtime(self.token_file_path)
        except Exception as e:
            self.logger.debug(f"Failed to get file modification time: {e}")
    
    async def _hot_reload_monitor(self) -> None:
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
                        old_digest_algorithms = self._digest_algorithms.copy()
                        
                        # Clear and reload
                        self._tokens.clear()
                        self._token_ids.clear()
                        self._digest_algorithms.clear()
                        
                        # Environment credentials remain effective across file reloads.
                        self._load_tokens_from_env()
                        self._load_tokens_from_file()
                        
                        # Update modification time
                        self._update_file_modified_time()
                        
                        self.logger.info(f"Hot reload completed, {len(self._tokens)} tokens loaded")
                        
                    except Exception as reload_error:
                        # Restore backup on failure
                        self.logger.error(f"Hot reload failed, restoring previous tokens: {reload_error}")
                        self._tokens = old_tokens
                        self._token_ids = old_token_ids
                        self._digest_algorithms = old_digest_algorithms
                
            except asyncio.CancelledError:
                self.logger.info("Hot reload monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Error in hot reload monitor: {e}")

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
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from filelock import FileLock

from ..utils.datetime_utils import as_utc, format_rfc3339, utc_now
from ..utils.logger import get_logger
from ..utils.secret_policy import (
    build_token_digest,
    is_static_token_environment_variable,
    normalize_token_digest,
    normalize_token_hash_algorithm,
    validate_high_entropy_secret,
)
from ..utils.security import RESERVED_DORIS_OAUTH_TOKEN_PREFIX


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
    created_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    last_used: datetime | None = None
    description: str = ""  # Optional description for token purpose
    is_active: bool = True
    database_config: DatabaseConfig | None = None  # Optional database binding


@dataclass
class TokenValidationResult:
    """Token validation result"""

    is_valid: bool
    token_info: TokenInfo | None = None
    error_message: str | None = None


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
        self._tokens: dict[str, TokenInfo] = {}  # token_hash -> TokenInfo
        self._token_ids: dict[str, str] = {}     # token_id -> token_hash
        self._digest_algorithms: set[str] = set()
        self._revoked_tokens: dict[str, dict[str, str]] = {}

        # Configuration
        self.token_file_path = getattr(config.security, 'token_file_path', 'tokens.json')
        self._token_file = Path(self.token_file_path)
        self._token_lock_file = self._token_file.with_name(
            f"{self._token_file.name}.lock"
        )
        self._token_file_lock = FileLock(
            str(self._token_lock_file),
            timeout=30,
            mode=0o600,
        )
        self.enable_token_expiry = getattr(config.security, 'enable_token_expiry', True)
        self.default_token_expiry_hours = getattr(config.security, 'default_token_expiry_hours', 24 * 30)  # 30 days
        self.token_hash_algorithm = normalize_token_hash_algorithm(
            getattr(config.security, 'token_hash_algorithm', 'sha256')
        )

        # Hot reload configuration
        self.enable_hot_reload = True
        self.hot_reload_interval = 10  # Check every 10 seconds
        self._file_last_modified = 0.0
        self._file_signature: tuple[int, int, int, int] | None = None
        self._hot_reload_task: asyncio.Task[None] | None = None

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

    @contextmanager
    def _shared_state_lock(self) -> Iterator[None]:
        """Serialize read-modify-write operations across worker processes."""
        with self._token_file_lock:
            os.chmod(self._token_lock_file, 0o600)
            yield

    def _current_file_signature(self) -> tuple[int, int, int, int] | None:
        """Return a signature that also changes after an atomic replacement."""
        try:
            file_stat = self._token_file.stat()
        except FileNotFoundError:
            return None
        return (
            file_stat.st_dev,
            file_stat.st_ino,
            file_stat.st_size,
            file_stat.st_mtime_ns,
        )

    def _reload_tokens_from_sources(self) -> None:
        """Replace local state from the environment and shared token file."""
        previous_state = (
            self._tokens,
            self._token_ids,
            self._digest_algorithms,
            self._revoked_tokens,
            self._file_signature,
            self._file_last_modified,
        )
        self._tokens = {}
        self._token_ids = {}
        self._digest_algorithms = set()
        self._revoked_tokens = {}
        try:
            self._load_tokens_from_env()
            if self._token_file.exists():
                self._load_tokens_from_file()
            self._update_file_modified_time()
        except Exception:
            (
                self._tokens,
                self._token_ids,
                self._digest_algorithms,
                self._revoked_tokens,
                self._file_signature,
                self._file_last_modified,
            ) = previous_state
            raise

    def _synchronize_shared_state(self) -> bool:
        """Reload immediately when another worker atomically changes the file."""
        if self._current_file_signature() == self._file_signature:
            return False
        with self._shared_state_lock():
            if self._current_file_signature() == self._file_signature:
                return False
            self._reload_tokens_from_sources()
        self.logger.info(
            "Synchronized %s static tokens from shared state",
            len(self._tokens),
        )
        return True

    @staticmethod
    def _parse_datetime(value: Any, *, setting: str) -> datetime | None:
        """Parse an RFC 3339 timestamp into timezone-aware UTC."""
        if value in (None, ""):
            return None
        if not isinstance(value, str):
            raise ValueError(f"{setting} must be an RFC 3339 timestamp")
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError as exc:
            raise ValueError(f"{setting} must be an RFC 3339 timestamp") from exc
        return as_utc(parsed)

    def _add_token_from_config(
        self,
        token_config: dict[str, Any],
    ) -> tuple[str, TokenInfo, bool]:
        """Add token from configuration with optional database binding"""
        try:
            token_id = str(token_config.get('token_id') or '').strip()
            if not token_id:
                raise ValueError("Static token entry requires token_id")

            created_at = self._parse_datetime(
                token_config.get('created_at'),
                setting=f"static token '{token_id}' created_at",
            ) or utc_now()

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

            # A later source wins cleanly when the same token ID is rotated.
            previous_hash = self._token_ids.get(token_info.token_id)
            if (
                previous_hash
                and previous_hash != token_hash
                and previous_hash in self._tokens
            ):
                del self._tokens[previous_hash]

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
        if self._token_file.exists():
            with self._shared_state_lock():
                self._reload_tokens_from_sources()
        else:
            self._reload_tokens_from_sources()

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
            with open(self.token_file_path, encoding='utf-8') as f:
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
            revoked_tokens = (
                tokens_data.get("revoked_tokens", [])
                if isinstance(tokens_data, dict)
                else []
            )
            if not isinstance(revoked_tokens, list):
                raise ValueError(
                    "Static token file revoked_tokens must be an array"
                )

            persisted_tokens = []
            persisted_revocations = []
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

            for revoked_token in revoked_tokens:
                sanitized = self._sanitize_revoked_token(revoked_token)
                token_hash = sanitized["token_digest"]
                self._revoked_tokens[token_hash] = sanitized
                self._digest_algorithms.add(token_hash.partition(":")[0])
                persisted_revocations.append(sanitized)

                revoked_token_info = self._tokens.get(token_hash)
                if revoked_token_info is not None:
                    del self._tokens[token_hash]
                if (
                    revoked_token_info is not None
                    and self._token_ids.get(revoked_token_info.token_id)
                    == token_hash
                ):
                    self._token_ids.pop(revoked_token_info.token_id, None)

            if needs_migration:
                migrated_data = self._token_file_document(
                    persisted_tokens,
                    persisted_revocations,
                )
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

    def _hash_token(self, token: str, algorithm: str | None = None) -> str:
        """Hash token for secure storage"""
        return str(
            build_token_digest(
                token,
                algorithm or self.token_hash_algorithm,
            )
        )

    def _candidate_token_digests(self, token: str) -> list[str]:
        algorithms = self._digest_algorithms | {self.token_hash_algorithm}
        return [
            self._hash_token(token, algorithm)
            for algorithm in sorted(algorithms)
        ]

    def _lookup_token(self, token: str) -> tuple[str, TokenInfo | None]:
        """Look up a raw token against every digest algorithm in the store."""
        candidate_digests = self._candidate_token_digests(token)
        if any(
            token_hash in self._revoked_tokens
            for token_hash in candidate_digests
        ):
            return "", None
        for token_hash in candidate_digests:
            token_info = self._tokens.get(token_hash)
            if token_info is not None:
                return token_hash, token_info
        return "", None

    async def validate_token(self, token: str) -> TokenValidationResult:
        """Validate token and return user information"""
        try:
            self._synchronize_shared_state()

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
            if token_info.expires_at and utc_now() > token_info.expires_at:
                return TokenValidationResult(
                    is_valid=False,
                    error_message="Token has expired"
                )

            # Update last used time
            token_info.last_used = utc_now()

            return TokenValidationResult(
                is_valid=True,
                token_info=token_info
            )

        except Exception as e:
            self.logger.error(
                "Token validation error (%s)",
                type(e).__name__,
            )
            return TokenValidationResult(
                is_valid=False,
                error_message="Token validation failed"
            )

    def generate_token(self, length: int = 32) -> str:
        """Generate a cryptographically secure random token"""
        return secrets.token_urlsafe(length)

    async def create_token(
        self,
        token_id: str,
        expires_hours: int | None = None,
        description: str = "",
        custom_token: str | None = None,
        database_config: DatabaseConfig | None = None
    ) -> str:
        """Create a new token"""
        try:
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
                expires_at = utc_now() + timedelta(hours=expires_hours)
            elif self.enable_token_expiry:
                expires_at = utc_now() + timedelta(hours=self.default_token_expiry_hours)

            # Create token info
            token_info = TokenInfo(
                token_id=token_id,
                expires_at=expires_at,
                description=description,
                database_config=database_config
            )

            with self._shared_state_lock():
                self._reload_tokens_from_sources()
                if token_id in self._token_ids:
                    raise ValueError(
                        f"Token ID '{token_id}' already exists"
                    )

                candidate_digests = self._candidate_token_digests(raw_token)
                if any(
                    digest in self._revoked_tokens
                    for digest in candidate_digests
                ):
                    raise ValueError(
                        "A revoked token value cannot be reused"
                    )
                if any(
                    digest in self._tokens
                    for digest in candidate_digests
                ):
                    raise ValueError("Token value already exists")

                token_hash = self._hash_token(raw_token)
                self._save_token_to_file(token_id, token_hash, token_info)
                self._tokens[token_hash] = token_info
                self._token_ids[token_id] = token_hash
                self._digest_algorithms.add(self.token_hash_algorithm)

            self.logger.info(f"Created new token '{token_id}'")

            return raw_token

        except Exception as e:
            self.logger.error(f"Failed to create token: {e}")
            raise

    async def revoke_token(self, token_id: str) -> bool:
        """Revoke a token by token ID"""
        try:
            with self._shared_state_lock():
                self._reload_tokens_from_sources()
                if token_id not in self._token_ids:
                    self.logger.warning(
                        f"Token ID '{token_id}' not found"
                    )
                    return False

                # Persist before changing live state. The shared revocation
                # record also disables environment-provisioned credentials.
                token_hash = self._token_ids[token_id]
                revocation = self._remove_token_from_file(
                    token_id,
                    token_hash,
                )
                self._tokens.pop(token_hash, None)
                self._token_ids.pop(token_id, None)
                self._revoked_tokens[token_hash] = revocation
                self._digest_algorithms.add(token_hash.partition(":")[0])

            self.logger.info(f"Revoked token '{token_id}'")
            return True

        except Exception as e:
            self.logger.error(f"Failed to revoke token '{token_id}': {e}")
            return False

    def _save_tokens_to_file(self) -> None:
        """Save current tokens to JSON file"""
        try:
            with self._shared_state_lock():
                self._reload_tokens_from_sources()
                tokens_list = [
                    self._token_info_to_config(token_hash, token_info)
                    for token_hash, token_info in self._tokens.items()
                ]
                file_content = self._token_file_document(
                    tokens_list,
                    list(self._revoked_tokens.values()),
                )
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
            existing_data: Any = {"tokens": []}
            if os.path.exists(self.token_file_path):
                try:
                    with open(self.token_file_path, encoding='utf-8') as f:
                        existing_data = json.load(f)
                except Exception as e:
                    raise ValueError(
                        f"Could not load existing token file: {e}"
                    ) from e
            if isinstance(existing_data, list):
                existing_data = {"tokens": existing_data}
            if not isinstance(existing_data, dict):
                raise ValueError("Static token file must contain an object")

            # Ensure tokens list exists
            if 'tokens' not in existing_data or not isinstance(existing_data['tokens'], list):
                existing_data['tokens'] = []
            revoked_tokens = existing_data.get("revoked_tokens", [])
            if not isinstance(revoked_tokens, list):
                raise ValueError(
                    "Static token file revoked_tokens must be an array"
                )

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
            revoked_tokens = [
                self._sanitize_revoked_token(revoked_token)
                for revoked_token in revoked_tokens
            ]

            # Update metadata
            existing_data = self._token_file_document(
                existing_data['tokens'],
                revoked_tokens,
            )
            self._atomic_write_token_file(
                Path(self.token_file_path),
                existing_data,
            )
            self.logger.info(f"Saved token '{token_id}' to file: {self.token_file_path}")

        except Exception as e:
            self.logger.error(f"Failed to save token '{token_id}' to file: {e}")
            raise

    def _token_file_document(
        self,
        tokens: list[dict[str, Any]],
        revoked_tokens: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Build the versioned digest-only token file document."""
        return {
            "version": "2.0",
            "description": (
                "Doris MCP Server digest-only shared token state"
            ),
            "updated_at": format_rfc3339(utc_now()),
            "tokens": tokens,
            "revoked_tokens": sorted(
                revoked_tokens or [],
                key=lambda entry: (
                    entry["revoked_at"],
                    entry["token_id"],
                ),
            ),
            "notes": [
                "Bearer token plaintext is returned only when a token is created.",
                "token_digest is self-describing and may use sha256 or sha512.",
                "revoked_tokens is shared by every worker and prevents token reuse.",
                "Do not replace token_digest with a plaintext token.",
            ],
        }

    def _atomic_write_token_file(
        self,
        file_path: Path,
        file_content: dict[str, Any],
    ) -> None:
        """Atomically replace a token file with owner-only permissions."""
        temporary_path: Path | None = None
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
        token_config: dict[str, Any],
    ) -> dict[str, Any]:
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

    def _sanitize_revoked_token(
        self,
        revoked_token: dict[str, Any],
    ) -> dict[str, str]:
        """Validate and whitelist a shared revocation record."""
        if not isinstance(revoked_token, dict):
            raise ValueError("Static token revocation entries must be objects")
        token_id = str(revoked_token.get("token_id") or "").strip()
        if not token_id:
            raise ValueError("Static token revocation requires token_id")
        raw_digest = revoked_token.get("token_digest")
        if not isinstance(raw_digest, str):
            raise ValueError(
                f"revoked static token '{token_id}' token_digest is required"
            )
        token_digest = normalize_token_digest(
            raw_digest,
            setting=f"revoked static token '{token_id}' token_digest",
        )
        revoked_at = self._parse_datetime(
            revoked_token.get("revoked_at"),
            setting=f"revoked static token '{token_id}' revoked_at",
        )
        if revoked_at is None:
            raise ValueError(
                f"revoked static token '{token_id}' revoked_at is required"
            )
        return {
            "token_id": token_id,
            "token_digest": token_digest,
            "revoked_at": format_rfc3339(revoked_at),
        }

    def _token_info_to_config(
        self,
        token_hash: str,
        token_info: TokenInfo,
    ) -> dict[str, Any]:
        """Convert TokenInfo to a digest-only file record."""
        token_config: dict[str, Any] = {
            "token_id": token_info.token_id,
            "token_digest": normalize_token_digest(
                token_hash,
                setting=f"static token '{token_info.token_id}' token_digest",
            ),
            "created_at": format_rfc3339(token_info.created_at),
            "expires_at": (
                format_rfc3339(token_info.expires_at)
                if token_info.expires_at
                else None
            ),
            "last_used": (
                format_rfc3339(token_info.last_used)
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

    def _remove_token_from_file(
        self,
        token_id: str,
        token_hash: str,
    ) -> dict[str, str]:
        """Remove a live record and persist a digest-only revocation."""
        try:
            existing_data: Any = {"tokens": [], "revoked_tokens": []}
            if self._token_file.exists():
                with self._token_file.open("r", encoding="utf-8") as token_file:
                    existing_data = json.load(token_file)
            if isinstance(existing_data, list):
                existing_data = {"tokens": existing_data}
            if not isinstance(existing_data, dict):
                raise ValueError("Static token file must contain an object")

            tokens = existing_data.get("tokens", [])
            revoked_tokens = existing_data.get("revoked_tokens", [])
            if not isinstance(tokens, list):
                raise ValueError(
                    "Static token file must contain a tokens array"
                )
            if not isinstance(revoked_tokens, list):
                raise ValueError(
                    "Static token file revoked_tokens must be an array"
                )

            sanitized_tokens = []
            for token in tokens:
                sanitized = self._sanitize_persisted_token(token)
                if (
                    sanitized["token_id"] != token_id
                    and sanitized["token_digest"] != token_hash
                ):
                    sanitized_tokens.append(sanitized)

            sanitized_revocations = [
                self._sanitize_revoked_token(revoked_token)
                for revoked_token in revoked_tokens
            ]
            revocation = self._sanitize_revoked_token(
                {
                    "token_id": token_id,
                    "token_digest": token_hash,
                    "revoked_at": format_rfc3339(utc_now()),
                }
            )
            sanitized_revocations = [
                item
                for item in sanitized_revocations
                if item["token_digest"] != token_hash
            ]
            sanitized_revocations.append(revocation)

            self._atomic_write_token_file(
                Path(self.token_file_path),
                self._token_file_document(
                    sanitized_tokens,
                    sanitized_revocations,
                ),
            )
            self.logger.info(
                f"Persisted revocation for '{token_id}' in "
                f"{self.token_file_path}"
            )
            return revocation

        except Exception as e:
            self.logger.error(f"Failed to remove token '{token_id}' from file: {e}")
            raise

    async def list_tokens(self) -> list[dict[str, Any]]:
        """List all tokens (without sensitive data)"""
        self._synchronize_shared_state()
        tokens = []

        for _token_hash, token_info in self._tokens.items():
            token_data: dict[str, Any] = {
                'token_id': token_info.token_id,
                'created_at': token_info.created_at.isoformat(),
                'expires_at': token_info.expires_at.isoformat() if token_info.expires_at else None,
                'last_used': token_info.last_used.isoformat() if token_info.last_used else None,
                'is_active': token_info.is_active,
                'description': token_info.description,
                'is_expired': (
                    utc_now() > token_info.expires_at
                    if token_info.expires_at
                    else False
                ),
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

        with self._shared_state_lock():
            self._reload_tokens_from_sources()
            now = utc_now()
            expired_tokens = [
                (token_hash, token_info.token_id)
                for token_hash, token_info in self._tokens.items()
                if token_info.expires_at and now > token_info.expires_at
            ]

            for token_hash, token_id in expired_tokens:
                revocation = self._remove_token_from_file(
                    token_id,
                    token_hash,
                )
                self._tokens.pop(token_hash, None)
                self._token_ids.pop(token_id, None)
                self._revoked_tokens[token_hash] = revocation

        if expired_tokens:
            self.logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")

        return len(expired_tokens)

    async def save_tokens_to_file(self, file_path: str | None = None) -> bool:
        """Save current tokens to JSON file"""
        try:
            target_path = Path(file_path or self.token_file_path)
            with self._shared_state_lock():
                self._reload_tokens_from_sources()
                tokens_list = [
                    self._token_info_to_config(token_hash, token_info)
                    for token_hash, token_info in self._tokens.items()
                ]
                self._atomic_write_token_file(
                    target_path,
                    self._token_file_document(
                        tokens_list,
                        list(self._revoked_tokens.values()),
                    ),
                )
            self.logger.info(f"Saved {len(tokens_list)} tokens to file: {target_path}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to save tokens to file: {e}")
            return False

    def get_database_config_by_token(self, token: str) -> DatabaseConfig | None:
        """Get database configuration bound to a token

        Args:
            token: The raw token string

        Returns:
            DatabaseConfig if token exists and has database binding, None otherwise
        """
        try:
            self._synchronize_shared_state()
            _token_hash, token_info = self._lookup_token(token)

            if not token_info or not token_info.is_active:
                return None

            # Check expiration
            if token_info.expires_at and utc_now() > token_info.expires_at:
                return None

            return token_info.database_config

        except Exception as e:
            self.logger.error(f"Failed to get database config for token: {e}")
            return None

    def get_token_stats(self) -> dict[str, Any]:
        """Get token statistics"""
        self._synchronize_shared_state()
        now = utc_now()
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
            'last_file_check': (
                datetime.fromtimestamp(self._file_last_modified, UTC).isoformat()
                if self._file_last_modified
                else None
            ),
        }

    def _start_hot_reload(self) -> None:
        """Start hot reload monitoring task"""
        if self._hot_reload_task:
            return  # Already running

        # _load_tokens() already captured a signature for the exact state held
        # in memory. Re-statting here could hide a change made in between.
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
            self._file_signature = self._current_file_signature()
            if self._file_signature is None:
                self._file_last_modified = 0.0
            else:
                self._file_last_modified = self._token_file.stat().st_mtime
        except Exception as e:
            self.logger.debug(f"Failed to get file modification time: {e}")

    async def _hot_reload_monitor(self) -> None:
        """Background task to monitor tokens.json file changes"""
        while True:
            try:
                await asyncio.sleep(self.hot_reload_interval)
                self._synchronize_shared_state()

            except asyncio.CancelledError:
                self.logger.info("Hot reload monitor stopped")
                break
            except Exception as e:
                self.logger.error(f"Error in hot reload monitor: {e}")

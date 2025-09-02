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
JWT Key Management Module
Provides secure key generation, loading, rotation and management for JWT tokens
"""

import os
import time
import secrets
from pathlib import Path
from typing import Optional, Tuple, Union
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from ..utils.logger import get_logger

logger = get_logger(__name__)


class KeyManager:
    """JWT Key Manager
    
    Responsible for generating, loading, rotating and securely storing JWT signing keys
    Supports RSA and EC algorithms, provides automatic key rotation functionality
    """
    
    def __init__(self, config):
        """Initialize key manager
        
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
        self.key_rotation_interval = security_config.key_rotation_interval
        self.private_key_path = security_config.jwt_private_key_path
        self.public_key_path = security_config.jwt_public_key_path
        self.secret_key = security_config.jwt_secret_key
        
        # Key storage
        self._private_key = None
        self._public_key = None
        self._secret_key = None
        self._key_generated_at = None
        
        logger.info(f"KeyManager initialized with algorithm: {self.algorithm}")
    
    async def initialize(self) -> bool:
        """Initialize key manager, load or generate keys"""
        try:
            if self.algorithm == "HS256":
                await self._initialize_symmetric_key()
            else:
                await self._initialize_asymmetric_keys()
            
            logger.info("KeyManager initialization completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize KeyManager: {e}")
            return False
    
    async def _initialize_symmetric_key(self):
        """Initialize symmetric key (HS256)"""
        if self.secret_key:
            # Use configured key
            self._secret_key = self.secret_key.encode()
            logger.info("Loaded symmetric key from configuration")
        else:
            # Generate new key
            self._secret_key = await self.generate_symmetric_key()
            logger.info("Generated new symmetric key")
        
        self._key_generated_at = datetime.utcnow()
    
    async def _initialize_asymmetric_keys(self):
        """Initialize asymmetric key pair (RS256/ES256)"""
        # Try to load keys from files
        if await self._load_keys_from_files():
            logger.info("Loaded asymmetric keys from files")
            return
        
        # Try to load from environment variables
        if await self._load_keys_from_env():
            logger.info("Loaded asymmetric keys from environment")
            return
        
        # Generate new key pair
        await self.generate_key_pair()
        logger.info("Generated new asymmetric key pair")
    
    async def _load_keys_from_files(self) -> bool:
        """Load keys from files"""
        try:
            if not self.private_key_path or not self.public_key_path:
                return False
            
            private_path = Path(self.private_key_path)
            public_path = Path(self.public_key_path)
            
            if not (private_path.exists() and public_path.exists()):
                return False
            
            # Read private key
            with open(private_path, 'rb') as f:
                private_key_data = f.read()
            self._private_key = serialization.load_pem_private_key(
                private_key_data, password=None, backend=default_backend()
            )
            
            # Read public key
            with open(public_path, 'rb') as f:
                public_key_data = f.read()
            self._public_key = serialization.load_pem_public_key(
                public_key_data, backend=default_backend()
            )
            
            # Get key generation time (using file modification time)
            self._key_generated_at = datetime.fromtimestamp(private_path.stat().st_mtime)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load keys from files: {e}")
            return False
    
    async def _load_keys_from_env(self) -> bool:
        """Load keys from environment variables"""
        try:
            private_key_env = os.getenv('JWT_PRIVATE_KEY')
            public_key_env = os.getenv('JWT_PUBLIC_KEY')
            
            if not (private_key_env and public_key_env):
                return False
            
            # Parse private key
            self._private_key = serialization.load_pem_private_key(
                private_key_env.encode(), password=None, backend=default_backend()
            )
            
            # Parse public key
            self._public_key = serialization.load_pem_public_key(
                public_key_env.encode(), backend=default_backend()
            )
            
            self._key_generated_at = datetime.utcnow()
            return True
            
        except Exception as e:
            logger.error(f"Failed to load keys from environment: {e}")
            return False
    
    async def generate_symmetric_key(self, length: int = 32) -> bytes:
        """Generate symmetric key
        
        Args:
            length: Key length (bytes), default 32 bytes (256 bits)
            
        Returns:
            Generated key
        """
        return secrets.token_bytes(length)
    
    async def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate asymmetric key pair
        
        Returns:
            (private key PEM, public key PEM) tuple
        """
        try:
            if self.algorithm == "RS256":
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
            elif self.algorithm == "ES256":
                private_key = ec.generate_private_key(
                    ec.SECP256R1(), backend=default_backend()
                )
            else:
                raise ValueError(f"Unsupported algorithm for key generation: {self.algorithm}")
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store keys
            self._private_key = private_key
            self._public_key = public_key
            self._key_generated_at = datetime.utcnow()
            
            # If file paths are configured, save to files
            if self.private_key_path and self.public_key_path:
                await self._save_keys_to_files(private_pem, public_pem)
            
            logger.info(f"Generated new {self.algorithm} key pair")
            return private_pem, public_pem
            
        except Exception as e:
            logger.error(f"Failed to generate key pair: {e}")
            raise
    
    async def _save_keys_to_files(self, private_pem: bytes, public_pem: bytes):
        """Save keys to files"""
        try:
            # Ensure directories exist
            private_path = Path(self.private_key_path)
            public_path = Path(self.public_key_path)
            
            private_path.parent.mkdir(parents=True, exist_ok=True)
            public_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Save private key (set secure permissions)
            with open(private_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_path, 0o600)  # Only owner can read/write
            
            # Save public key
            with open(public_path, 'wb') as f:
                f.write(public_pem)
            os.chmod(public_path, 0o644)  # Owner read/write, others read only
            
            logger.info(f"Saved keys to files: {private_path}, {public_path}")
            
        except Exception as e:
            logger.error(f"Failed to save keys to files: {e}")
            raise
    
    def get_private_key(self):
        """Get private key for signing"""
        if self.algorithm == "HS256":
            return self._secret_key
        else:
            return self._private_key
    
    def get_public_key(self):
        """Get public key for verification"""
        if self.algorithm == "HS256":
            return self._secret_key
        else:
            return self._public_key
    
    def get_algorithm(self) -> str:
        """Get signing algorithm"""
        return self.algorithm
    
    async def is_key_expired(self) -> bool:
        """Check if key is expired"""
        if not self._key_generated_at:
            return True
        
        expiry_time = self._key_generated_at + timedelta(seconds=self.key_rotation_interval)
        return datetime.utcnow() > expiry_time
    
    async def rotate_keys(self) -> bool:
        """Rotate keys"""
        try:
            logger.info("Starting key rotation")
            
            if self.algorithm == "HS256":
                # Generate new symmetric key
                self._secret_key = await self.generate_symmetric_key()
                self._key_generated_at = datetime.utcnow()
            else:
                # Generate new asymmetric key pair
                await self.generate_key_pair()
            
            logger.info("Key rotation completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False
    
    async def get_key_info(self) -> dict:
        """Get key information"""
        return {
            "algorithm": self.algorithm,
            "key_generated_at": self._key_generated_at.isoformat() if self._key_generated_at else None,
            "key_expires_at": (
                self._key_generated_at + timedelta(seconds=self.key_rotation_interval)
            ).isoformat() if self._key_generated_at else None,
            "is_expired": await self.is_key_expired(),
            "has_private_key": self._private_key is not None or self._secret_key is not None,
            "has_public_key": self._public_key is not None or self._secret_key is not None
        }
    
    async def export_public_key_pem(self) -> Optional[str]:
        """Export public key in PEM format"""
        if self.algorithm == "HS256":
            return None  # Symmetric key not exported
        
        if not self._public_key:
            return None
        
        try:
            public_pem = self._public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return public_pem.decode()
            
        except Exception as e:
            logger.error(f"Failed to export public key: {e}")
            return None
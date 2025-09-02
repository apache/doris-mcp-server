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
    """JWT密钥管理器
    
    负责JWT签名密钥的生成、加载、轮换和安全存储
    支持RSA和EC算法，提供自动密钥轮换功能
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
        
        # 密钥存储
        self._private_key = None
        self._public_key = None
        self._secret_key = None
        self._key_generated_at = None
        
        logger.info(f"KeyManager initialized with algorithm: {self.algorithm}")
    
    async def initialize(self) -> bool:
        """初始化密钥管理器，加载或生成密钥"""
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
        """初始化对称密钥 (HS256)"""
        if self.secret_key:
            # 使用配置的密钥
            self._secret_key = self.secret_key.encode()
            logger.info("Loaded symmetric key from configuration")
        else:
            # 生成新的密钥
            self._secret_key = await self.generate_symmetric_key()
            logger.info("Generated new symmetric key")
        
        self._key_generated_at = datetime.utcnow()
    
    async def _initialize_asymmetric_keys(self):
        """初始化非对称密钥对 (RS256/ES256)"""
        # 尝试从文件加载密钥
        if await self._load_keys_from_files():
            logger.info("Loaded asymmetric keys from files")
            return
        
        # 尝试从环境变量加载
        if await self._load_keys_from_env():
            logger.info("Loaded asymmetric keys from environment")
            return
        
        # 生成新的密钥对
        await self.generate_key_pair()
        logger.info("Generated new asymmetric key pair")
    
    async def _load_keys_from_files(self) -> bool:
        """从文件加载密钥"""
        try:
            if not self.private_key_path or not self.public_key_path:
                return False
            
            private_path = Path(self.private_key_path)
            public_path = Path(self.public_key_path)
            
            if not (private_path.exists() and public_path.exists()):
                return False
            
            # 读取私钥
            with open(private_path, 'rb') as f:
                private_key_data = f.read()
            self._private_key = serialization.load_pem_private_key(
                private_key_data, password=None, backend=default_backend()
            )
            
            # 读取公钥
            with open(public_path, 'rb') as f:
                public_key_data = f.read()
            self._public_key = serialization.load_pem_public_key(
                public_key_data, backend=default_backend()
            )
            
            # 获取密钥生成时间（使用文件修改时间）
            self._key_generated_at = datetime.fromtimestamp(private_path.stat().st_mtime)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to load keys from files: {e}")
            return False
    
    async def _load_keys_from_env(self) -> bool:
        """从环境变量加载密钥"""
        try:
            private_key_env = os.getenv('JWT_PRIVATE_KEY')
            public_key_env = os.getenv('JWT_PUBLIC_KEY')
            
            if not (private_key_env and public_key_env):
                return False
            
            # 解析私钥
            self._private_key = serialization.load_pem_private_key(
                private_key_env.encode(), password=None, backend=default_backend()
            )
            
            # 解析公钥
            self._public_key = serialization.load_pem_public_key(
                public_key_env.encode(), backend=default_backend()
            )
            
            self._key_generated_at = datetime.utcnow()
            return True
            
        except Exception as e:
            logger.error(f"Failed to load keys from environment: {e}")
            return False
    
    async def generate_symmetric_key(self, length: int = 32) -> bytes:
        """生成对称密钥
        
        Args:
            length: 密钥长度(字节)，默认32字节(256位)
            
        Returns:
            生成的密钥
        """
        return secrets.token_bytes(length)
    
    async def generate_key_pair(self) -> Tuple[bytes, bytes]:
        """生成非对称密钥对
        
        Returns:
            (私钥PEM, 公钥PEM) 元组
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
            
            # 获取公钥
            public_key = private_key.public_key()
            
            # 序列化私钥
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # 序列化公钥
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # 存储密钥
            self._private_key = private_key
            self._public_key = public_key
            self._key_generated_at = datetime.utcnow()
            
            # 如果配置了文件路径，保存到文件
            if self.private_key_path and self.public_key_path:
                await self._save_keys_to_files(private_pem, public_pem)
            
            logger.info(f"Generated new {self.algorithm} key pair")
            return private_pem, public_pem
            
        except Exception as e:
            logger.error(f"Failed to generate key pair: {e}")
            raise
    
    async def _save_keys_to_files(self, private_pem: bytes, public_pem: bytes):
        """保存密钥到文件"""
        try:
            # 确保目录存在
            private_path = Path(self.private_key_path)
            public_path = Path(self.public_key_path)
            
            private_path.parent.mkdir(parents=True, exist_ok=True)
            public_path.parent.mkdir(parents=True, exist_ok=True)
            
            # 保存私钥（设置安全权限）
            with open(private_path, 'wb') as f:
                f.write(private_pem)
            os.chmod(private_path, 0o600)  # 只有所有者可读写
            
            # 保存公钥
            with open(public_path, 'wb') as f:
                f.write(public_pem)
            os.chmod(public_path, 0o644)  # 所有者读写，其他人只读
            
            logger.info(f"Saved keys to files: {private_path}, {public_path}")
            
        except Exception as e:
            logger.error(f"Failed to save keys to files: {e}")
            raise
    
    def get_private_key(self):
        """获取私钥用于签名"""
        if self.algorithm == "HS256":
            return self._secret_key
        else:
            return self._private_key
    
    def get_public_key(self):
        """获取公钥用于验证"""
        if self.algorithm == "HS256":
            return self._secret_key
        else:
            return self._public_key
    
    def get_algorithm(self) -> str:
        """获取签名算法"""
        return self.algorithm
    
    async def is_key_expired(self) -> bool:
        """检查密钥是否过期"""
        if not self._key_generated_at:
            return True
        
        expiry_time = self._key_generated_at + timedelta(seconds=self.key_rotation_interval)
        return datetime.utcnow() > expiry_time
    
    async def rotate_keys(self) -> bool:
        """轮换密钥"""
        try:
            logger.info("Starting key rotation")
            
            if self.algorithm == "HS256":
                # 生成新的对称密钥
                self._secret_key = await self.generate_symmetric_key()
                self._key_generated_at = datetime.utcnow()
            else:
                # 生成新的非对称密钥对
                await self.generate_key_pair()
            
            logger.info("Key rotation completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Key rotation failed: {e}")
            return False
    
    async def get_key_info(self) -> dict:
        """获取密钥信息"""
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
        """导出公钥PEM格式"""
        if self.algorithm == "HS256":
            return None  # 对称密钥不导出
        
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
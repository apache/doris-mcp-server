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
SQL Security Utilities Module

Provides SQL identifier validation, escaping, and safe query building utilities
to prevent SQL injection attacks.
"""

import re
from contextvars import ContextVar
from typing import Optional, Tuple, List, Any

from .logger import get_logger

logger = get_logger(__name__)

# Context variable for auth_context (set by HTTP middleware)
auth_context_var: ContextVar = ContextVar('mcp_auth_context', default=None)


class SQLSecurityError(Exception):
    """Exception raised for SQL security validation failures"""
    pass


class SQLSecurityUtils:
    """
    SQL Security Utilities for preventing SQL injection attacks.
    
    Provides:
    - Identifier validation (database names, table names, column names)
    - Safe identifier quoting with backticks
    - Safe table reference building
    - Auth context retrieval from context variables
    """
    
    # Valid SQL identifier pattern: letters, numbers, underscores
    # Must start with letter or underscore, not a number
    # Supports Unicode letters for international database/table names
    IDENTIFIER_PATTERN = re.compile(r'^[a-zA-Z_\u4e00-\u9fff][a-zA-Z0-9_\u4e00-\u9fff]*$')
    
    # Maximum identifier length (MySQL/Doris standard)
    MAX_IDENTIFIER_LENGTH = 64
    
    # SQL reserved keywords that should be quoted
    SQL_KEYWORDS = {
        'SELECT', 'FROM', 'WHERE', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 
        'CREATE', 'ALTER', 'TABLE', 'DATABASE', 'INDEX', 'VIEW', 'AND', 
        'OR', 'NOT', 'NULL', 'TRUE', 'FALSE', 'IN', 'LIKE', 'BETWEEN',
        'JOIN', 'LEFT', 'RIGHT', 'INNER', 'OUTER', 'ON', 'AS', 'ORDER',
        'BY', 'GROUP', 'HAVING', 'LIMIT', 'OFFSET', 'UNION', 'ALL',
        'DISTINCT', 'INTO', 'VALUES', 'SET', 'DEFAULT', 'PRIMARY', 'KEY',
        'FOREIGN', 'REFERENCES', 'CHECK', 'UNIQUE', 'CONSTRAINT'
    }
    
    @classmethod
    def validate_identifier(cls, name: str, identifier_type: str = "identifier") -> str:
        """
        Validate a SQL identifier (database name, table name, column name, etc.)
        
        Args:
            name: The identifier to validate
            identifier_type: Type description for error messages (e.g., "database name", "table name")
        
        Returns:
            The validated identifier (unchanged if valid)
            
        Raises:
            SQLSecurityError: If the identifier is invalid
        """
        if not name:
            raise SQLSecurityError(f"Empty {identifier_type} is not allowed")
        
        if not isinstance(name, str):
            raise SQLSecurityError(f"Invalid {identifier_type}: must be a string, got {type(name).__name__}")
        
        # Strip whitespace
        name = name.strip()
        
        if not name:
            raise SQLSecurityError(f"Empty {identifier_type} is not allowed")
        
        # Check length
        if len(name) > cls.MAX_IDENTIFIER_LENGTH:
            raise SQLSecurityError(
                f"Invalid {identifier_type}: '{name[:20]}...' exceeds maximum length of {cls.MAX_IDENTIFIER_LENGTH} characters"
            )
        
        # Check for dangerous characters that could be SQL injection
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/', '\\', '\x00']
        for char in dangerous_chars:
            if char in name:
                raise SQLSecurityError(
                    f"Invalid {identifier_type}: '{name}' contains forbidden character '{char}'"
                )
        
        # Validate pattern
        if not cls.IDENTIFIER_PATTERN.match(name):
            raise SQLSecurityError(
                f"Invalid {identifier_type}: '{name}' contains invalid characters. "
                f"Only letters, numbers, and underscores are allowed, and must start with a letter or underscore."
            )
        
        logger.debug(f"Validated {identifier_type}: {name}")
        return name
    
    @classmethod
    def quote_identifier(cls, name: str, identifier_type: str = "identifier") -> str:
        """
        Safely quote a SQL identifier using backticks.
        
        Args:
            name: The identifier to quote
            identifier_type: Type description for error messages
        
        Returns:
            The quoted identifier (e.g., `table_name`)
            
        Raises:
            SQLSecurityError: If the identifier is invalid
        """
        # First validate the identifier
        validated_name = cls.validate_identifier(name, identifier_type)
        
        # Escape any backticks within the name (double them)
        escaped_name = validated_name.replace('`', '``')
        
        return f"`{escaped_name}`"
    
    @classmethod
    def build_table_reference(
        cls, 
        table_name: str, 
        db_name: Optional[str] = None, 
        catalog_name: Optional[str] = None,
        quote: bool = True
    ) -> str:
        """
        Build a safe, fully-qualified table reference.
        
        Args:
            table_name: The table name (required)
            db_name: The database name (optional)
            catalog_name: The catalog name (optional)
            quote: Whether to quote identifiers with backticks (default: True)
        
        Returns:
            A safe table reference string (e.g., `catalog`.`db`.`table`)
            
        Raises:
            SQLSecurityError: If any identifier is invalid
        """
        parts = []
        
        if catalog_name:
            if quote:
                parts.append(cls.quote_identifier(catalog_name, "catalog name"))
            else:
                parts.append(cls.validate_identifier(catalog_name, "catalog name"))
        
        if db_name:
            if quote:
                parts.append(cls.quote_identifier(db_name, "database name"))
            else:
                parts.append(cls.validate_identifier(db_name, "database name"))
        
        if quote:
            parts.append(cls.quote_identifier(table_name, "table name"))
        else:
            parts.append(cls.validate_identifier(table_name, "table name"))
        
        return '.'.join(parts)
    
    @classmethod
    def build_column_reference(
        cls,
        column_name: str,
        table_name: Optional[str] = None,
        quote: bool = True
    ) -> str:
        """
        Build a safe column reference.
        
        Args:
            column_name: The column name (required)
            table_name: The table name (optional, for qualified references)
            quote: Whether to quote identifiers with backticks (default: True)
        
        Returns:
            A safe column reference string (e.g., `table`.`column`)
            
        Raises:
            SQLSecurityError: If any identifier is invalid
        """
        parts = []
        
        if table_name:
            if quote:
                parts.append(cls.quote_identifier(table_name, "table name"))
            else:
                parts.append(cls.validate_identifier(table_name, "table name"))
        
        if quote:
            parts.append(cls.quote_identifier(column_name, "column name"))
        else:
            parts.append(cls.validate_identifier(column_name, "column name"))
        
        return '.'.join(parts)
    
    @classmethod
    def validate_and_build_where_condition(
        cls,
        column_name: str,
        operator: str = "=",
        use_param: bool = True
    ) -> Tuple[str, bool]:
        """
        Build a safe WHERE condition for a column.
        
        Args:
            column_name: The column name
            operator: The comparison operator (=, !=, <, >, <=, >=, LIKE, IN)
            use_param: Whether to use parameterized placeholder (%s)
        
        Returns:
            Tuple of (condition_string, needs_param)
            e.g., ("`column` = %s", True) or ("`column` = DATABASE()", False)
            
        Raises:
            SQLSecurityError: If column name is invalid or operator is not allowed
        """
        # Validate column name
        quoted_column = cls.quote_identifier(column_name, "column name")
        
        # Validate operator
        allowed_operators = {'=', '!=', '<>', '<', '>', '<=', '>=', 'LIKE', 'IN', 'IS'}
        if operator.upper() not in allowed_operators:
            raise SQLSecurityError(f"Invalid operator: '{operator}'. Allowed: {allowed_operators}")
        
        if use_param:
            return f"{quoted_column} {operator} %s", True
        else:
            return f"{quoted_column} {operator}", False
    
    @staticmethod
    def get_auth_context():
        """
        Get auth_context from the context variable.
        
        This retrieves the auth_context that was set by the HTTP middleware
        during request processing.
        
        Returns:
            The auth_context object, or None if not available
        """
        try:
            auth_context = auth_context_var.get()
            if auth_context:
                logger.debug(f"Retrieved auth_context from context variable")
            return auth_context
        except Exception as e:
            logger.debug(f"Could not retrieve auth_context: {e}")
            return None
    
    @staticmethod
    def set_auth_context(auth_context):
        """
        Set auth_context in the context variable.
        
        This is typically called by the HTTP middleware during request processing.
        
        Args:
            auth_context: The auth_context object to set
        """
        auth_context_var.set(auth_context)
        logger.debug("Set auth_context in context variable")


# Convenience functions for direct use
validate_identifier = SQLSecurityUtils.validate_identifier
quote_identifier = SQLSecurityUtils.quote_identifier
build_table_reference = SQLSecurityUtils.build_table_reference
build_column_reference = SQLSecurityUtils.build_column_reference
get_auth_context = SQLSecurityUtils.get_auth_context
set_auth_context = SQLSecurityUtils.set_auth_context


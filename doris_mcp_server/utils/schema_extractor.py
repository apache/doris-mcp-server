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
Metadata Extraction Tool

Responsible for extracting table structures, relationships, and other metadata from the database.
"""

import os
import json
import pandas as pd
import re
import uuid
import time
from typing import Dict, List, Any, Optional, Tuple
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Import unified logging configuration
from .logger import get_logger

# Configure logging
logger = get_logger(__name__)

# Load environment variables
load_dotenv(override=True)

METADATA_DB_NAME="information_schema"
ENABLE_MULTI_DATABASE=os.getenv("ENABLE_MULTI_DATABASE",True)
MULTI_DATABASE_NAMES=os.getenv("MULTI_DATABASE_NAMES","")

# Import local modules
from .db import DorisConnectionManager

class MetadataExtractor:
    """Apache Doris Metadata Extractor"""
    
    def __init__(self, db_name: str = None, catalog_name: str = None, connection_manager=None):
        """
        Initialize the metadata extractor
        
        Args:
            db_name: Default database name, uses the currently connected database if not specified
            catalog_name: Default catalog name for federation queries, uses the current catalog if not specified
            connection_manager: DorisConnectionManager instance for database operations
        """
        # Get configuration from environment variables
        self.db_name = db_name or os.getenv("DB_DATABASE", "")
        self.catalog_name = catalog_name  # Store catalog name for federation support
        self.metadata_db = METADATA_DB_NAME  # Use constant
        self.connection_manager = connection_manager
        
        # Caching system
        self.metadata_cache = {}
        self.metadata_cache_time = {}
        self.cache_ttl = int(os.getenv("METADATA_CACHE_TTL", "3600"))  # Default cache 1 hour
        
        # Refresh time
        self.last_refresh_time = None
        
        # Enable multi-database support - use variable imported from db.py
        self.enable_multi_database = ENABLE_MULTI_DATABASE
        
        # Load table hierarchy matching configuration
        self.enable_table_hierarchy = os.getenv("ENABLE_TABLE_HIERARCHY", "false").lower() == "true"
        if self.enable_table_hierarchy:
            self.table_hierarchy_patterns = self._load_table_hierarchy_patterns()
        else:
            self.table_hierarchy_patterns = []
        
        # List of excluded system databases
        self.excluded_databases = self._load_excluded_databases()
        
        # Session ID for database queries
        self._session_id = f"metadata_extractor_{uuid.uuid4().hex[:8]}"
        
    def _load_excluded_databases(self) -> List[str]:
        """
        Load the list of excluded databases configuration
        
        Returns:
            List of excluded databases
        """
        excluded_dbs_str = os.getenv("EXCLUDED_DATABASES", 
                               '["information_schema", "mysql", "performance_schema", "sys", "doris_metadata"]')
        try:
            excluded_dbs = json.loads(excluded_dbs_str)
            if isinstance(excluded_dbs, list):
                logger.info(f"Loaded excluded database list: {excluded_dbs}")
                return excluded_dbs
            else:
                logger.warning("Excluded database list configuration is not in list format, using default value")
        except json.JSONDecodeError:
            logger.warning("Error parsing excluded database list JSON, using default value")
        
        # Default value
        default_excluded_dbs = ["information_schema", "mysql", "performance_schema", "sys", "doris_metadata"]
        return default_excluded_dbs
        
    def _load_table_hierarchy_patterns(self) -> List[str]:
        """
        Load table hierarchy matching pattern configuration
        
        Returns:
            List of table hierarchy matching regular expressions
        """
        patterns_str = os.getenv("TABLE_HIERARCHY_PATTERNS", 
                               '["^ads_.*$","^dim_.*$","^dws_.*$","^dwd_.*$","^ods_.*$","^tmp_.*$","^stg_.*$","^.*$"]')
        try:
            patterns = json.loads(patterns_str)
            if isinstance(patterns, list):
                # Ensure all patterns are valid regular expressions
                validated_patterns = []
                for pattern in patterns:
                    try:
                        re.compile(pattern)
                        validated_patterns.append(pattern)
                    except re.error:
                        logger.warning(f"Invalid regular expression pattern: {pattern}")
                
                logger.info(f"Loaded table hierarchy matching patterns: {validated_patterns}")
                return validated_patterns
            else:
                logger.warning("Table hierarchy matching pattern configuration is not in list format, using default value")
        except json.JSONDecodeError:
            logger.warning("Error parsing table hierarchy matching pattern JSON, using default value")
        
        # Default value
        default_patterns = ["^ads_.*$", "^dim_.*$", "^dws_.*$", "^dwd_.*$", "^ods_.*$", "^.*$"]
        return default_patterns
        
    def get_all_databases(self, catalog_name: str = None) -> List[str]:
        """
        Get a list of all databases
        
        Args:
            catalog_name: Catalog name for federation queries, uses instance catalog if None
            
        Returns:
            List of database names
        """
        effective_catalog = catalog_name or self.catalog_name
        cache_key = f"databases_{effective_catalog or 'default'}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Use information_schema.schemata table to get database list
            query = """
            SELECT 
                SCHEMA_NAME 
            FROM 
                information_schema.schemata 
            WHERE 
                SCHEMA_NAME NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
            ORDER BY 
                SCHEMA_NAME
            """
            
            result = self._execute_query_with_catalog(query, self.db_name, effective_catalog)
            
            if not result:
                databases = []
            else:
                databases = [db["SCHEMA_NAME"] for db in result]
                logger.info(f"Retrieved database list from catalog {effective_catalog or 'default'}: {databases}")
            
            # Update cache
            self.metadata_cache[cache_key] = databases
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return databases
        except Exception as e:
            logger.error(f"Error getting database list: {str(e)}")
            return []

    def get_all_target_databases(self) -> List[str]:
        """
        Get all target databases
        
        If multi-database support is enabled, returns all databases from the configuration;
        Otherwise, returns the current database
        
        Returns:
            List of target databases
        """
        if self.enable_multi_database:
            # Get multi-database list from configuration
            from doris_mcp_server.utils.db import MULTI_DATABASE_NAMES
            
            # If configuration is empty, return current database and all databases in the system
            if not MULTI_DATABASE_NAMES:
                all_dbs = self.get_all_databases()
                # Put the current database at the front
                if self.db_name in all_dbs:
                    all_dbs.remove(self.db_name)
                    all_dbs = [self.db_name] + all_dbs
                
                # Filter out excluded databases
                all_dbs = [db for db in all_dbs if db not in self.excluded_databases]
                logger.info(f"Multi-database list not configured, getting database list from system: {all_dbs}")
                return all_dbs
            else:
                # Ensure the current database is in the list and at the front
                db_names = list(MULTI_DATABASE_NAMES)  # Copy to avoid modifying the original list
                if self.db_name and self.db_name not in db_names:
                    db_names.insert(0, self.db_name)
                elif self.db_name and self.db_name in db_names:
                    # If current database is in the list but not first, adjust position
                    db_names.remove(self.db_name)
                    db_names.insert(0, self.db_name)
                
                # Filter out excluded databases
                db_names = [db for db in db_names if db not in self.excluded_databases]
                logger.info(f"Using configured multi-database list: {db_names}")
                return db_names
        else:
            # Return only the current database
            if self.db_name in self.excluded_databases:
                logger.warning(f"Current database {self.db_name} is in the excluded list, metadata retrieval might not work properly")
            return [self.db_name] if self.db_name else []
    
    def get_database_tables(self, db_name: Optional[str] = None, catalog_name: str = None) -> List[str]:
        """
        Get a list of all tables in the database
        
        Args:
            db_name: Database name, uses current database if None
            catalog_name: Catalog name for federation queries, uses instance catalog if None
            
        Returns:
            List of table names
        """
        db_name = db_name or self.db_name
        effective_catalog = catalog_name or self.catalog_name
        if not db_name:
            logger.warning("Database name not specified")
            return []
        
        cache_key = f"tables_{effective_catalog or 'default'}_{db_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Use information_schema.tables table to get table list
            query = f"""
            SELECT 
                TABLE_NAME 
            FROM 
                information_schema.tables 
            WHERE 
                TABLE_SCHEMA = '{db_name}' 
                AND TABLE_TYPE = 'BASE TABLE'
            """
            
            result = self._execute_query_with_catalog(query, db_name, effective_catalog)
            logger.info(f"{effective_catalog or 'default'}.{db_name}.information_schema.tables query result: {result}")
            
            if not result:
                tables = []
            else:
                tables = [table['TABLE_NAME'] for table in result]
                logger.info(f"Table names retrieved from {effective_catalog or 'default'}.{db_name}.information_schema.tables: {tables}")
            
            # Sort tables by hierarchy matching (if enabled)
            if self.enable_table_hierarchy and tables:
                tables = self._sort_tables_by_hierarchy(tables)
            
            # Update cache
            self.metadata_cache[cache_key] = tables
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return tables
        except Exception as e:
            logger.error(f"Error getting table list: {str(e)}")
            return []
    
    def get_all_tables_and_columns(self) -> Dict[str, Any]:
        """
        Get information for all tables and columns
        
        Returns:
            Dict[str, Any]: Dictionary containing information for all tables and columns
        """
        cache_key = f"all_tables_columns_{self.db_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            result = {}
            tables = self.get_database_tables(self.db_name)
            
            for table_name in tables:
                schema = self.get_table_schema(table_name, self.db_name)
                if schema:
                    columns = schema.get("columns", [])
                    column_names = [col.get("name") for col in columns if col.get("name")]
                    column_types = {col.get("name"): col.get("type") for col in columns if col.get("name") and col.get("type")}
                    column_comments = {col.get("name"): col.get("comment") for col in columns if col.get("name")}
                    
                    result[table_name] = {
                        "comment": schema.get("comment", ""),
                        "columns": column_names,
                        "column_types": column_types,
                        "column_comments": column_comments
                    }
            
            # Update cache
            self.metadata_cache[cache_key] = result
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return result
        except Exception as e:
            logger.error(f"Error getting all tables and columns information: {str(e)}")
            return {}
    
    def _sort_tables_by_hierarchy(self, tables: List[str]) -> List[str]:
        """
        Sort tables based on hierarchy matching patterns
        
        Args:
            tables: List of table names
            
        Returns:
            Sorted list of table names
        """
        if not self.enable_table_hierarchy or not self.table_hierarchy_patterns:
            return tables
        
        # Group tables by pattern priority
        table_groups = []
        remaining_tables = set(tables)
        
        for pattern in self.table_hierarchy_patterns:
            matching_tables = []
            regex = re.compile(pattern)
            
            for table in list(remaining_tables):
                if regex.match(table):
                    matching_tables.append(table)
                    remaining_tables.remove(table)
            
            if matching_tables:
                # Within each group, sort alphabetically
                matching_tables.sort()
                table_groups.append(matching_tables)
        
        # Add remaining tables to the end
        if remaining_tables:
            table_groups.append(sorted(list(remaining_tables)))
        
        # Flatten the groups
        return [table for group in table_groups for table in group]
    
    def get_all_tables_from_all_databases(self) -> Dict[str, List[str]]:
        """
        Get all tables from all target databases
        
        Returns:
            Mapping from database name to list of table names
        """
        all_tables = {}
        target_dbs = self.get_all_target_databases()
        
        for db_name in target_dbs:
            tables = self.get_database_tables(db_name)
            if tables:
                all_tables[db_name] = tables
        
        return all_tables
    
    def find_tables_by_pattern(self, pattern: str, db_name: Optional[str] = None) -> List[Tuple[str, str]]:
        """
        Find matching tables in the database based on a pattern
        
        Args:
            pattern: Table name pattern (regular expression)
            db_name: Database name, searches all target databases if None
            
        Returns:
            List of matching (database_name, table_name) tuples
        """
        try:
            regex = re.compile(pattern)
        except re.error:
            logger.error(f"Invalid regular expression pattern: {pattern}")
            return []
        
        matches = []
        
        if db_name:
            # Search only in the specified database
            tables = self.get_database_tables(db_name)
            matches = [(db_name, table) for table in tables if regex.match(table)]
        else:
            # Search in all target databases
            all_tables = self.get_all_tables_from_all_databases()
            
            for db, tables in all_tables.items():
                db_matches = [(db, table) for table in tables if regex.match(table)]
                matches.extend(db_matches)
        
        return matches
    
    def get_table_schema(self, table_name: str, db_name: Optional[str] = None, catalog_name: str = None) -> Dict[str, Any]:
        """
        Get the schema information for a table
        
        Args:
            table_name: Table name
            db_name: Database name, uses current database if None
            catalog_name: Catalog name for federation queries, uses instance catalog if None
            
        Returns:
            Table schema information, including column names, types, nullability, defaults, comments, etc.
        """
        db_name = db_name or self.db_name
        effective_catalog = catalog_name or self.catalog_name
        if not db_name:
            logger.warning("Database name not specified")
            return {}
        
        cache_key = f"schema_{effective_catalog or 'default'}_{db_name}_{table_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Use information_schema.columns table to get table schema
            query = f"""
            SELECT 
                COLUMN_NAME, 
                DATA_TYPE, 
                IS_NULLABLE, 
                COLUMN_DEFAULT, 
                COLUMN_COMMENT,
                ORDINAL_POSITION,
                COLUMN_KEY,
                EXTRA
            FROM 
                information_schema.columns 
            WHERE 
                TABLE_SCHEMA = '{db_name}' 
                AND TABLE_NAME = '{table_name}'
            ORDER BY 
                ORDINAL_POSITION
            """
            
            result = self._execute_query_with_catalog(query, db_name, effective_catalog)
            
            if not result:
                logger.warning(f"Table {effective_catalog or 'default'}.{db_name}.{table_name} does not exist or has no columns")
                return {}
                
            # Create structured table schema information
            columns = []
            for col in result:
                # Ensure using actual column values, not column names
                column_info = {
                    "name": col.get("COLUMN_NAME", ""),
                    "type": col.get("DATA_TYPE", ""),
                    "nullable": col.get("IS_NULLABLE", "") == "YES",
                    "default": col.get("COLUMN_DEFAULT", ""),
                    "comment": col.get("COLUMN_COMMENT", "") or "",
                    "position": col.get("ORDINAL_POSITION", ""),
                    "key": col.get("COLUMN_KEY", "") or "",
                    "extra": col.get("EXTRA", "") or ""
                }
                columns.append(column_info)
                
            # Get table comment
            table_comment = self.get_table_comment(table_name, db_name, effective_catalog)
            
            # Build complete structure
            schema = {
                "name": table_name,
                "database": db_name,
                "comment": table_comment,
                "columns": columns,
                "create_time": datetime.now().isoformat()
            }
            
            # Get table type information
            try:
                table_type_query = f"""
                SELECT 
                    TABLE_TYPE,
                    ENGINE 
                FROM 
                    information_schema.tables 
                WHERE 
                    TABLE_SCHEMA = '{db_name}' 
                    AND TABLE_NAME = '{table_name}'
                """
                table_type_result = self._execute_query(table_type_query)
                if table_type_result:
                    schema["table_type"] = table_type_result[0].get("TABLE_TYPE", "")
                    schema["engine"] = table_type_result[0].get("ENGINE", "")
            except Exception as e:
                logger.warning(f"Error getting table type information: {str(e)}")
            
            # Update cache
            self.metadata_cache[cache_key] = schema
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return schema
        except Exception as e:
            logger.error(f"Error getting table schema: {str(e)}")
            return {}
    
    def get_table_comment(self, table_name: str, db_name: Optional[str] = None, catalog_name: str = None) -> str:
        """
        Get the comment for a table
        
        Args:
            table_name: Table name
            db_name: Database name, uses current database if None
            catalog_name: Catalog name for federation queries, uses instance catalog if None
            
        Returns:
            Table comment
        """
        db_name = db_name or self.db_name
        effective_catalog = catalog_name or self.catalog_name
        if not db_name:
            logger.warning("Database name not specified")
            return ""
        
        cache_key = f"table_comment_{effective_catalog or 'default'}_{db_name}_{table_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Use information_schema.tables table to get table comment
            query = f"""
            SELECT 
                TABLE_COMMENT 
            FROM 
                information_schema.tables 
            WHERE 
                TABLE_SCHEMA = '{db_name}' 
                AND TABLE_NAME = '{table_name}'
            """
            
            result = self._execute_query_with_catalog(query, db_name, effective_catalog)
            
            if not result or not result[0]:
                comment = ""
            else:
                comment = result[0].get("TABLE_COMMENT", "")
            
            # Update cache
            self.metadata_cache[cache_key] = comment
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return comment
        except Exception as e:
            logger.error(f"Error getting table comment: {str(e)}")
            return ""
    
    def get_column_comments(self, table_name: str, db_name: Optional[str] = None, catalog_name: str = None) -> Dict[str, str]:
        """
        Get comments for all columns in a table
        
        Args:
            table_name: Table name
            db_name: Database name, uses current database if None
            catalog_name: Catalog name for federation queries, uses instance catalog if None
            
        Returns:
            Dictionary of column names and comments
        """
        db_name = db_name or self.db_name
        effective_catalog = catalog_name or self.catalog_name
        if not db_name:
            logger.warning("Database name not specified")
            return {}
        
        cache_key = f"column_comments_{effective_catalog or 'default'}_{db_name}_{table_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Use information_schema.columns table to get column comments
            query = f"""
            SELECT 
                COLUMN_NAME, 
                COLUMN_COMMENT 
            FROM 
                information_schema.columns 
            WHERE 
                TABLE_SCHEMA = '{db_name}' 
                AND TABLE_NAME = '{table_name}'
            ORDER BY 
                ORDINAL_POSITION
            """
            
            result = self._execute_query_with_catalog(query, db_name, effective_catalog)
            
            comments = {}
            for col in result:
                column_name = col.get("COLUMN_NAME", "")
                column_comment = col.get("COLUMN_COMMENT", "")
                if column_name:
                    comments[column_name] = column_comment
            
            # Update cache
            self.metadata_cache[cache_key] = comments
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return comments
        except Exception as e:
            logger.error(f"Error getting column comments: {str(e)}")
            return {}
    
    def get_table_indexes(self, table_name: str, db_name: Optional[str] = None, catalog_name: str = None) -> List[Dict[str, Any]]:
        """
        Get the index information for a table
        
        Args:
            table_name: Table name
            db_name: Database name, uses the database specified during initialization if None
            catalog_name: Catalog name for federation queries, uses instance catalog if None
            
        Returns:
            List[Dict[str, Any]]: List of index information
        """
        db_name = db_name or self.db_name
        effective_catalog = catalog_name or self.catalog_name
        if not db_name:
            logger.error("Database name not specified")
            return []
        
        cache_key = f"indexes_{effective_catalog or 'default'}_{db_name}_{table_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Build query with catalog prefix if specified
            if effective_catalog:
                query = f"SHOW INDEX FROM `{effective_catalog}`.`{db_name}`.`{table_name}`"
                logger.info(f"Using three-part naming for index query: {query}")
            else:
                query = f"SHOW INDEX FROM `{db_name}`.`{table_name}`"
            
            try:
                df = self._execute_query(query, return_dataframe=True)
                
                # Process results
                indexes = []
                current_index = None
                
                if not df.empty:
                    for _, row in df.iterrows():
                        try:
                            index_name = row['Key_name']
                            column_name = row['Column_name']
                            
                            if current_index is None or current_index['name'] != index_name:
                                if current_index is not None:
                                    indexes.append(current_index)
                                
                                current_index = {
                                    'name': index_name,
                                    'columns': [column_name],
                                    'unique': row['Non_unique'] == 0,
                                    'type': row['Index_type']
                                }
                            else:
                                current_index['columns'].append(column_name)
                        except Exception as row_error:
                            logger.warning(f"Failed to process index row data: {row_error}")
                            continue
                    
                    if current_index is not None:
                        indexes.append(current_index)
            except Exception as df_error:
                logger.warning(f"DataFrame processing failed, trying regular query: {df_error}")
                # Fall back to regular query
                result = self._execute_query(query, return_dataframe=False)
                indexes = []
                if result:
                    # Simple processing, no complex index grouping
                    for row in result:
                        if isinstance(row, dict):
                            indexes.append({
                                'name': row.get('Key_name', ''),
                                'columns': [row.get('Column_name', '')],
                                'unique': row.get('Non_unique', 1) == 0,
                                'type': row.get('Index_type', '')
                            })
            
            # Update cache
            self.metadata_cache[cache_key] = indexes
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return indexes
        except Exception as e:
            logger.error(f"Error getting index information: {str(e)}")
            return []
    
    def get_table_relationships(self) -> List[Dict[str, Any]]:
        """
        Infer table relationships from table comments and naming patterns
        
        Returns:
            List[Dict[str, Any]]: List of table relationship information
        """
        cache_key = f"relationships_{self.db_name}"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Get all tables
            tables = self.get_database_tables(self.db_name)
            relationships = []
            
            # Simple foreign key naming convention detection
            # Example: If a table has a column named xxx_id and another table named xxx exists, it might be a foreign key relationship
            for table_name in tables:
                schema = self.get_table_schema(table_name, self.db_name)
                columns = schema.get("columns", [])
                
                for column in columns:
                    column_name = column["name"]
                    if column_name.endswith('_id'):
                        # Possible foreign key table name
                        ref_table_name = column_name[:-3]  # Remove _id suffix
                        
                        # Check if the possible table exists
                        if ref_table_name in tables:
                            # Find possible primary key column
                            ref_schema = self.get_table_schema(ref_table_name, self.db_name)
                            ref_columns = ref_schema.get("columns", [])
                            
                            # Assume primary key column name is id
                            if any(col["name"] == "id" for col in ref_columns):
                                relationships.append({
                                    "table": table_name,
                                    "column": column_name,
                                    "references_table": ref_table_name,
                                    "references_column": "id",
                                    "relationship_type": "many-to-one",
                                    "confidence": "medium"  # Low confidence, based on naming convention
                                })
            
            # Update cache
            self.metadata_cache[cache_key] = relationships
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return relationships
        except Exception as e:
            logger.error(f"Error inferring table relationships: {str(e)}")
            return []
    
    def get_recent_audit_logs(self, days: int = 7, limit: int = 100) -> pd.DataFrame:
        """
        Get recent audit logs
        
        Args:
            days: Get audit logs for the last N days
            limit: Maximum number of records to return
            
        Returns:
            pd.DataFrame: Audit log DataFrame
        """
        try:
            start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            
            query = f"""
            SELECT client_ip, user, db, time, stmt_id, stmt, state, error_code
            FROM `__internal_schema`.`audit_log`
            WHERE `time` >= '{start_date}'
            AND state = 'EOF' AND error_code = 0
            AND `stmt` NOT LIKE 'SHOW%'
            AND `stmt` NOT LIKE 'DESC%'
            AND `stmt` NOT LIKE 'EXPLAIN%'
            AND `stmt` NOT LIKE 'SELECT 1%'
            ORDER BY time DESC
            LIMIT {limit}
            """
            df = self._execute_query(query, return_dataframe=True)
            return df
        except Exception as e:
            logger.error(f"Error getting audit logs: {str(e)}")
            return pd.DataFrame()
    
    def get_catalog_list(self) -> List[Dict[str, Any]]:
        """
        Get a list of all catalogs in Doris with detailed information
        
        Returns:
            List[Dict[str, Any]]: List of catalog information including CatalogId, CatalogName, Type, IsCurrent, CreateTime, LastUpdateTime, Comment
        """
        cache_key = "catalogs"
        if cache_key in self.metadata_cache and (datetime.now() - self.metadata_cache_time.get(cache_key, datetime.min)).total_seconds() < self.cache_ttl:
            return self.metadata_cache[cache_key]
        
        try:
            # Use SHOW CATALOGS command to get catalog list
            query = "SHOW CATALOGS"
            result = self._execute_query(query)
            
            if not result:
                catalogs = []
            else:
                # Extract catalog information from the result
                # SHOW CATALOGS returns: CatalogId, CatalogName, Type, IsCurrent, CreateTime, LastUpdateTime, Comment
                catalogs = []
                for row in result:
                    if isinstance(row, dict):
                        catalog_info = {
                            "catalog_id": row.get("CatalogId", ""),
                            "catalog_name": row.get("CatalogName", ""),
                            "type": row.get("Type", ""),
                            "is_current": row.get("IsCurrent", ""),
                            "create_time": row.get("CreateTime", ""),
                            "last_update_time": row.get("LastUpdateTime", ""),
                            "comment": row.get("Comment", "")
                        }
                        catalogs.append(catalog_info)
                
                logger.info(f"Retrieved catalog list: {catalogs}")
            
            # Update cache
            self.metadata_cache[cache_key] = catalogs
            self.metadata_cache_time[cache_key] = datetime.now()
            
            return catalogs
        except Exception as e:
            logger.error(f"Error getting catalog list: {str(e)}")
            return []
    
    def extract_sql_comments(self, sql: str) -> str:
        """
        Extract comments from SQL
        
        Args:
            sql: SQL query
            
        Returns:
            str: Extracted comments
        """
        # Extract single-line comments
        single_line_comments = re.findall(r'--\s*(.*?)(?:\n|$)', sql)
        
        # Extract multi-line comments
        multi_line_comments = re.findall(r'/\*(.*?)\*/', sql, re.DOTALL)
        
        # Merge all comments
        all_comments = single_line_comments + multi_line_comments
        return '\n'.join(comment.strip() for comment in all_comments if comment.strip())
    
    def extract_common_sql_patterns(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Extract common SQL patterns
        
        Args:
            limit: Maximum number of audit logs to retrieve
            
        Returns:
            List[Dict[str, Any]]: List of SQL pattern information, including pattern, type, frequency, etc.
        """
        try:
            # Get audit logs
            audit_logs = self.get_recent_audit_logs(days=30, limit=limit)
            if audit_logs.empty:
                # If audit logs cannot be retrieved, return some default patterns
                default_patterns = [
                    {
                        "pattern": "SELECT * FROM {table} WHERE {condition}",
                        "type": "SELECT",
                        "frequency": 1
                    },
                    {
                        "pattern": "SELECT {columns} FROM {table} GROUP BY {group_by} ORDER BY {order_by} LIMIT {limit}",
                        "type": "SELECT",
                        "frequency": 1
                    }
                ]
                return default_patterns
            
            # Group and process by SQL type
            patterns_by_type = {}
            for _, row in audit_logs.iterrows():
                sql = row['stmt']
                if not sql:
                    continue
                
                # Determine SQL type
                sql_type = self._get_sql_type(sql)
                if not sql_type:
                    continue
                
                # Simplify SQL
                simplified_sql = self._simplify_sql(sql)
                
                # Extract involved tables
                tables = self._extract_tables_from_sql(sql)
                
                # Extract SQL comments
                comments = self.extract_sql_comments(sql)
                
                # Initialize if it's a new pattern
                if sql_type not in patterns_by_type:
                    patterns_by_type[sql_type] = []
                    
                # Check if a similar pattern exists
                found_similar = False
                for pattern in patterns_by_type[sql_type]:
                    if self._are_sqls_similar(simplified_sql, pattern['simplified_sql']):
                        pattern['count'] += 1
                        pattern['examples'].append(sql)
                        if comments:
                            pattern['comments'].append(comments)
                        found_similar = True
                        break
                        
                # If no similar pattern found, add new pattern
                if not found_similar:
                    patterns_by_type[sql_type].append({
                        'simplified_sql': simplified_sql,
                        'examples': [sql],
                        'comments': [comments] if comments else [],
                        'count': 1,
                        'tables': tables
                    })
                    
            # Convert grouped patterns to the required output format
            result_patterns = []
            
            # Sort by frequency and convert format
            for sql_type, type_patterns in patterns_by_type.items():
                sorted_patterns = sorted(type_patterns, key=lambda x: x['count'], reverse=True)
                
                # Extract top 3 patterns and convert to expected format
                for pattern in sorted_patterns[:3]:
                    # Create output consistent with the format used in _update_sql_patterns_for_all_databases
                    result_patterns.append({
                        "pattern": pattern['simplified_sql'],
                        "type": sql_type,
                        "frequency": pattern['count'],
                        "examples": json.dumps(pattern['examples'][:3], ensure_ascii=False),
                        "comments": json.dumps(pattern['comments'][:3], ensure_ascii=False) if pattern['comments'] else "[]",
                        "tables": json.dumps(pattern['tables'], ensure_ascii=False)
                    })
            
            # If no patterns found, return default values
            if not result_patterns:
                default_patterns = [
                    {
                        "pattern": "SELECT * FROM {table} WHERE {condition}",
                        "type": "SELECT",
                        "frequency": 1,
                        "examples": "[]",
                        "comments": "[]",
                        "tables": "[]"
                    },
                    {
                        "pattern": "SELECT {columns} FROM {table} GROUP BY {group_by} ORDER BY {order_by} LIMIT {limit}",
                        "type": "SELECT",
                        "frequency": 1,
                        "examples": "[]",
                        "comments": "[]",
                        "tables": "[]"
                    }
                ]
                return default_patterns
            
            return result_patterns
            
        except Exception as e:
            logger.error(f"Error extracting SQL patterns: {str(e)}")
            # Return some default patterns to ensure subsequent processing doesn't fail
            default_patterns = [
                {
                    "pattern": "SELECT * FROM {table} WHERE {condition}",
                    "type": "SELECT",
                    "frequency": 1,
                    "examples": "[]",
                    "comments": "[]",
                    "tables": "[]"
                },
                {
                    "pattern": "SELECT {columns} FROM {table} GROUP BY {group_by} ORDER BY {order_by} LIMIT {limit}",
                    "type": "SELECT",
                    "frequency": 1,
                    "examples": "[]",
                    "comments": "[]",
                    "tables": "[]"
                }
            ]
            return default_patterns
    
    def _simplify_sql(self, sql: str) -> str:
        """
        Simplify SQL for better pattern recognition
        
        Args:
            sql: SQL query
            
        Returns:
            str: Simplified SQL
        """
        # Remove comments
        sql = re.sub(r'--.*?(\n|$)', ' ', sql)
        sql = re.sub(r'/\*.*?\*/', ' ', sql, flags=re.DOTALL)
        
        # Replace string and numeric constants
        sql = re.sub(r"'[^']*'", "'?'", sql)
        sql = re.sub(r'\b\d+\b', '?', sql)
        
        # Replace contents of IN clauses
        sql = re.sub(r'IN\s*\([^)]+\)', 'IN (?)', sql, flags=re.IGNORECASE)
        
        # Remove excess whitespace
        sql = re.sub(r'\s+', ' ', sql).strip()
        
        return sql
    
    
    def _extract_tables_from_sql(self, sql: str) -> List[str]:
        """
        Extract table names from SQL
        
        Args:
            sql: SQL query
            
        Returns:
            List[str]: List of table names
        """
        # This is a very simplified implementation
        # Real applications require more complex SQL parsing
        tables = set()
        
        # Find table names after FROM clause
        from_matches = re.finditer(r'\bFROM\s+`?(\w+)`?', sql, re.IGNORECASE)
        for match in from_matches:
            tables.add(match.group(1))
        
        # Find table names after JOIN clause
        join_matches = re.finditer(r'\bJOIN\s+`?(\w+)`?', sql, re.IGNORECASE)
        for match in join_matches:
            tables.add(match.group(1))
        
        # Find table names after INSERT INTO
        insert_matches = re.finditer(r'\bINSERT\s+INTO\s+`?(\w+)`?', sql, re.IGNORECASE)
        for match in insert_matches:
            tables.add(match.group(1))
        
        # Find table names after UPDATE
        update_matches = re.finditer(r'\bUPDATE\s+`?(\w+)`?', sql, re.IGNORECASE)
        for match in update_matches:
            tables.add(match.group(1))
        
        # Find table names after DELETE FROM
        delete_matches = re.finditer(r'\bDELETE\s+FROM\s+`?(\w+)`?', sql, re.IGNORECASE)
        for match in delete_matches:
            tables.add(match.group(1))
        
        return list(tables)
    
    
    
    def get_table_partition_info(self, db_name: str, table_name: str) -> Dict[str, Any]:
        """
        Get partition information for a table
        
        Args:
            db_name: Database name
            table_name: Table name
            
        Returns:
            Dict: Partition information
        """
        try:
            # Get partition information
            query = f"""
            SELECT 
                PARTITION_NAME,
                PARTITION_EXPRESSION,
                PARTITION_DESCRIPTION,
                TABLE_ROWS
            FROM 
                information_schema.partitions
            WHERE 
                TABLE_SCHEMA = '{db_name}'
                AND TABLE_NAME = '{table_name}'
            """
            
            partitions = self._execute_query(query)
            
            if not partitions:
                return {}
                
            partition_info = {
                "has_partitions": True,
                "partitions": []
            }
            
            for part in partitions:
                partition_info["partitions"].append({
                    "name": part.get("PARTITION_NAME", ""),
                    "expression": part.get("PARTITION_EXPRESSION", ""),
                    "description": part.get("PARTITION_DESCRIPTION", ""),
                    "rows": part.get("TABLE_ROWS", 0)
                })
                
            return partition_info
        except Exception as e:
            logger.error(f"Error getting partition information for table {db_name}.{table_name}: {str(e)}")
            return {}

    def _execute_query_with_catalog(self, query: str, db_name: str = None, catalog_name: str = None):
        """
        Execute query with catalog-aware metadata operations using three-part naming
        
        Args:
            query: SQL query to execute
            db_name: Database name to use
            catalog_name: Catalog name for three-part naming
            
        Returns:
            Query result
        """
        try:
            # If catalog_name is specified, modify the query to use three-part naming
            # for information_schema queries
            if catalog_name and 'information_schema' in query.lower():
                # Replace 'information_schema' with 'catalog_name.information_schema'
                modified_query = query.replace('information_schema', f'{catalog_name}.information_schema')
                logger.info(f"Modified query for catalog {catalog_name}: {modified_query}")
                return self._execute_query(modified_query, db_name)
            else:
                # Execute the original query
                return self._execute_query(query, db_name)
        except Exception as e:
            logger.error(f"Error executing query with catalog: {str(e)}")
            raise

    async def _execute_query_async(self, query: str, db_name: str = None, return_dataframe: bool = False):
        """
        Execute database query asynchronously
        
        Args:
            query: SQL query to execute
            db_name: Database name to use (optional)
            return_dataframe: Whether to return a pandas DataFrame instead of list
            
        Returns:
            Query result data (list of dictionaries or pandas DataFrame)
        """
        try:
            if self.connection_manager:
                # Use the injected connection manager directly (async)
                result = await self.connection_manager.execute_query(self._session_id, query, None)
                
                # Extract data from QueryResult
                if hasattr(result, 'data'):
                    data = result.data
                else:
                    data = result
                
                # Convert to DataFrame if requested
                if return_dataframe and data:
                    import pandas as pd
                    return pd.DataFrame(data)
                elif return_dataframe:
                    import pandas as pd
                    return pd.DataFrame()
                else:
                    return data
            else:
                # Fallback: Return empty result
                logger.warning("No connection manager provided, returning empty result")
                if return_dataframe:
                    import pandas as pd
                    return pd.DataFrame()
                else:
                    return []
        except Exception as e:
            logger.error(f"Error executing query: {str(e)}")
            # Return empty result instead of raising exception to prevent cascade failures
            if return_dataframe:
                import pandas as pd
                return pd.DataFrame()
            else:
                return []

    def _execute_query(self, query: str, db_name: str = None, return_dataframe: bool = False):
        """
        Execute database query with proper session management (sync wrapper)
        
        Args:
            query: SQL query to execute
            db_name: Database name to use (optional)
            return_dataframe: Whether to return a pandas DataFrame instead of list
            
        Returns:
            Query result data (list of dictionaries or pandas DataFrame)
        """
        try:
            if self.connection_manager:
                import asyncio
                import concurrent.futures
                import threading
                
                # Always run in a separate thread with new event loop to avoid conflicts
                def run_in_new_loop():
                    # Create new event loop for this thread
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        return new_loop.run_until_complete(
                            self._execute_query_async(query, db_name, return_dataframe)
                        )
                    finally:
                        try:
                            # Properly close the loop
                            pending = asyncio.all_tasks(new_loop)
                            if pending:
                                new_loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                        finally:
                            new_loop.close()
                
                # Use ThreadPoolExecutor to run in separate thread
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(run_in_new_loop)
                    try:
                        return future.result(timeout=30)
                    except concurrent.futures.TimeoutError:
                        logger.error("Query execution timed out after 30 seconds")
                        if return_dataframe:
                            import pandas as pd
                            return pd.DataFrame()
                        else:
                            return []
            else:
                # Fallback: Return empty result
                logger.warning("No connection manager provided, returning empty result")
                if return_dataframe:
                    import pandas as pd
                    return pd.DataFrame()
                else:
                    return []
        except Exception as e:
            logger.error(f"Error executing query: {str(e)}")
            # Return empty result instead of raising exception to prevent cascade failures
            if return_dataframe:
                import pandas as pd
                return pd.DataFrame()
            else:
                return []

    async def get_table_schema_async(self, table_name: str, db_name: str = None, catalog_name: str = None) -> List[Dict[str, Any]]:
        """Asynchronously get table schema information"""
        try:
            # Use async query method
            effective_catalog = catalog_name or self.catalog_name
            
            # Build query statement
            if effective_catalog and effective_catalog != "internal":
                query = f"DESCRIBE `{effective_catalog}`.`{db_name or self.db_name}`.`{table_name}`"
            else:
                query = f"DESCRIBE `{db_name or self.db_name}`.`{table_name}`"
            
            # Execute async query
            result = await self._execute_query_async(query, db_name)
            
            if not result:
                return []
            
            # Process results
            schema = []
            for row in result:
                if isinstance(row, dict):
                    schema.append({
                        'column_name': row.get('Field', ''),
                        'data_type': row.get('Type', ''),
                        'is_nullable': row.get('Null', 'NO') == 'YES',
                        'default_value': row.get('Default', None),
                        'comment': row.get('Comment', ''),
                        'key': row.get('Key', ''),
                        'extra': row.get('Extra', '')
                    })
            
            return schema
            
        except Exception as e:
            logger.error(f"Failed to get table schema: {e}")
            return []

    async def get_all_databases_async(self, catalog_name: str = None) -> List[str]:
        """Asynchronously get all database list"""
        try:
            effective_catalog = catalog_name or self.catalog_name
            
            if effective_catalog and effective_catalog != "internal":
                query = f"SHOW DATABASES FROM `{effective_catalog}`"
            else:
                query = "SHOW DATABASES"
            
            result = await self._execute_query_async(query)
            
            if not result:
                return []
            
            # Extract database names
            databases = []
            for row in result:
                if isinstance(row, dict):
                    # Get the value of the first field (usually Database field)
                    db_name = list(row.values())[0] if row else None
                    if db_name:
                        databases.append(db_name)
            
            return databases
            
        except Exception as e:
            logger.error(f"Failed to get database list: {e}")
            return []

    async def get_database_tables_async(self, db_name: str = None, catalog_name: str = None) -> List[str]:
        """Asynchronously get table list in database"""
        try:
            effective_catalog = catalog_name or self.catalog_name
            effective_db = db_name or self.db_name
            
            if effective_catalog and effective_catalog != "internal":
                query = f"SHOW TABLES FROM `{effective_catalog}`.`{effective_db}`"
            else:
                query = f"SHOW TABLES FROM `{effective_db}`"
            
            result = await self._execute_query_async(query, effective_db)
            
            if not result:
                return []
            
            # Extract table names
            tables = []
            for row in result:
                if isinstance(row, dict):
                    # Get the value of the first field (usually Tables_in_xxx field)
                    table_name = list(row.values())[0] if row else None
                    if table_name:
                        tables.append(table_name)
            
            return tables
            
        except Exception as e:
            logger.error(f"Failed to get table list: {e}")
            return []

    async def get_catalog_list_async(self) -> List[str]:
        """Asynchronously get catalog list"""
        try:
            query = "SHOW CATALOGS"
            result = await self._execute_query_async(query)
            
            if not result:
                return []
            
            # Extract catalog names
            catalogs = []
            for row in result:
                if isinstance(row, dict):
                    # SHOW CATALOGS returns fields including: CatalogId, CatalogName, Type, IsCurrent, CreateTime, LastUpdateTime, Comment
                    # We need to get the CatalogName field (second field)
                    if 'CatalogName' in row:
                        catalog_name = row['CatalogName']
                    else:
                        # If no CatalogName field, try to get the second field
                        values = list(row.values())
                        catalog_name = values[1] if len(values) > 1 else values[0] if values else None
                    
                    if catalog_name:
                        catalogs.append(str(catalog_name))
            
            return catalogs
            
        except Exception as e:
            logger.error(f"Failed to get catalog list: {e}")
            return []

    # ==================== Business layer methods (original metadata_tools.py functionality) ====================
    
    def _format_response(self, success: bool, result: Any = None, error: str = None, message: str = "") -> Dict[str, Any]:
        """Format response result"""
        response_data = {
            "success": success,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        if success and result is not None:
            response_data["result"] = result
            response_data["message"] = message or "Operation successful"
        elif not success:
            response_data["error"] = error or "Unknown error"
            response_data["message"] = message or "Operation failed"
        
        return response_data

    async def exec_query_for_mcp(
        self, 
        sql: str, 
        db_name: str = None, 
        catalog_name: str = None, 
        max_rows: int = 100, 
        timeout: int = 30
    ) -> Dict[str, Any]:
        """
        Execute SQL query and return results, supports catalog federation queries
        Unified interface for MCP tools
        """
        logger.info(f"Executing SQL query: {sql}, DB: {db_name}, Catalog: {catalog_name}, MaxRows: {max_rows}, Timeout: {timeout}")
        
        try:
            if not sql:
                return self._format_response(success=False, error="No SQL statement provided", message="Please provide SQL statement to execute")

            # Import query executor
            from .query_executor import execute_sql_query

            # Call execute_sql_query to execute query
            exec_result = await execute_sql_query(
                sql=sql,
                connection_manager=self.connection_manager,
                limit=max_rows,
                timeout=timeout
            )

            return exec_result

        except Exception as e:
            logger.error(f"Failed to execute SQL query: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while executing SQL query")

    async def get_table_schema_for_mcp(
        self, 
        table_name: str, 
        db_name: str = None, 
        catalog_name: str = None
    ) -> Dict[str, Any]:
        """Get detailed schema information for specified table (columns, types, comments, etc.) - MCP interface"""
        logger.info(f"Getting table schema: Table: {table_name}, DB: {db_name}, Catalog: {catalog_name}")
        
        if not table_name:
            return self._format_response(success=False, error="Missing table_name parameter")
        
        try:
            schema = await self.get_table_schema_async(table_name=table_name, db_name=db_name, catalog_name=catalog_name)
            
            if not schema:
                return self._format_response(
                    success=False, 
                    error="Table does not exist or has no columns", 
                    message=f"Unable to get schema for table {catalog_name or 'default'}.{db_name or self.db_name}.{table_name}"
                )
            
            return self._format_response(success=True, result=schema)
        except Exception as e:
            logger.error(f"Failed to get table schema: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting table schema")

    async def get_db_table_list_for_mcp(
        self, 
        db_name: str = None, 
        catalog_name: str = None
    ) -> Dict[str, Any]:
        """Get list of all table names in specified database - MCP interface"""
        logger.info(f"Getting database table list: DB: {db_name}, Catalog: {catalog_name}")
        
        try:
            tables = await self.get_database_tables_async(db_name=db_name, catalog_name=catalog_name)
            return self._format_response(success=True, result=tables)
        except Exception as e:
            logger.error(f"Failed to get database table list: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting database table list")

    async def get_db_list_for_mcp(self, catalog_name: str = None) -> Dict[str, Any]:
        """Get list of all database names on server - MCP interface"""
        logger.info(f"Getting database list: Catalog: {catalog_name}")
        
        try:
            databases = await self.get_all_databases_async(catalog_name=catalog_name)
            return self._format_response(success=True, result=databases)
        except Exception as e:
            logger.error(f"Failed to get database list: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting database list")

    async def get_table_comment_for_mcp(
        self, 
        table_name: str, 
        db_name: str = None, 
        catalog_name: str = None
    ) -> Dict[str, Any]:
        """Get comment information for specified table - MCP interface"""
        logger.info(f"Getting table comment: Table: {table_name}, DB: {db_name}, Catalog: {catalog_name}")
        
        if not table_name:
            return self._format_response(success=False, error="Missing table_name parameter")
        
        try:
            comment = self.get_table_comment(table_name=table_name, db_name=db_name, catalog_name=catalog_name)
            return self._format_response(success=True, result=comment)
        except Exception as e:
            logger.error(f"Failed to get table comment: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting table comment")

    async def get_table_column_comments_for_mcp(
        self, 
        table_name: str, 
        db_name: str = None, 
        catalog_name: str = None
    ) -> Dict[str, Any]:
        """Get comment information for all columns in specified table - MCP interface"""
        logger.info(f"Getting table column comments: Table: {table_name}, DB: {db_name}, Catalog: {catalog_name}")
        
        if not table_name:
            return self._format_response(success=False, error="Missing table_name parameter")
        
        try:
            comments = self.get_column_comments(table_name=table_name, db_name=db_name, catalog_name=catalog_name)
            return self._format_response(success=True, result=comments)
        except Exception as e:
            logger.error(f"Failed to get table column comments: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting table column comments")

    async def get_table_indexes_for_mcp(
        self, 
        table_name: str, 
        db_name: str = None, 
        catalog_name: str = None
    ) -> Dict[str, Any]:
        """Get index information for specified table - MCP interface"""
        logger.info(f"Getting table indexes: Table: {table_name}, DB: {db_name}, Catalog: {catalog_name}")
        
        if not table_name:
            return self._format_response(success=False, error="Missing table_name parameter")
        
        try:
            indexes = self.get_table_indexes(table_name=table_name, db_name=db_name, catalog_name=catalog_name)
            return self._format_response(success=True, result=indexes)
        except Exception as e:
            logger.error(f"Failed to get table indexes: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting table indexes")

    def _serialize_datetime_objects(self, data):
        """Serialize datetime objects to JSON compatible format"""
        if isinstance(data, list):
            return [self._serialize_datetime_objects(item) for item in data]
        elif isinstance(data, dict):
            return {key: self._serialize_datetime_objects(value) for key, value in data.items()}
        elif hasattr(data, 'isoformat'):  # datetime, date, time objects
            return data.isoformat()
        elif hasattr(data, 'strftime'):  # pandas Timestamp objects
            return data.strftime('%Y-%m-%d %H:%M:%S')
        else:
            return data

    async def get_recent_audit_logs_for_mcp(self, days: int = 7, limit: int = 100) -> Dict[str, Any]:
        """Get recent audit log records - MCP interface"""
        logger.info(f"Getting audit logs: Days: {days}, Limit: {limit}")
        
        try:
            logs_df = self.get_recent_audit_logs(days=days, limit=limit)
            
            # Convert DataFrame to JSON format
            if hasattr(logs_df, 'to_dict'):
                try:
                    logs_data = logs_df.to_dict('records')
                except Exception as e:
                    logger.warning(f"DataFrame.to_dict failed, trying manual conversion: {e}")
                    # Manually convert DataFrame to records format
                    logs_data = []
                    if not logs_df.empty:
                        for _, row in logs_df.iterrows():
                            logs_data.append(dict(row))
                # Serialize datetime objects
                logs_data = self._serialize_datetime_objects(logs_data)
            else:
                logs_data = self._serialize_datetime_objects(logs_df)
                
            return self._format_response(success=True, result=logs_data)
        except Exception as e:
            logger.error(f"Failed to get audit logs: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting audit logs")

    async def get_catalog_list_for_mcp(self) -> Dict[str, Any]:
        """Get Doris catalog list - MCP interface"""
        logger.info("Getting catalog list")
        
        try:
            catalogs = await self.get_catalog_list_async()
            return self._format_response(success=True, result=catalogs, message="Successfully retrieved catalog list")
        except Exception as e:
            logger.error(f"Failed to get catalog list: {str(e)}", exc_info=True)
            return self._format_response(success=False, error=str(e), message="Error occurred while getting catalog list")


# ==================== Compatibility aliases ====================

# For backward compatibility, create MetadataManager alias
class MetadataManager:
    """
    Metadata manager - backward compatibility class
    Actually a wrapper for MetadataExtractor
    """
    
    def __init__(self, connection_manager=None):
        self.extractor = MetadataExtractor(connection_manager=connection_manager)
    
    async def exec_query(self, sql: str, db_name: str = None, catalog_name: str = None, max_rows: int = 100, timeout: int = 30) -> Dict[str, Any]:
        """Execute SQL query and return results, supports catalog federation queries"""
        return await self.extractor.exec_query_for_mcp(sql, db_name, catalog_name, max_rows, timeout)
    
    async def get_table_schema(self, table_name: str, db_name: str = None, catalog_name: str = None) -> Dict[str, Any]:
        """Get detailed schema information for specified table (columns, types, comments, etc.)"""
        return await self.extractor.get_table_schema_for_mcp(table_name, db_name, catalog_name)
    
    async def get_db_table_list(self, db_name: str = None, catalog_name: str = None) -> Dict[str, Any]:
        """Get list of all table names in specified database"""
        return await self.extractor.get_db_table_list_for_mcp(db_name, catalog_name)
    
    async def get_db_list(self, catalog_name: str = None) -> Dict[str, Any]:
        """Get list of all database names on server"""
        return await self.extractor.get_db_list_for_mcp(catalog_name)
    
    async def get_table_comment(self, table_name: str, db_name: str = None, catalog_name: str = None) -> Dict[str, Any]:
        """Get comment information for specified table"""
        return await self.extractor.get_table_comment_for_mcp(table_name, db_name, catalog_name)
    
    async def get_table_column_comments(self, table_name: str, db_name: str = None, catalog_name: str = None) -> Dict[str, Any]:
        """Get comment information for all columns in specified table"""
        return await self.extractor.get_table_column_comments_for_mcp(table_name, db_name, catalog_name)
    
    async def get_table_indexes(self, table_name: str, db_name: str = None, catalog_name: str = None) -> Dict[str, Any]:
        """Get index information for specified table"""
        return await self.extractor.get_table_indexes_for_mcp(table_name, db_name, catalog_name)
    
    async def get_recent_audit_logs(self, days: int = 7, limit: int = 100) -> Dict[str, Any]:
        """Get recent audit log records"""
        return await self.extractor.get_recent_audit_logs_for_mcp(days, limit)
    
    async def get_catalog_list(self) -> Dict[str, Any]:
        """Get Doris catalog list"""
        return await self.extractor.get_catalog_list_for_mcp()
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
Token Authentication HTTP Handlers

Provides HTTP endpoints for token management including creation, revocation,
listing, and statistics. Used for administrative token management in HTTP mode.
"""

import json
from typing import Dict, Any

from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse

from ..utils.logger import get_logger
from ..utils.security import SecurityLevel
from ..utils.config import DatabaseConfig
from .token_security_middleware import TokenSecurityMiddleware


class TokenHandlers:
    """Token Authentication HTTP Handlers"""
    
    def __init__(self, security_manager, config=None):
        self.security_manager = security_manager
        self.logger = get_logger(__name__)
        
        # Initialize security middleware if config is provided
        if config:
            self.security_middleware = TokenSecurityMiddleware(config)
        else:
            self.security_middleware = None
            self.logger.warning("Token handlers initialized without security middleware - access control disabled")
    
    async def handle_create_token(self, request: Request) -> JSONResponse:
        """Handle token creation request"""
        # Apply security checks
        if self.security_middleware:
            security_response = await self.security_middleware.check_token_management_access(request)
            if security_response:
                return security_response
        
        try:
            # Check if token manager is available
            if not self.security_manager.auth_provider.token_manager:
                return JSONResponse({
                    "error": "Token authentication is not enabled"
                }, status_code=503)
            
            # Parse request data
            if request.method == "GET":
                # GET request with query parameters
                query_params = dict(request.query_params)
                token_id = query_params.get("token_id")
                expires_hours_str = query_params.get("expires_hours")
                description = query_params.get("description", "")
                custom_token = query_params.get("custom_token")
                # Database configuration from query params
                db_config = None
                if query_params.get("db_host"):
                    db_config = DatabaseConfig(
                        host=query_params.get("db_host", "localhost"),
                        port=int(query_params.get("db_port", "9030")),
                        user=query_params.get("db_user", "root"),
                        password=query_params.get("db_password", ""),
                        database=query_params.get("db_database", "information_schema"),
                        fe_http_port=int(query_params.get("db_fe_http_port", "8030"))
                    )
            else:
                # POST request with JSON body
                try:
                    body = await request.json()
                except:
                    return JSONResponse({
                        "error": "Invalid JSON body"
                    }, status_code=400)
                
                token_id = body.get("token_id")
                expires_hours_str = body.get("expires_hours")
                description = body.get("description", "")
                custom_token = body.get("custom_token")
                # Database configuration from JSON body
                db_config = None
                if body.get("database_config"):
                    db_data = body["database_config"]
                    try:
                        db_config = DatabaseConfig(
                            host=db_data.get("host", "localhost"),
                            port=int(db_data.get("port", 9030)),
                            user=db_data.get("user", "root"),
                            password=db_data.get("password", ""),
                            database=db_data.get("database", "information_schema"),
                            fe_http_port=int(db_data.get("fe_http_port", 8030))
                        )
                    except (ValueError, TypeError) as e:
                        return JSONResponse({
                            "error": f"Invalid database configuration: {str(e)}"
                        }, status_code=400)
            
            # Validate required fields
            if not token_id:
                return JSONResponse({
                    "error": "token_id is required"
                }, status_code=400)
            
            # Parse expires_hours
            expires_hours = None
            if expires_hours_str:
                try:
                    expires_hours = int(expires_hours_str)
                except ValueError:
                    return JSONResponse({
                        "error": "expires_hours must be an integer"
                    }, status_code=400)
            
            # Create token using the actual API
            try:
                token = await self.security_manager.create_token(
                    token_id=token_id,
                    expires_hours=expires_hours,
                    description=description,
                    custom_token=custom_token,
                    database_config=db_config
                )
                
                return JSONResponse({
                    "success": True,
                    "token_id": token_id,
                    "token": token,
                    "expires_hours": expires_hours,
                    "description": description,
                    "message": "Token created successfully"
                })
                
            except Exception as e:
                self.logger.error(f"Token creation failed: {e}")
                return JSONResponse({
                    "error": f"Token creation failed: {str(e)}"
                }, status_code=400)
            
        except Exception as e:
            self.logger.error(f"Error in handle_create_token: {e}")
            return JSONResponse({
                "error": f"Internal server error: {str(e)}"
            }, status_code=500)
    
    async def handle_revoke_token(self, request: Request) -> JSONResponse:
        """Handle token revocation request"""
        # Apply security checks
        if self.security_middleware:
            security_response = await self.security_middleware.check_token_management_access(request)
            if security_response:
                return security_response
        
        try:
            # Check if token manager is available
            if not self.security_manager.auth_provider.token_manager:
                return JSONResponse({
                    "error": "Token authentication is not enabled"
                }, status_code=503)
            
            # Get token_id from query parameters or path
            token_id = request.query_params.get("token_id")
            if not token_id and request.method == "DELETE":
                # Try to get from path: /token/revoke/{token_id}
                path_parts = str(request.url.path).split("/")
                if len(path_parts) >= 4:
                    token_id = path_parts[-1]
            
            if not token_id:
                return JSONResponse({
                    "error": "token_id is required"
                }, status_code=400)
            
            # Revoke token
            success = await self.security_manager.revoke_token(token_id)
            
            if success:
                return JSONResponse({
                    "success": True,
                    "token_id": token_id,
                    "message": "Token revoked successfully"
                })
            else:
                return JSONResponse({
                    "success": False,
                    "token_id": token_id,
                    "message": "Token not found or already revoked"
                }, status_code=404)
            
        except Exception as e:
            self.logger.error(f"Error in handle_revoke_token: {e}")
            return JSONResponse({
                "error": f"Internal server error: {str(e)}"
            }, status_code=500)
    
    async def handle_list_tokens(self, request: Request) -> JSONResponse:
        """Handle token listing request"""
        # Apply security checks
        if self.security_middleware:
            security_response = await self.security_middleware.check_token_management_access(request)
            if security_response:
                return security_response
        
        try:
            # Check if token manager is available
            if not self.security_manager.auth_provider.token_manager:
                return JSONResponse({
                    "error": "Token authentication is not enabled"
                }, status_code=503)
            
            # Get tokens list
            tokens = await self.security_manager.list_tokens()
            
            return JSONResponse({
                "success": True,
                "count": len(tokens),
                "tokens": tokens
            })
            
        except Exception as e:
            self.logger.error(f"Error in handle_list_tokens: {e}")
            return JSONResponse({
                "error": f"Internal server error: {str(e)}"
            }, status_code=500)
    
    async def handle_token_stats(self, request: Request) -> JSONResponse:
        """Handle token statistics request"""
        # Apply security checks
        if self.security_middleware:
            security_response = await self.security_middleware.check_token_management_access(request)
            if security_response:
                return security_response
        
        try:
            # Check if token manager is available
            if not self.security_manager.auth_provider.token_manager:
                return JSONResponse({
                    "error": "Token authentication is not enabled"
                }, status_code=503)
            
            # Get token statistics
            stats = self.security_manager.get_token_stats()
            
            return JSONResponse({
                "success": True,
                "stats": stats
            })
            
        except Exception as e:
            self.logger.error(f"Error in handle_token_stats: {e}")
            return JSONResponse({
                "error": f"Internal server error: {str(e)}"
            }, status_code=500)
    
    async def handle_cleanup_tokens(self, request: Request) -> JSONResponse:
        """Handle expired tokens cleanup request"""
        # Apply security checks
        if self.security_middleware:
            security_response = await self.security_middleware.check_token_management_access(request)
            if security_response:
                return security_response
        
        try:
            # Check if token manager is available
            if not self.security_manager.auth_provider.token_manager:
                return JSONResponse({
                    "error": "Token authentication is not enabled"
                }, status_code=503)
            
            # Cleanup expired tokens
            cleaned_count = await self.security_manager.cleanup_expired_tokens()
            
            return JSONResponse({
                "success": True,
                "cleaned_count": cleaned_count,
                "message": f"Cleaned up {cleaned_count} expired tokens"
            })
            
        except Exception as e:
            self.logger.error(f"Error in handle_cleanup_tokens: {e}")
            return JSONResponse({
                "error": f"Internal server error: {str(e)}"
            }, status_code=500)
    
    async def handle_management_page(self, request: Request) -> HTMLResponse:
        """Handle token management demo page"""
        # Apply security checks
        if self.security_middleware:
            security_response = await self.security_middleware.check_token_management_access(request)
            if security_response:
                # Convert JSON response to HTML for demo page
                error_data = security_response.body.decode('utf-8') if hasattr(security_response, 'body') else '{"error": "Access denied"}'
                try:
                    error_info = json.loads(error_data)
                except:
                    error_info = {"error": "Access denied"}
                
                error_html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Access Denied - Token Management</title>
                    <style>
                        body {{ font-family: Arial, sans-serif; margin: 50px; background: #f5f5f5; }}
                        .container {{ max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
                        .error {{ color: #dc3545; background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; }}
                        .security-info {{ background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin-top: 20px; }}
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h1>🔐 Token Management - Access Denied</h1>
                        <div class="error">
                            <h3>Access Denied</h3>
                            <p><strong>Error:</strong> {error_info.get('error', 'Access denied')}</p>
                            <p><strong>Message:</strong> {error_info.get('message', 'Token management access is restricted')}</p>
                            {'<p><strong>Your IP:</strong> ' + str(error_info.get('client_ip', 'Unknown')) + '</p>' if 'client_ip' in error_info else ''}
                        </div>
                        
                        <div class="security-info">
                            <h3>🛡️ Security Information</h3>
                            <p>Token management endpoints are protected by the following security measures:</p>
                            <ul>
                                <li><strong>IP Restrictions:</strong> Only localhost/127.0.0.1 access allowed</li>
                                <li><strong>Admin Authentication:</strong> Valid admin token required</li>
                                <li><strong>Configuration Control:</strong> Must be explicitly enabled</li>
                            </ul>
                            <p>If you need access, please:</p>
                            <ol>
                                <li>Access from the server host (127.0.0.1)</li>
                                <li>Ensure HTTP token management is enabled in configuration</li>
                                <li>Provide valid admin authentication</li>
                            </ol>
                        </div>
                    </div>
                </body>
                </html>
                """
                return HTMLResponse(error_html, status_code=security_response.status_code)
        
        try:
            # Check if token manager is available
            if not self.security_manager.auth_provider.token_manager:
                html_content = """
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Token Management - Not Available</title>
                    <style>
                        body { font-family: Arial, sans-serif; margin: 50px; }
                        .error { color: red; font-size: 18px; }
                    </style>
                </head>
                <body>
                    <h1>Token Management</h1>
                    <div class="error">Token authentication is not enabled on this server.</div>
                </body>
                </html>
                """
                return HTMLResponse(html_content)
            
            # Get current stats for demo
            stats = self.security_manager.get_token_stats()
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Doris MCP Server - Token Management</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 50px; background: #f5f5f5; }}
                    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
                    h1 {{ color: #333; }}
                    .section {{ margin: 30px 0; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }}
                    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }}
                    .stat-item {{ padding: 15px; background: #f8f9fa; border-radius: 5px; text-align: center; }}
                    .stat-value {{ font-size: 24px; font-weight: bold; color: #007bff; }}
                    .form-group {{ margin: 15px 0; }}
                    .form-group label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
                    .form-group input, .form-group textarea {{ width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }}
                    button {{ padding: 10px 20px; margin: 5px; border: none; border-radius: 4px; cursor: pointer; }}
                    .btn-primary {{ background: #007bff; color: white; }}
                    .btn-danger {{ background: #dc3545; color: white; }}
                    .btn-success {{ background: #28a745; color: white; }}
                    .response {{ margin: 15px 0; padding: 15px; border-radius: 5px; }}
                    .response.success {{ background: #d4edda; border: 1px solid #c3e6cb; }}
                    .response.error {{ background: #f8d7da; border: 1px solid #f5c6cb; }}
                    .token-list {{ margin: 15px 0; }}
                    .token-item {{ padding: 10px; margin: 5px 0; background: #f8f9fa; border-radius: 4px; }}
                    pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>🔐 Doris MCP Server - Token Management</h1>
                    
                    <div class="section">
                        <h2>📊 Token Statistics</h2>
                        <div class="stats">
                            <div class="stat-item">
                                <div class="stat-value">{stats.get('total_tokens', 0)}</div>
                                <div>Total Tokens</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">{stats.get('active_tokens', 0)}</div>
                                <div>Active Tokens</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value">{stats.get('expired_tokens', 0)}</div>
                                <div>Expired Tokens</div>
                            </div>
                        </div>
                        <p><strong>Token Expiry:</strong> {'Enabled' if stats.get('expiry_enabled') else 'Disabled'}</p>
                        <p><strong>Default Expiry:</strong> {stats.get('default_expiry_hours', 0)} hours</p>
                    </div>
                    
                    <div class="section">
                        <h2>➕ Create New Token</h2>
                        <form id="createTokenForm">
                            <div class="form-group">
                                <label for="token_id">Token ID (required):</label>
                                <input type="text" id="token_id" name="token_id" placeholder="e.g., my-app-token" required>
                            </div>
                            <div class="form-group">
                                <label for="expires_hours">Expires Hours (optional):</label>
                                <input type="number" id="expires_hours" name="expires_hours" placeholder="e.g., 720 (30 days), leave empty for default">
                            </div>
                            <div class="form-group">
                                <label for="description">Description (optional):</label>
                                <textarea id="description" name="description" placeholder="Token description"></textarea>
                            </div>
                            <div class="form-group">
                                <label for="custom_token">Custom Token (optional):</label>
                                <input type="text" id="custom_token" name="custom_token" placeholder="Leave empty to auto-generate">
                                <small style="color: #666; display: block; margin-top: 5px;">If not provided, a secure token will be generated automatically</small>
                            </div>
                            
                            <div class="section" style="margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px;">
                                <h3>🗄️ Database Configuration (Optional)</h3>
                                <p style="color: #666; font-size: 14px; margin-bottom: 15px;">Configure database connection for this token. Leave empty to use system defaults.</p>
                                
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                                    <div class="form-group">
                                        <label for="db_host">Host:</label>
                                        <input type="text" id="db_host" name="db_host" placeholder="localhost">
                                    </div>
                                    <div class="form-group">
                                        <label for="db_port">Port:</label>
                                        <input type="number" id="db_port" name="db_port" placeholder="9030">
                                    </div>
                                    <div class="form-group">
                                        <label for="db_user">User:</label>
                                        <input type="text" id="db_user" name="db_user" placeholder="root">
                                    </div>
                                    <div class="form-group">
                                        <label for="db_password">Password:</label>
                                        <input type="password" id="db_password" name="db_password" placeholder="(optional)">
                                    </div>
                                    <div class="form-group">
                                        <label for="db_database">Database:</label>
                                        <input type="text" id="db_database" name="db_database" placeholder="information_schema">
                                    </div>
                                    <div class="form-group">
                                        <label for="db_fe_http_port">FE HTTP Port:</label>
                                        <input type="number" id="db_fe_http_port" name="db_fe_http_port" placeholder="8030">
                                    </div>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn-primary">Create Token</button>
                        </form>
                        <div id="createTokenResponse"></div>
                    </div>
                    
                    <div class="section">
                        <h2>📋 Token Management</h2>
                        <button id="listTokensBtn" class="btn-success">Refresh Token List</button>
                        <button id="cleanupTokensBtn" class="btn-primary">Cleanup Expired Tokens</button>
                        <div id="tokenListResponse"></div>
                        
                        <h3>Revoke Token</h3>
                        <div class="form-group">
                            <input type="text" id="revokeTokenId" placeholder="Enter token ID to revoke">
                            <button id="revokeTokenBtn" class="btn-danger">Revoke Token</button>
                        </div>
                        <div id="revokeTokenResponse"></div>
                    </div>
                    
                    <div class="section">
                        <h2>🔧 API Endpoints</h2>
                        <p>Use these endpoints for programmatic token management:</p>
                        <ul>
                            <li><strong>POST /token/create</strong> - Create new token</li>
                            <li><strong>DELETE /token/revoke?token_id=...</strong> - Revoke token</li>
                            <li><strong>GET /token/list</strong> - List all tokens</li>
                            <li><strong>GET /token/stats</strong> - Get token statistics</li>
                            <li><strong>POST /token/cleanup</strong> - Cleanup expired tokens</li>
                        </ul>
                    </div>
                </div>
                
                <script>
                    // Get admin token from URL parameters
                    const urlParams = new URLSearchParams(window.location.search);
                    const adminToken = urlParams.get('admin_token');
                    
                    // Create request headers with admin token
                    function getAuthHeaders() {{
                        if (adminToken) {{
                            return {{
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${{adminToken}}`
                            }};
                        }} else {{
                            return {{'Content-Type': 'application/json'}};
                        }}
                    }}
                    
                    // Create URL with admin token parameter
                    function getAuthURL(baseUrl) {{
                        if (adminToken) {{
                            const separator = baseUrl.includes('?') ? '&' : '?';
                            return `${{baseUrl}}${{separator}}admin_token=${{encodeURIComponent(adminToken)}}`;
                        }}
                        return baseUrl;
                    }}
                    
                    function showResponse(elementId, data, isSuccess = true) {{
                        const element = document.getElementById(elementId);
                        element.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                        element.className = 'response ' + (isSuccess ? 'success' : 'error');
                    }}
                    
                    // Create token form - updated to match actual API
                    document.getElementById('createTokenForm').addEventListener('submit', async (e) => {{
                        e.preventDefault();
                        const formData = new FormData(e.target);
                        const data = Object.fromEntries(formData.entries());
                        
                        // Remove empty fields for optional parameters
                        if (!data.expires_hours) delete data.expires_hours;
                        if (!data.description) delete data.description;
                        if (!data.custom_token) delete data.custom_token;
                        
                        // Handle database configuration
                        if (data.db_host) {{
                            data.database_config = {{
                                host: data.db_host,
                                port: data.db_port ? parseInt(data.db_port) : 9030,
                                user: data.db_user || 'root',
                                password: data.db_password || '',
                                database: data.db_database || 'information_schema',
                                fe_http_port: data.db_fe_http_port ? parseInt(data.db_fe_http_port) : 8030
                            }};
                        }}
                        
                        // Remove individual database fields from data
                        delete data.db_host;
                        delete data.db_port;
                        delete data.db_user;
                        delete data.db_password;
                        delete data.db_database;
                        delete data.db_fe_http_port;
                        
                        try {{
                            const response = await fetch(getAuthURL('/token/create'), {{
                                method: 'POST',
                                headers: getAuthHeaders(),
                                body: JSON.stringify(data)
                            }});
                            const result = await response.json();
                            showResponse('createTokenResponse', result, response.ok);
                            
                            // Refresh token list if creation was successful
                            if (response.ok) {{
                                document.getElementById('listTokensBtn').click();
                            }}
                        }} catch (error) {{
                            showResponse('createTokenResponse', {{error: error.message}}, false);
                        }}
                    }});
                    
                    // List tokens
                    document.getElementById('listTokensBtn').addEventListener('click', async () => {{
                        try {{
                            const response = await fetch(getAuthURL('/token/list'), {{
                                headers: getAuthHeaders()
                            }});
                            const result = await response.json();
                            showResponse('tokenListResponse', result, response.ok);
                        }} catch (error) {{
                            showResponse('tokenListResponse', {{error: error.message}}, false);
                        }}
                    }});
                    
                    // Cleanup tokens
                    document.getElementById('cleanupTokensBtn').addEventListener('click', async () => {{
                        try {{
                            const response = await fetch(getAuthURL('/token/cleanup'), {{
                                method: 'POST',
                                headers: getAuthHeaders()
                            }});
                            const result = await response.json();
                            showResponse('tokenListResponse', result, response.ok);
                        }} catch (error) {{
                            showResponse('tokenListResponse', {{error: error.message}}, false);
                        }}
                    }});
                    
                    // Revoke token
                    document.getElementById('revokeTokenBtn').addEventListener('click', async () => {{
                        const tokenId = document.getElementById('revokeTokenId').value;
                        if (!tokenId) {{
                            showResponse('revokeTokenResponse', {{error: 'Token ID is required'}}, false);
                            return;
                        }}
                        
                        try {{
                            const response = await fetch(getAuthURL(`/token/revoke?token_id=${{encodeURIComponent(tokenId)}}`), {{
                                method: 'DELETE',
                                headers: getAuthHeaders()
                            }});
                            const result = await response.json();
                            showResponse('revokeTokenResponse', result, response.ok);
                            
                            // Refresh token list if revocation was successful
                            if (response.ok) {{
                                document.getElementById('listTokensBtn').click();
                                document.getElementById('revokeTokenId').value = '';
                            }}
                        }} catch (error) {{
                            showResponse('revokeTokenResponse', {{error: error.message}}, false);
                        }}
                    }});
                    
                    // Load token list on page load
                    document.getElementById('listTokensBtn').click();
                </script>
            </body>
            </html>
            """
            
            return HTMLResponse(html_content)
            
        except Exception as e:
            self.logger.error(f"Error in handle_demo_page: {e}")
            error_html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Token Management Error</title>
                <style>body {{ font-family: Arial, sans-serif; margin: 50px; }}</style>
            </head>
            <body>
                <h1>Token Management Error</h1>
                <p>Error loading token management page: {str(e)}</p>
            </body>
            </html>
            """
            return HTMLResponse(error_html, status_code=500)
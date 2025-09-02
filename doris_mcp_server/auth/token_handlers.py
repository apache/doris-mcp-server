#!/usr/bin/env python3
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


class TokenHandlers:
    """Token Authentication HTTP Handlers"""
    
    def __init__(self, security_manager):
        self.security_manager = security_manager
        self.logger = get_logger(__name__)
    
    async def handle_create_token(self, request: Request) -> JSONResponse:
        """Handle token creation request"""
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
                user_id = query_params.get("user_id")
                roles = query_params.get("roles", "").split(",") if query_params.get("roles") else []
                permissions = query_params.get("permissions", "").split(",") if query_params.get("permissions") else []
                security_level_str = query_params.get("security_level", "internal")
                expires_hours_str = query_params.get("expires_hours")
                description = query_params.get("description", "")
                custom_token = query_params.get("custom_token")
            else:
                # POST request with JSON body
                try:
                    body = await request.json()
                except:
                    return JSONResponse({
                        "error": "Invalid JSON body"
                    }, status_code=400)
                
                token_id = body.get("token_id")
                user_id = body.get("user_id")
                roles = body.get("roles", [])
                permissions = body.get("permissions", [])
                security_level_str = body.get("security_level", "internal")
                expires_hours_str = body.get("expires_hours")
                description = body.get("description", "")
                custom_token = body.get("custom_token")
            
            # Validate required fields
            if not token_id or not user_id:
                return JSONResponse({
                    "error": "token_id and user_id are required"
                }, status_code=400)
            
            # Parse security level
            try:
                security_level = SecurityLevel(security_level_str.lower())
            except ValueError:
                security_level = SecurityLevel.INTERNAL
            
            # Parse expires_hours
            expires_hours = None
            if expires_hours_str:
                try:
                    expires_hours = int(expires_hours_str)
                except ValueError:
                    return JSONResponse({
                        "error": "expires_hours must be an integer"
                    }, status_code=400)
            
            # Create token
            try:
                token = await self.security_manager.create_token(
                    token_id=token_id,
                    user_id=user_id,
                    roles=roles,
                    permissions=permissions,
                    security_level=security_level,
                    expires_hours=expires_hours,
                    description=description,
                    custom_token=custom_token
                )
                
                return JSONResponse({
                    "success": True,
                    "token_id": token_id,
                    "user_id": user_id,
                    "token": token,
                    "roles": roles,
                    "permissions": permissions,
                    "security_level": security_level.value,
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
    
    async def handle_demo_page(self, request: Request) -> HTMLResponse:
        """Handle token management demo page"""
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
                                <label for="user_id">User ID (required):</label>
                                <input type="text" id="user_id" name="user_id" placeholder="e.g., john_doe" required>
                            </div>
                            <div class="form-group">
                                <label for="roles">Roles (comma-separated):</label>
                                <input type="text" id="roles" name="roles" placeholder="e.g., data_analyst,viewer">
                            </div>
                            <div class="form-group">
                                <label for="permissions">Permissions (comma-separated):</label>
                                <input type="text" id="permissions" name="permissions" placeholder="e.g., read_data,query_database">
                            </div>
                            <div class="form-group">
                                <label for="security_level">Security Level:</label>
                                <select id="security_level" name="security_level">
                                    <option value="public">Public</option>
                                    <option value="internal" selected>Internal</option>
                                    <option value="confidential">Confidential</option>
                                    <option value="secret">Secret</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="expires_hours">Expires Hours (leave empty for default):</label>
                                <input type="number" id="expires_hours" name="expires_hours" placeholder="e.g., 720 (30 days)">
                            </div>
                            <div class="form-group">
                                <label for="description">Description:</label>
                                <textarea id="description" name="description" placeholder="Token description"></textarea>
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
                    function showResponse(elementId, data, isSuccess = true) {{
                        const element = document.getElementById(elementId);
                        element.innerHTML = '<pre>' + JSON.stringify(data, null, 2) + '</pre>';
                        element.className = 'response ' + (isSuccess ? 'success' : 'error');
                    }}
                    
                    // Create token form
                    document.getElementById('createTokenForm').addEventListener('submit', async (e) => {{
                        e.preventDefault();
                        const formData = new FormData(e.target);
                        const data = Object.fromEntries(formData.entries());
                        
                        // Convert comma-separated values to arrays
                        data.roles = data.roles ? data.roles.split(',').map(r => r.trim()).filter(r => r) : [];
                        data.permissions = data.permissions ? data.permissions.split(',').map(p => p.trim()).filter(p => p) : [];
                        
                        try {{
                            const response = await fetch('/token/create', {{
                                method: 'POST',
                                headers: {{'Content-Type': 'application/json'}},
                                body: JSON.stringify(data)
                            }});
                            const result = await response.json();
                            showResponse('createTokenResponse', result, response.ok);
                        }} catch (error) {{
                            showResponse('createTokenResponse', {{error: error.message}}, false);
                        }}
                    }});
                    
                    // List tokens
                    document.getElementById('listTokensBtn').addEventListener('click', async () => {{
                        try {{
                            const response = await fetch('/token/list');
                            const result = await response.json();
                            showResponse('tokenListResponse', result, response.ok);
                        }} catch (error) {{
                            showResponse('tokenListResponse', {{error: error.message}}, false);
                        }}
                    }});
                    
                    // Cleanup tokens
                    document.getElementById('cleanupTokensBtn').addEventListener('click', async () => {{
                        try {{
                            const response = await fetch('/token/cleanup', {{method: 'POST'}});
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
                            const response = await fetch(`/token/revoke?token_id=${{encodeURIComponent(tokenId)}}`, {{
                                method: 'DELETE'
                            }});
                            const result = await response.json();
                            showResponse('revokeTokenResponse', result, response.ok);
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
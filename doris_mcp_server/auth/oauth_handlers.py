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
OAuth HTTP Handlers
Provides HTTP endpoints for OAuth authentication flow
"""

from typing import Dict, Any
from urllib.parse import parse_qs, urlparse
import json

from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.requests import Request

from ..utils.logger import get_logger

logger = get_logger(__name__)


class OAuthHandlers:
    """OAuth HTTP request handlers"""
    
    def __init__(self, security_manager):
        """Initialize OAuth handlers
        
        Args:
            security_manager: DorisSecurityManager instance
        """
        self.security_manager = security_manager
        logger.info("OAuth handlers initialized")
    
    async def handle_login(self, request: Request) -> JSONResponse:
        """Handle OAuth login initiation
        
        Returns JSON with authorization URL and state
        """
        try:
            # Check if OAuth is enabled
            oauth_info = self.security_manager.get_oauth_provider_info()
            if not oauth_info.get("enabled"):
                return JSONResponse(
                    {"error": "OAuth authentication is not enabled"},
                    status_code=400
                )
            
            # Get authorization URL
            authorization_url, state = self.security_manager.get_oauth_authorization_url()
            
            return JSONResponse({
                "authorization_url": authorization_url,
                "state": state,
                "provider": oauth_info.get("provider"),
                "message": "Navigate to authorization_url to complete OAuth login"
            })
            
        except Exception as e:
            logger.error(f"OAuth login initiation failed: {e}")
            return JSONResponse(
                {"error": f"OAuth login failed: {str(e)}"},
                status_code=500
            )
    
    async def handle_callback(self, request: Request) -> JSONResponse:
        """Handle OAuth callback
        
        Processes the OAuth callback and returns authentication result
        """
        try:
            # Get query parameters
            query_params = dict(request.query_params)
            
            # Check for error in callback
            if "error" in query_params:
                error_description = query_params.get("error_description", "Unknown error")
                logger.warning(f"OAuth callback error: {query_params['error']} - {error_description}")
                return JSONResponse(
                    {
                        "error": query_params["error"],
                        "error_description": error_description,
                        "error_uri": query_params.get("error_uri")
                    },
                    status_code=400
                )
            
            # Extract required parameters
            code = query_params.get("code")
            state = query_params.get("state")
            
            if not code or not state:
                return JSONResponse(
                    {"error": "Missing required parameters: code and state"},
                    status_code=400
                )
            
            # Handle OAuth callback
            auth_context = await self.security_manager.handle_oauth_callback(code, state)
            
            # Return successful authentication response
            return JSONResponse({
                "success": True,
                "user_id": auth_context.user_id,
                "roles": auth_context.roles,
                "permissions": auth_context.permissions,
                "security_level": auth_context.security_level.value,
                "session_id": auth_context.session_id,
                "message": "OAuth authentication successful"
            })
            
        except Exception as e:
            logger.error(f"OAuth callback handling failed: {e}")
            return JSONResponse(
                {"error": f"OAuth callback failed: {str(e)}"},
                status_code=500
            )
    
    async def handle_provider_info(self, request: Request) -> JSONResponse:
        """Handle OAuth provider information request
        
        Returns information about the configured OAuth provider
        """
        try:
            provider_info = self.security_manager.get_oauth_provider_info()
            return JSONResponse(provider_info)
            
        except Exception as e:
            logger.error(f"Failed to get OAuth provider info: {e}")
            return JSONResponse(
                {"error": f"Failed to get provider info: {str(e)}"},
                status_code=500
            )
    
    async def handle_demo_page(self, request: Request) -> HTMLResponse:
        """Handle OAuth demo page
        
        Returns a simple HTML page for testing OAuth flow
        """
        oauth_info = self.security_manager.get_oauth_provider_info()
        if not oauth_info.get("enabled"):
            return HTMLResponse("""
                <html>
                    <head><title>OAuth Demo</title></head>
                    <body>
                        <h1>OAuth Demo</h1>
                        <p style="color: red;">OAuth authentication is not enabled.</p>
                        <p>Please configure OAuth settings in your security configuration.</p>
                    </body>
                </html>
            """)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Doris MCP Server - OAuth Demo</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }}
        .info {{
            background-color: #f0f8ff;
            padding: 15px;
            border-left: 4px solid #0066cc;
            margin: 20px 0;
        }}
        .error {{
            background-color: #ffe6e6;
            padding: 15px;
            border-left: 4px solid #cc0000;
            margin: 20px 0;
        }}
        .success {{
            background-color: #e6ffe6;
            padding: 15px;
            border-left: 4px solid #00cc00;
            margin: 20px 0;
        }}
        button {{
            background-color: #0066cc;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }}
        button:hover {{
            background-color: #0052a3;
        }}
        pre {{
            background-color: #f5f5f5;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <h1>Doris MCP Server - OAuth Demo</h1>
    
    <div class="info">
        <h3>OAuth Configuration</h3>
        <p><strong>Provider:</strong> {oauth_info.get('provider', 'N/A')}</p>
        <p><strong>Client ID:</strong> {oauth_info.get('client_id', 'N/A')}</p>
        <p><strong>Scopes:</strong> {', '.join(oauth_info.get('scopes', []))}</p>
        <p><strong>PKCE Enabled:</strong> {oauth_info.get('pkce_enabled', False)}</p>
    </div>
    
    <div>
        <h3>OAuth Authentication Test</h3>
        <p>Click the button below to start OAuth authentication flow:</p>
        <button onclick="startOAuthFlow()">Start OAuth Login</button>
    </div>
    
    <div id="result" style="margin-top: 20px;"></div>
    
    <div>
        <h3>API Endpoints</h3>
        <ul>
            <li><code>GET /auth/login</code> - Initiate OAuth login</li>
            <li><code>GET /auth/callback</code> - OAuth callback handler</li>
            <li><code>GET /auth/provider</code> - Provider information</li>
        </ul>
    </div>

    <script>
        async function startOAuthFlow() {{
            const resultDiv = document.getElementById('result');
            resultDiv.innerHTML = '<div class="info">Initiating OAuth flow...</div>';
            
            try {{
                const response = await fetch('/auth/login');
                const data = await response.json();
                
                if (response.ok) {{
                    resultDiv.innerHTML = `
                        <div class="success">
                            <h4>OAuth URL Generated Successfully</h4>
                            <p><strong>State:</strong> ${{data.state}}</p>
                            <p><strong>Provider:</strong> ${{data.provider}}</p>
                            <p><a href="${{data.authorization_url}}" target="_blank">Click here to authenticate</a></p>
                            <p><em>Note: After authentication, you will be redirected to the callback URL.</em></p>
                        </div>
                    `;
                    
                    // Automatically redirect to OAuth provider
                    // window.open(data.authorization_url, '_blank');
                }} else {{
                    resultDiv.innerHTML = `
                        <div class="error">
                            <h4>Error</h4>
                            <p>${{data.error}}</p>
                        </div>
                    `;
                }}
            }} catch (error) {{
                resultDiv.innerHTML = `
                    <div class="error">
                        <h4>Network Error</h4>
                        <p>${{error.message}}</p>
                    </div>
                `;
            }}
        }}
        
        // Handle OAuth callback result if present in URL
        window.addEventListener('load', function() {{
            const urlParams = new URLSearchParams(window.location.search);
            if (urlParams.has('code') && urlParams.has('state')) {{
                const resultDiv = document.getElementById('result');
                resultDiv.innerHTML = `
                    <div class="success">
                        <h4>OAuth Callback Received</h4>
                        <p>Code: ${{urlParams.get('code')}}</p>
                        <p>State: ${{urlParams.get('state')}}</p>
                        <p>The authentication was successful!</p>
                    </div>
                `;
            }} else if (urlParams.has('error')) {{
                const resultDiv = document.getElementById('result');
                resultDiv.innerHTML = `
                    <div class="error">
                        <h4>OAuth Error</h4>
                        <p>Error: ${{urlParams.get('error')}}</p>
                        <p>Description: ${{urlParams.get('error_description') || 'No description'}}</p>
                    </div>
                `;
            }}
        }});
    </script>
</body>
</html>
        """
        
        return HTMLResponse(html_content)
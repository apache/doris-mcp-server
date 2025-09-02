#!/bin/bash
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

# Doris MCP Server Start Script (Streamable HTTP Mode)
# Ensures the service runs in Streamable HTTP mode for web-based MCP clients

# Set colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}========== Doris MCP Server Start Script (HTTP Mode) ==========${NC}"

# Check virtual environment
if [ -d ".venv" ]; then
    echo -e "${CYAN}Virtual environment found, activating...${NC}"
    source .venv/bin/activate
elif [ -d "venv" ]; then
    echo -e "${CYAN}Virtual environment found, activating...${NC}"
    source venv/bin/activate
else
    echo -e "${YELLOW}Warning: No virtual environment found${NC}"
fi

# Clean cache files
echo -e "${CYAN}Cleaning cache files...${NC}"
echo -e "${CYAN}Cleaning Python cache files...${NC}"
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo -e "${CYAN}Cleaning temporary files...${NC}"
rm -rf .pytest_cache 2>/dev/null || true
echo -e "${CYAN}Cleaning log files...${NC}"
find ./logs -type f -name "*.log" -delete 2>/dev/null || true

# Create necessary directories
mkdir -p logs
mkdir -p tmp

# Reload environment variables
if [ -f .env ]; then
    echo -e "${CYAN}Loading environment variables from .env file...${NC}"
    set -a  # automatically export all variables
    source .env
    set +a  # stop automatically exporting
else
    echo -e "${YELLOW}Warning: .env file not found${NC}"
fi

# Set HTTP-specific environment variables
export MCP_TRANSPORT_TYPE="http"
export MCP_HOST="${MCP_HOST:-0.0.0.0}"
export MCP_PORT="${MCP_PORT:-3000}"
export WORKERS="${WORKERS:-1}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-*}"
export LOG_LEVEL="${LOG_LEVEL:-info}"
export MCP_ALLOW_CREDENTIALS="${MCP_ALLOW_CREDENTIALS:-false}"

# Add adapter debug support
export MCP_DEBUG_ADAPTER="true"
export PYTHONPATH="$(pwd):$PYTHONPATH"

echo -e "${GREEN}Starting MCP server (Streamable HTTP mode)...${NC}"
echo -e "${YELLOW}Service will run on http://${MCP_HOST}:${MCP_PORT}/mcp${NC}"
echo -e "${YELLOW}Health Check: http://${MCP_HOST}:${MCP_PORT}/health${NC}"
echo -e "${YELLOW}MCP Endpoint: http://${MCP_HOST}:${MCP_PORT}/mcp${NC}"
echo -e "${YELLOW}Local access: http://localhost:${MCP_PORT}/mcp${NC}"
echo -e "${YELLOW}Workers: ${WORKERS}${NC}"
echo -e "${YELLOW}Use Ctrl+C to stop the service${NC}"

# Start the server in HTTP mode (Streamable HTTP)
python -m doris_mcp_server.main --transport http --host ${MCP_HOST} --port ${MCP_PORT} --workers ${WORKERS}

# Check exit status
if [ $? -ne 0 ]; then
    echo -e "${RED}Server exited abnormally! Check logs for more information${NC}"
    exit 1
fi

# Show usage tips
echo -e "${YELLOW}Tip: If the page displays abnormally, please clear your browser cache or use incognito mode${NC}"
echo -e "${YELLOW}Chrome browser clear cache shortcut: Ctrl+Shift+Del (Windows) or Cmd+Shift+Del (Mac)${NC}"
echo -e "${CYAN}For testing HTTP endpoints, you can use:${NC}"
echo -e "${CYAN}  curl -X POST http://localhost:${MCP_PORT}/mcp -H 'Content-Type: application/json' -d '{\"method\":\"tools/list\"}'${NC}" 
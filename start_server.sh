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

# NOTE: Old log files are intentionally NOT deleted on startup so that logs
# from a previous run are preserved. The server's LogCleanupManager handles
# aged logs on its own schedule (see doris_mcp_server/utils/logger.py).

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

# Load sensitive values from Docker/Compose secret files without placing them
# in the Compose model or a tracked environment file. Direct values and *_FILE
# values are mutually exclusive so deployment configuration cannot be
# ambiguous.
load_secret_file() {
    local variable_name="$1"
    local file_variable_name="${variable_name}_FILE"
    local secret_file="${!file_variable_name:-}"
    local direct_value="${!variable_name:-}"
    local secret_value

    if [ -z "${secret_file}" ]; then
        return
    fi
    if [ -n "${direct_value}" ]; then
        echo -e "${RED}Both ${variable_name} and ${file_variable_name} are set${NC}" >&2
        exit 1
    fi
    if [ ! -f "${secret_file}" ] || [ ! -r "${secret_file}" ]; then
        echo -e "${RED}${file_variable_name} is not a readable file${NC}" >&2
        exit 1
    fi

    secret_value="$(<"${secret_file}")"
    if [ -z "${secret_value}" ] || [[ "${secret_value}" == *$'\n'* ]] || [[ "${secret_value}" == *$'\r'* ]]; then
        echo -e "${RED}${file_variable_name} must contain one non-empty line${NC}" >&2
        exit 1
    fi

    printf -v "${variable_name}" '%s' "${secret_value}"
    export "${variable_name}"
    unset "${file_variable_name}"
}

load_secret_file DORIS_PASSWORD
load_secret_file TOKEN_ADMIN

# Set HTTP-specific environment variables
# FIX for Issue #62 Bug 4: Use SERVER_PORT instead of MCP_PORT for consistency with code
export MCP_TRANSPORT_TYPE="http"
export SERVER_HOST="${SERVER_HOST:-${MCP_HOST:-127.0.0.1}}"
# Keep MCP_HOST available for existing .env files while using the server's
# canonical host setting for the actual process.
export MCP_HOST="${SERVER_HOST}"
export SERVER_PORT="${SERVER_PORT:-3000}"  # Changed from MCP_PORT to SERVER_PORT
export WORKERS="${WORKERS:-1}"
# Optional reverse-proxy route prefix, e.g. ROUTE_PREFIX=doris-mcp behind an
# nginx `location /doris-mcp/`. Empty (default) serves from the root path.
export ROUTE_PREFIX="${ROUTE_PREFIX:-}"
export ALLOWED_ORIGINS="${ALLOWED_ORIGINS:-*}"
export LOG_LEVEL="${LOG_LEVEL:-info}"
export MCP_ALLOW_CREDENTIALS="${MCP_ALLOW_CREDENTIALS:-false}"

# Add adapter debug support
export MCP_DEBUG_ADAPTER="true"
export PYTHONPATH="$(pwd):$PYTHONPATH"

# Build the URL path prefix for the echoed endpoints below.
ROUTE_PATH_PREFIX=""
ROUTE_PREFIX_ARGS=()
if [ -n "${ROUTE_PREFIX}" ]; then
    ROUTE_PATH_PREFIX="/${ROUTE_PREFIX#/}"
    ROUTE_PREFIX_ARGS=(--route-prefix "${ROUTE_PREFIX}")
fi

echo -e "${GREEN}Starting MCP server (Streamable HTTP mode)...${NC}"
echo -e "${YELLOW}Service will run on http://${SERVER_HOST}:${SERVER_PORT}${ROUTE_PATH_PREFIX}/mcp${NC}"
echo -e "${YELLOW}Liveness: http://${SERVER_HOST}:${SERVER_PORT}${ROUTE_PATH_PREFIX}/live${NC}"
echo -e "${YELLOW}Readiness: http://${SERVER_HOST}:${SERVER_PORT}${ROUTE_PATH_PREFIX}/ready${NC}"
echo -e "${YELLOW}MCP Endpoint: http://${SERVER_HOST}:${SERVER_PORT}${ROUTE_PATH_PREFIX}/mcp${NC}"
echo -e "${YELLOW}Local access: http://localhost:${SERVER_PORT}${ROUTE_PATH_PREFIX}/mcp${NC}"
echo -e "${YELLOW}Workers: ${WORKERS}${NC}"
if [ -n "${ROUTE_PREFIX}" ]; then
    echo -e "${YELLOW}Route Prefix: /${ROUTE_PREFIX#/}${NC}"
fi
echo -e "${YELLOW}Use Ctrl+C to stop the service${NC}"

# Start the server in HTTP mode (Streamable HTTP)
python -m doris_mcp_server.main --transport http --host "${SERVER_HOST}" --port "${SERVER_PORT}" --workers "${WORKERS}" "${ROUTE_PREFIX_ARGS[@]}"

# Check exit status
if [ $? -ne 0 ]; then
    echo -e "${RED}Server exited abnormally! Check logs for more information${NC}"
    exit 1
fi

# Show usage tips
echo -e "${YELLOW}Tip: If the page displays abnormally, please clear your browser cache or use incognito mode${NC}"
echo -e "${YELLOW}Chrome browser clear cache shortcut: Ctrl+Shift+Del (Windows) or Cmd+Shift+Del (Mac)${NC}"
echo -e "${CYAN}For testing HTTP endpoints, you can use:${NC}"
echo -e "${CYAN}  curl --fail http://127.0.0.1:${SERVER_PORT}${ROUTE_PATH_PREFIX}/live${NC}"
echo -e "${CYAN}  curl --fail http://127.0.0.1:${SERVER_PORT}${ROUTE_PATH_PREFIX}/ready${NC}"

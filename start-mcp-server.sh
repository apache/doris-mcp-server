#!/usr/bin/env bash
# =============================================================================
# start-mcp-server.sh — 一键启动 doris-mcp-server
#
# 所有配置从同目录 mcp-server.toml 读取，无需传参。
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# 优先使用 DORIS_MCP_PYTHON 环境变量，否则用自带的 Python
PYTHON="${DORIS_MCP_PYTHON:-$SCRIPT_DIR/python/bin/python3}"
CONFIG="$SCRIPT_DIR/mcp-server.toml"

if [ ! -x "$PYTHON" ]; then
    echo "ERROR: Python not found at $PYTHON" >&2
    exit 1
fi

if [ ! -f "$CONFIG" ]; then
    echo "ERROR: Config not found at $CONFIG" >&2
    exit 1
fi

cd "$SCRIPT_DIR"
export PYTHONPATH="$SCRIPT_DIR/src"
exec "$PYTHON" -m src.main --config-dir "$SCRIPT_DIR"

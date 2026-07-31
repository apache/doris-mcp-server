#!/usr/bin/env bash
# =============================================================================
# build.sh — doris-mcp-server / doris-mcp-client 构建脚本
#
#   构建：  ./build.sh linux-x64        # Linux x86_64
#          ./build.sh linux-arm64      # Linux ARM64 (信创)
#          ./build.sh macos-x64        # macOS Intel
#          ./build.sh macos-arm64      # macOS Apple Silicon
#          ./build.sh                  # 自动检测当前平台
#
#   每次构建产出一个自包含全量包（server + client + 文档 + Python 运行时）：
#     dist/doris-mcp-server-{version}-{platform}.tar.gz
#
#   清理：  ./build.sh clean
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_NAME="doris-mcp-server"
# VERSION 环境变量优先；否则从 pyproject.toml 解析（版本号单一事实源）
VERSION="${VERSION:-$(grep -m1 '^version' "$SCRIPT_DIR/pyproject.toml" | sed -E 's/^version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/')}"
PYTHON_DIR="$SCRIPT_DIR/python"
REQUIREMENTS="$SCRIPT_DIR/requirements.txt"
DIST_DIR="$SCRIPT_DIR/dist"

# ── Python Standalone 配置 ───────────────────────────────────────────────
PY_STANDALONE_RELEASE="${PY_STANDALONE_RELEASE:-20250115}"
PY_VERSION="${PY_VERSION:-3.10.16}"

# ── 颜色 ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
_info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
_warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── 平台解析 ────────────────────────────────────────────────────────────
# 返回 "标签|下载标识"  e.g. "linux-x64|x86_64-unknown-linux-gnu"
_resolve_platform() {
    case "$1" in
        linux-x64)    echo "linux-x64|x86_64-unknown-linux-gnu" ;;
        linux-arm64)  echo "linux-arm64|aarch64-unknown-linux-gnu" ;;
        macos-x64)    echo "macos-x64|x86_64-apple-darwin" ;;
        macos-arm64)  echo "macos-arm64|aarch64-apple-darwin" ;;
        *) _error "Unknown: '$1'. Valid: linux-x64, linux-arm64, macos-x64, macos-arm64"
           exit 1 ;;
    esac
}

_detect_native() {
    local os arch
    case "$(uname -s)" in
        Linux)  os="linux" ;;
        Darwin) os="macos" ;;
        *) _error "Unsupported OS"; exit 1 ;;
    esac
    case "$(uname -m)" in
        x86_64)        arch="x64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) _error "Unsupported arch"; exit 1 ;;
    esac
    echo "${os}-${arch}"
}

# pip --platform tag for a target label (used for cross-builds)
_pip_platform_tag() {
    case "$1" in
        linux-x64)    echo "manylinux2014_x86_64" ;;
        linux-arm64)  echo "manylinux2014_aarch64" ;;
        macos-x64)    echo "macosx_10_9_x86_64" ;;
        macos-arm64)  echo "macosx_11_0_arm64" ;;
        *) _error "No pip platform tag for '$1'"; exit 1 ;;
    esac
}

# ════════════════════════════════════════════════════════════════════
# _install_deps_cross — 交叉安装依赖（不执行目标平台二进制）
#
# pip --target 只是解压 wheel 到目录，不需要运行目标平台的解释器，
# 因此可以在 macOS 上为 Linux 构建，反之亦然。
# ════════════════════════════════════════════════════════════════════
_install_deps_cross() {
    local platform_label="$1"
    local site_packages="$PYTHON_DIR/lib/python${PY_VERSION%.*}/site-packages"
    local pip_tag
    pip_tag="$(_pip_platform_tag "$platform_label")"

    local host_py=""
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1 &&
           "$candidate" -m pip --version >/dev/null 2>&1; then
            host_py="$candidate"; break
        fi
    done
    if [ -z "$host_py" ]; then
        _error "Cross-build needs a host Python with pip (python3 -m pip)"
        exit 1
    fi

    _info "Cross-installing dependencies for $platform_label (tag: $pip_tag) ..."
    mkdir -p "$site_packages"
    "$host_py" -m pip install --quiet --upgrade \
        --platform "$pip_tag" \
        --python-version "${PY_VERSION%.*}" \
        --only-binary :all: \
        --target "$site_packages" \
        -r "$REQUIREMENTS"
    _info "Dependencies installed into $site_packages"
}

# ════════════════════════════════════════════════════════════════════
# _ensure_python — 确保 python/ 有 Python 3.10 + 全部依赖
#
# 优先使用 DORIS_MCP_SYSTEM_PYTHON 指向的已有 Python（如 conda）
# 然后尝试下载 python-build-standalone
# ════════════════════════════════════════════════════════════════════
_ensure_python() {
    local platform_label="$1"
    local platform="$2"
    local native_label
    native_label="$(_detect_native)"
    local is_cross="false"
    [ "$platform_label" != "$native_label" ] && is_cross="true"

    local stamp="$PYTHON_DIR/.build-platform"

    # Reuse an existing python/ only if it was built for this same target.
    if [ -f "$stamp" ] && [ "$(cat "$stamp" 2>/dev/null)" = "$platform_label" ]; then
        if [ "$is_cross" = "true" ]; then
            _info "Python ready (cross-built for $platform_label)"
            return 0
        fi
        if [ -x "$PYTHON_DIR/bin/python3" ] && "$PYTHON_DIR/bin/python3" --version >/dev/null 2>&1; then
            _info "Python ready: $("$PYTHON_DIR/bin/python3" --version 2>&1)"
            return 0
        fi
    fi
    if [ -d "$PYTHON_DIR" ]; then
        _warn "python/ is stale or for another platform, re-creating..."
        rm -rf "$PYTHON_DIR"
    fi

    if [ "$is_cross" = "true" ]; then
        _info "Cross-build: host=$native_label → target=$platform_label"
    fi

    # ── Fallback 1: use system/conda Python if provided (native builds only) ──
    if [ "$is_cross" = "false" ] && \
       [ -n "${DORIS_MCP_SYSTEM_PYTHON:-}" ] && [ -x "$DORIS_MCP_SYSTEM_PYTHON" ]; then
        _info "Using system Python: $DORIS_MCP_SYSTEM_PYTHON"
        local py_ver
        py_ver=$("$DORIS_MCP_SYSTEM_PYTHON" --version 2>&1)
        _info "Python version: $py_ver"

        # 打包瘦身路径硬编码 lib/python3.10，系统 Python 必须是 3.10.x
        local py_major_minor
        py_major_minor=$("$DORIS_MCP_SYSTEM_PYTHON" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if [ "$py_major_minor" != "3.10" ]; then
            _error "DORIS_MCP_SYSTEM_PYTHON must point to Python 3.10.x (got: $py_ver)"
            _error "The packaging layout hardcodes lib/python3.10; other versions are not supported"
            exit 1
        fi
        
        # Copy real Python files into python/ dir (no symlinks)
        local py_root
        py_root=$(cd $(dirname $(dirname "$DORIS_MCP_SYSTEM_PYTHON")) && pwd)
        _info "Copying Python from $py_root to $PYTHON_DIR ..."
        rm -rf "$PYTHON_DIR"
        mkdir -p "$PYTHON_DIR"
        
        # Copy bin/
        cp -a "$py_root/bin/" "$PYTHON_DIR/bin/"
        # Copy lib/ (excluding heavy test/tkinter/idlelib)
        mkdir -p "$PYTHON_DIR/lib"
        for item in "$py_root/lib/"python* "$py_root/lib/"lib*.so*; do
            [ -e "$item" ] && cp -a "$item" "$PYTHON_DIR/lib/" 2>/dev/null || true
        done
        
        if [ ! -x "$PYTHON_DIR/bin/python3" ]; then
            _error "Failed to setup Python at $PYTHON_DIR/bin/python3"
            exit 1
        fi
        _info "Python $("$PYTHON_DIR/bin/python3" --version) ready"
        
        _info "Installing dependencies ..."
        "$PYTHON_DIR/bin/python3" -m pip install --quiet --upgrade pip 2>/dev/null || true
        "$PYTHON_DIR/bin/python3" -m pip install --quiet -r "$REQUIREMENTS"
        _info "Dependencies installed."
        echo "$platform_label" > "$stamp"
        return 0
    fi

    # ── Fallback 2: download python-build-standalone ──
    local tarball_name="cpython-${PY_VERSION}+${PY_STANDALONE_RELEASE}-${platform}-install_only_stripped.tar.gz"
    local url="https://github.com/astral-sh/python-build-standalone/releases/download/${PY_STANDALONE_RELEASE}/${tarball_name}"

    _info "Downloading Python $PY_VERSION for $platform ..."
    local tmp_dir
    tmp_dir="$(mktemp -d)"
    trap "rm -rf $tmp_dir" EXIT

    local tarball="$tmp_dir/$tarball_name"
    if command -v curl > /dev/null 2>&1; then
        curl -fsSL --connect-timeout 30 --max-time 600 -o "$tarball" "$url" || {
            _error "Download failed: $url"
            _error "Tip: set DORIS_MCP_SYSTEM_PYTHON=/path/to/python3.10 to use a local Python"
            exit 1
        }
    elif command -v wget > /dev/null 2>&1; then
        wget -q --timeout=30 --tries=3 -O "$tarball" "$url" || {
            _error "Download failed: $url"
            _error "Tip: set DORIS_MCP_SYSTEM_PYTHON=/path/to/python3.10 to use a local Python"
            exit 1
        }
    else
        _error "Need curl or wget"
        exit 1
    fi

    if [ ! -f "$tarball" ] || [ ! -s "$tarball" ]; then
        _error "Download failed: $url"
        _error "Tip: set DORIS_MCP_SYSTEM_PYTHON=/path/to/python3.10 to use a local Python"
        exit 1
    fi

    _info "Extracting ..."
    rm -rf "$PYTHON_DIR"
    mkdir -p "$PYTHON_DIR"
    tar xzf "$tarball" -C "$PYTHON_DIR" --strip-components=1

    # bin/python3 may be missing (only python3.10 shipped) — link it.
    if [ ! -e "$PYTHON_DIR/bin/python3" ] && [ -e "$PYTHON_DIR/bin/python3.10" ]; then
        ln -sf python3.10 "$PYTHON_DIR/bin/python3"
    fi
    if [ ! -e "$PYTHON_DIR/bin/python3" ]; then
        _error "Python binary not found in extracted tarball"; exit 1
    fi

    if [ "$is_cross" = "true" ]; then
        # Target binaries can't run here — install wheels by extraction only.
        _install_deps_cross "$platform_label"
    else
        _info "Python $("$PYTHON_DIR/bin/python3" --version) ready"
        if ! "$PYTHON_DIR/bin/python3" -m pip --version >/dev/null 2>&1; then
            "$PYTHON_DIR/bin/python3" -m ensurepip --upgrade 2>/dev/null || true
        fi
        _info "Installing dependencies ..."
        "$PYTHON_DIR/bin/python3" -m pip install --quiet --upgrade pip 2>/dev/null || true
        "$PYTHON_DIR/bin/python3" -m pip install --quiet -r "$REQUIREMENTS"
        _info "Dependencies installed."
    fi

    echo "$platform_label" > "$stamp"
}

# ═════════════════════════════════════════════════════════════════════════
# _pack — 打包单个目标
# ═════════════════════════════════════════════════════════════════════════
#
# 用法: _pack <包名> <平台> <相对 SCRIPT_DIR 的路径...>
#
# 通过 staging 目录打包，使解压后的顶层目录名 == 包名（如 doris-mcp-server/），
# 与部署脚本的 ${WORK_DIR}/${name} 约定一致。
_pack() {
    local name="$1"         # doris-mcp-server
    local platform="$2"
    shift 2                 # 剩下的参数是相对 SCRIPT_DIR 的路径
    local pkg_name="${name}-${VERSION}-${platform}"
    local outfile="$DIST_DIR/${pkg_name}.tar.gz"

    _info "Packing: ${pkg_name}.tar.gz"

    local stage="$DIST_DIR/.stage"
    local root="$stage/$name"
    rm -rf "$stage"
    mkdir -p "$root"

    # python/ 是所有包的公共部分
    cp -a "$PYTHON_DIR" "$root/python"
    for item in "$@"; do
        cp -a "$SCRIPT_DIR/$item" "$root/"
    done

    # 瘦身：移除不需要随包分发的内容
    rm -rf "$root/python/include" "$root/python/share" \
           "$root/python/lib/python3.10/test" \
           "$root/python/lib/python3.10/idlelib" \
           "$root/python/lib/python3.10/turtledemo" \
           "$root/python/lib/python3.10/tkinter" \
           "$root/python/lib/python3.10/ensurepip" \
           "$root/python/.build-platform"
    find "$root" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    find "$root" \( -name '*.pyc' -o -name '*.pyo' -o -name '.DS_Store' \) -delete 2>/dev/null || true

    ( cd "$stage" && tar czf "$outfile" "$name" )
    rm -rf "$stage"

    local size
    size="$(du -sh "$outfile" | cut -f1)"
    echo "        ${pkg_name}.tar.gz  (${size})  →  解压为 ${name}/"
}

# ═════════════════════════════════════════════════════════════════════════
# build — 构建单个全量包（server + client + 文档 + Python 运行时）
#
# 顶层目录名保持 doris-mcp-server/，与现有部署脚本的
# ${WORK_DIR}/doris-mcp-server 约定一致，部署脚本无需改动。
# ═════════════════════════════════════════════════════════════════════════
build() {
    local platform_label="${1%%|*}"
    local platform_url="${1##*|}"

    _ensure_python "$platform_label" "$platform_url"

    rm -rf "$DIST_DIR"
    mkdir -p "$DIST_DIR"

    _pack "doris-mcp-server" "$platform_label" \
        src \
        mcp-server.toml \
        start-mcp-server.sh \
        mcp-client \
        mcp-client.sh \
        README.md \
        INSTALL.html \
        doris-mcp-docs.html

    echo ""
    echo "  ────────────────────────────────────────────"
    echo "  Build complete!  Platform: $platform_label"
    echo ""
    echo "  tar xzf doris-mcp-server-${VERSION}-${platform_label}.tar.gz"
    echo "  cd doris-mcp-server"
    echo ""
    echo "    Server:  ./start-mcp-server.sh"
    echo "    Client:  ./mcp-client.sh ..."
    echo "    Docs:    README.md, INSTALL.html, doris-mcp-docs.html"
    echo ""
    echo "  No network, no pip, no system Python needed."
    echo "  ────────────────────────────────────────────"
}

# ═════════════════════════════════════════════════════════════════════════
# clean
# ═════════════════════════════════════════════════════════════════════════
do_clean() {
    rm -rf "$DIST_DIR" "$SCRIPT_DIR/build" "$SCRIPT_DIR"/*.egg-info
    rm -rf "$PYTHON_DIR"
    _info "Cleaned: dist/, python/, build artifacts."
}

# ═════════════════════════════════════════════════════════════════════════
# main
# ═════════════════════════════════════════════════════════════════════════
case "${1:-}" in
    linux-x64|linux-arm64|macos-x64|macos-arm64)
        build "$(_resolve_platform "$1")"
        ;;
    clean)
        do_clean
        ;;
    ""|build)
        _native="$(_detect_native)"
        _info "Auto-detected: $_native"
        build "$(_resolve_platform "$_native")"
        ;;
    *)
        echo "Usage: $0 [linux-x64|linux-arm64|macos-x64|macos-arm64|clean]"
        echo ""
        echo "  linux-x64     Linux x86_64"
        echo "  linux-arm64   Linux ARM64"
        echo "  macos-x64     macOS Intel"
        echo "  macos-arm64   macOS Apple Silicon"
        echo "  clean         Remove build artifacts and python/"
        echo ""
        echo "  No argument = auto-detect and build"
        echo ""
        echo "  Produces one all-in-one package in dist/:"
        echo "    doris-mcp-server-{version}-{platform}.tar.gz"
        echo "    (server + client + docs + Python runtime)"
        exit 1
        ;;
esac

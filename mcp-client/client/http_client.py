from __future__ import annotations

import io
import json
import os
import tarfile
from pathlib import Path
from typing import Any

import httpx


def _use_system_proxy() -> bool:
    val = os.environ.get("DORIS_MCP_USE_SYSTEM_PROXY", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _client(**overrides) -> httpx.Client:
    opts = {"timeout": 60}
    opts.update(overrides)
    opts["trust_env"] = _use_system_proxy()
    return httpx.Client(**opts)


def _wrap_httpx(url: str, op: str, func):
    try:
        return func()
    except httpx.InvalidURL as e:
        raise RuntimeError(f"Invalid URL '{url}': {e}") from None
    except httpx.UnsupportedProtocol as e:
        raise RuntimeError(
            f"Invalid URL '{url}': missing 'http://' or 'https://' scheme."
        ) from None
    except httpx.ConnectError as e:
        raise RuntimeError(
            f"Cannot connect to {url} ({op}). "
            "Check that the server is running and reachable."
        ) from None
    except httpx.TimeoutException:
        raise RuntimeError(f"Connection to {url} timed out during {op}.") from None
    except httpx.HTTPError as e:
        raise RuntimeError(f"Network error during {op}: {e}") from None


def semantic_push(server_url: str, token: str, local_path: str, workspace: str = "example") -> dict:
    path = Path(local_path)
    if not path.exists():
        raise FileNotFoundError(f"Path not found: {local_path}")

    files_to_upload: list[tuple[str, bytes]] = []
    if path.is_file():
        if not path.name.endswith((".yml", ".yaml")):
            raise ValueError(f"Not a YAML file: {path.name}")
        files_to_upload.append((path.name, path.read_bytes()))
    else:
        for root, _, filenames in os.walk(path):
            for fn in filenames:
                if not fn.endswith((".yml", ".yaml")):
                    continue
                full = Path(root) / fn
                rel = str(full.relative_to(path))
                files_to_upload.append((rel, full.read_bytes()))

    if not files_to_upload:
        raise ValueError(f"No YAML files found in {local_path}")

    multipart_files = [
        ("files", (rel, content, "application/x-yaml"))
        for rel, content in files_to_upload
    ]

    url = f"{server_url}/mcp/web/semantic/push"

    def _call():
        with _client(timeout=60) as client:
            return client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                files=multipart_files,
                data={"workspace": workspace},
            )

    resp = _wrap_httpx(url, "push", _call)
    if resp.status_code not in (200, 202):
        _raise_for_error(resp)
    return resp.json()


def _make_url_with_workspace(base_url: str, workspace: str) -> str:
    """Append workspace query param to URL if not default."""
    return f"{base_url}?workspace={workspace}"


_MAX_RESPONSE_BYTES = 20 * 1024 * 1024
_MAX_EXTRACTED_BYTES = 10 * 1024 * 1024
_MAX_EXTRACTED_FILE = 1 * 1024 * 1024
_MAX_MEMBER_COUNT = 10000


def semantic_pull(server_url: str, token: str, output_dir: str, workspace: str = "example") -> int:
    url = _make_url_with_workspace(f"{server_url}/mcp/web/semantic/pull", workspace)

    def _call():
        with _client(timeout=60) as client:
            return client.get(url, headers={"Authorization": f"Bearer {token}"})

    resp = _wrap_httpx(url, "pull", _call)
    if resp.status_code != 200:
        _raise_for_error(resp)

    if len(resp.content) > _MAX_RESPONSE_BYTES:
        raise RuntimeError(
            f"Pull response too large ({len(resp.content)} bytes, "
            f"max {_MAX_RESPONSE_BYTES}). Possible compression bomb."
        )

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    import shutil
    import tempfile
    staging = Path(tempfile.mkdtemp(prefix=".doris-mcp-pull-", dir=str(out.parent)))
    try:
        count, total_bytes = _extract_with_limits(resp.content, staging)

        for root, _, filenames in os.walk(staging):
            for fn in filenames:
                src = Path(root) / fn
                rel = src.relative_to(staging)
                dst = out / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(src), str(dst))
        return count
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _extract_with_limits(tar_bytes: bytes, dest: Path) -> tuple[int, int]:
    count = 0
    total_bytes = 0
    buf = io.BytesIO(tar_bytes)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        for member in tar:
            count += 1
            if count > _MAX_MEMBER_COUNT:
                raise RuntimeError(
                    f"Too many entries in archive (>{_MAX_MEMBER_COUNT}). "
                    "Possible header flooding attack."
                )
            if member.isfile():
                if member.size > _MAX_EXTRACTED_FILE:
                    raise RuntimeError(
                        f"File '{member.name}' too large "
                        f"({member.size} bytes, max {_MAX_EXTRACTED_FILE})."
                    )
                total_bytes += member.size
                if total_bytes > _MAX_EXTRACTED_BYTES:
                    raise RuntimeError(
                        f"Archive total size exceeds {_MAX_EXTRACTED_BYTES} bytes "
                        "after extraction. Possible decompression bomb."
                    )
            tar.extract(member, path=str(dest), filter="data")
    file_count = 0
    for _, _, filenames in os.walk(dest):
        file_count += len(filenames)
    return file_count, total_bytes


def semantic_reload(server_url: str, token: str, workspace: str = "example") -> dict:
    url = f"{server_url}/mcp/web/semantic/reload"

    def _call():
        with _client(timeout=30) as client:
            return client.post(url, headers={"Authorization": f"Bearer {token}"}, json={"workspace": workspace})

    resp = _wrap_httpx(url, "reload", _call)
    if resp.status_code != 200:
        _raise_for_error(resp)
    return resp.json()


def semantic_result(server_url: str, token: str, request_id: str) -> dict:
    url = f"{server_url}/mcp/web/semantic/push/{request_id}"

    def _call():
        with _client(timeout=30) as client:
            return client.get(url, headers={"Authorization": f"Bearer {token}"})

    resp = _wrap_httpx(url, "push result query", _call)
    if resp.status_code == 404:
        raise RuntimeError(
            f"No push request found with id '{request_id}'. "
            "It may have been cleaned up, or the id is wrong."
        )
    if resp.status_code != 200:
        _raise_for_error(resp)
    return resp.json()


def semantic_status(server_url: str, token: str, workspace: str = "example") -> dict:
    from client.mcp_client import tool_call
    result = tool_call(server_url, token, "check_service_health", {"detail": True})
    return result


def semantic_list_files(server_url: str, token: str, workspace: str = "example") -> dict:
    url = _make_url_with_workspace(f"{server_url}/mcp/web/semantic/files", workspace)

    def _call():
        with _client(timeout=30) as client:
            return client.get(url, headers={"Authorization": f"Bearer {token}"})

    resp = _wrap_httpx(url, "list files", _call)
    if resp.status_code != 200:
        _raise_for_error(resp)
    return resp.json()


def semantic_get_file(server_url: str, token: str, filename: str, workspace: str = "example") -> dict:
    url = _make_url_with_workspace(f"{server_url}/mcp/web/semantic/files/{filename}", workspace)

    def _call():
        with _client(timeout=30) as client:
            return client.get(url, headers={"Authorization": f"Bearer {token}"})

    resp = _wrap_httpx(url, "get file", _call)
    if resp.status_code == 404:
        return {"data": None}
    if resp.status_code != 200:
        _raise_for_error(resp)
    return resp.json()


def semantic_save_file(server_url: str, token: str, filename: str, content: str, workspace: str = "example") -> dict:
    url = f"{server_url}/mcp/web/semantic/files"

    def _call():
        with _client(timeout=30) as client:
            return client.post(
                url,
                headers={"Authorization": f"Bearer {token}"},
                json={"filename": filename, "content": content, "workspace": workspace},
            )

    resp = _wrap_httpx(url, "save file", _call)
    if resp.status_code != 200:
        _raise_for_error(resp)
    return resp.json()


def semantic_delete_file(server_url: str, token: str, filename: str, workspace: str = "example") -> dict:
    url = _make_url_with_workspace(f"{server_url}/mcp/web/semantic/files/{filename}", workspace)

    def _call():
        with _client(timeout=30) as client:
            return client.delete(url, headers={"Authorization": f"Bearer {token}"})

    resp = _wrap_httpx(url, "delete file", _call)
    if resp.status_code == 404:
        raise RuntimeError(f"File not found: {filename}")
    if resp.status_code != 200:
        _raise_for_error(resp)
    return resp.json()


import re

_TOKEN_PATTERNS = [
    re.compile(r"Bearer\s+\S+", re.IGNORECASE),
    re.compile(r"sk-[\w\-]+"),
    re.compile(r"[A-Za-z0-9_\-]{30,}"),
]


def _mask_secrets(text: str) -> str:
    for pat in _TOKEN_PATTERNS:
        text = pat.sub("***REDACTED***", text)
    return text


def _is_debug() -> bool:
    val = os.environ.get("DORIS_MCP_DEBUG", "").strip().lower()
    return val in ("1", "true", "yes", "on")


def _raise_for_error(resp: httpx.Response) -> None:
    msg = None
    try:
        body = resp.json()
        if isinstance(body, dict):
            err = body.get("error", {})
            if isinstance(err, dict):
                msg = err.get("message")
            elif isinstance(err, str):
                msg = err
    except (ValueError, TypeError):
        pass

    if msg:
        base = f"Server error (HTTP {resp.status_code}): {msg}"
    else:
        base = f"Server error (HTTP {resp.status_code})"

    if _is_debug():
        preview = resp.text[:2000]
        base += f"\n--- response body (debug, masked) ---\n{_mask_secrets(preview)}"

    raise RuntimeError(base)

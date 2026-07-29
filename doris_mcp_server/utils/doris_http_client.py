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
"""Bounded HTTP access to explicitly configured Doris FE and BE nodes."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlencode, urlunsplit

import aiohttp

DEFAULT_CONNECT_TIMEOUT_SECONDS = 3.0
DEFAULT_READ_TIMEOUT_SECONDS = 15.0
DEFAULT_TOTAL_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_TIMEOUT_SECONDS = 60.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_METADATA_HOSTS = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
    }
)
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)


class DorisHTTPError(RuntimeError):
    """Base error for a Doris HTTP request."""


class DorisHTTPPolicyError(DorisHTTPError):
    """The requested endpoint violates the configured SSRF boundary."""


class DorisHTTPResponseTooLarge(DorisHTTPError):
    """The Doris HTTP response exceeded the configured byte limit."""


class DorisHTTPRequestError(DorisHTTPError):
    """The configured Doris HTTP endpoint could not be reached."""


@dataclass(frozen=True)
class DorisHTTPResponse:
    """A bounded in-memory Doris HTTP response."""

    status: int
    headers: Mapping[str, str]
    body: bytes
    url: str

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    """Resolve one configured hostname only to preflighted addresses."""

    def __init__(self, hostname: str, addresses: tuple[str, ...]):
        self.hostname = hostname
        self.addresses = addresses

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[aiohttp.abc.ResolveResult]:
        if _normalize_host(host) != self.hostname:
            raise OSError("Unexpected Doris HTTP hostname")
        results: list[aiohttp.abc.ResolveResult] = []
        for address in self.addresses:
            parsed = ipaddress.ip_address(address)
            address_family = socket.AF_INET6 if parsed.version == 6 else socket.AF_INET
            if family not in {socket.AF_UNSPEC, address_family}:
                continue
            results.append(
                {
                    "hostname": host,
                    "host": address,
                    "port": port,
                    "family": address_family,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not results:
            raise OSError("No validated Doris HTTP address")
        return results

    async def close(self) -> None:
        return None


def _normalize_host(host: Any) -> str:
    if not isinstance(host, str):
        raise DorisHTTPPolicyError("Doris HTTP host must be a string")
    normalized = host.strip()
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    normalized = normalized.rstrip(".")
    if (
        not normalized
        or "://" in normalized
        or any(character in normalized for character in "/\\?#@%")
    ):
        raise DorisHTTPPolicyError("Doris HTTP host is malformed")
    try:
        return normalized.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise DorisHTTPPolicyError("Doris HTTP host is malformed") from exc


def _validate_port(port: Any) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not (1 <= port <= 65535):
        raise DorisHTTPPolicyError("Doris HTTP port must be between 1 and 65535")
    return int(port)


def _address_allowed(address: str) -> bool:
    parsed = ipaddress.ip_address(address)
    candidates = (parsed, getattr(parsed, "ipv4_mapped", None))
    return not any(
        candidate is not None
        and (
            candidate in _METADATA_ADDRESSES
            or candidate.is_link_local
            or candidate.is_multicast
            or candidate.is_unspecified
            or (candidate.is_reserved and not candidate.is_loopback)
        )
        for candidate in candidates
    )


def _bounded_float(value: Any, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return min(parsed, MAX_TIMEOUT_SECONDS)


def _bounded_response_limit(value: Any) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return DEFAULT_MAX_RESPONSE_BYTES
    if parsed <= 0:
        return DEFAULT_MAX_RESPONSE_BYTES
    return min(parsed, MAX_RESPONSE_BYTES)


class DorisHTTPClient:
    """Fetch only configured Doris HTTP endpoints with SSRF controls."""

    def __init__(
        self,
        *,
        user: str,
        password: str,
        allowed_endpoints: Mapping[str, set[tuple[str, int]]],
        connect_timeout_seconds: float = DEFAULT_CONNECT_TIMEOUT_SECONDS,
        read_timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
        total_timeout_seconds: float = DEFAULT_TOTAL_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ):
        self.user = user
        self.password = password
        self.allowed_endpoints = {
            role: {
                (_normalize_host(host), _validate_port(port))
                for host, port in endpoints
            }
            for role, endpoints in allowed_endpoints.items()
        }
        self.connect_timeout_seconds = _bounded_float(
            connect_timeout_seconds,
            DEFAULT_CONNECT_TIMEOUT_SECONDS,
        )
        self.read_timeout_seconds = _bounded_float(
            read_timeout_seconds,
            DEFAULT_READ_TIMEOUT_SECONDS,
        )
        self.total_timeout_seconds = _bounded_float(
            total_timeout_seconds,
            DEFAULT_TOTAL_TIMEOUT_SECONDS,
        )
        self.max_response_bytes = _bounded_response_limit(max_response_bytes)

    @classmethod
    def from_database_config(cls, database_config: Any) -> DorisHTTPClient:
        fe_host = _normalize_host(
            getattr(database_config, "fe_http_host", "") or database_config.host
        )
        fe_port = _validate_port(database_config.fe_http_port)
        be_port = _validate_port(getattr(database_config, "be_webserver_port", 8040))
        be_hosts = getattr(database_config, "be_hosts", []) or []
        if not isinstance(be_hosts, list) or any(
            not isinstance(host, str) for host in be_hosts
        ):
            raise DorisHTTPPolicyError("Configured Doris BE hosts are invalid")
        return cls(
            user=str(database_config.user),
            password=str(database_config.password),
            allowed_endpoints={
                "fe": {(fe_host, fe_port)},
                "be": {(_normalize_host(host), be_port) for host in be_hosts},
            },
            connect_timeout_seconds=getattr(
                database_config,
                "http_connect_timeout_seconds",
                DEFAULT_CONNECT_TIMEOUT_SECONDS,
            ),
            read_timeout_seconds=getattr(
                database_config,
                "http_read_timeout_seconds",
                DEFAULT_READ_TIMEOUT_SECONDS,
            ),
            total_timeout_seconds=getattr(
                database_config,
                "http_total_timeout_seconds",
                DEFAULT_TOTAL_TIMEOUT_SECONDS,
            ),
            max_response_bytes=getattr(
                database_config,
                "http_max_response_bytes",
                DEFAULT_MAX_RESPONSE_BYTES,
            ),
        )

    async def get(
        self,
        *,
        role: Literal["fe", "be"],
        host: str,
        port: int,
        path: str,
        params: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> DorisHTTPResponse:
        normalized_host = _normalize_host(host)
        validated_port = _validate_port(port)
        if (normalized_host, validated_port) not in self.allowed_endpoints.get(
            role,
            set(),
        ):
            raise DorisHTTPPolicyError(
                "Doris HTTP request is not an explicitly configured endpoint"
            )
        if normalized_host in _METADATA_HOSTS:
            raise DorisHTTPPolicyError(
                "Doris HTTP endpoint is prohibited by SSRF policy"
            )
        if (
            not isinstance(path, str)
            or not path.startswith("/")
            or path.startswith("//")
            or any(character in path for character in "\\?#\r\n")
        ):
            raise DorisHTTPPolicyError("Doris HTTP path is malformed")

        addresses = await self._resolve_addresses(normalized_host, validated_port)
        resolver = _PinnedResolver(normalized_host, addresses)
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            use_dns_cache=False,
            ttl_dns_cache=0,
            force_close=True,
            limit=1,
        )
        timeout = aiohttp.ClientTimeout(
            total=self.total_timeout_seconds,
            connect=self.connect_timeout_seconds,
            sock_connect=self.connect_timeout_seconds,
            sock_read=self.read_timeout_seconds,
        )
        host_for_url = (
            f"[{normalized_host}]" if ":" in normalized_host else normalized_host
        )
        query = urlencode(params or {}, doseq=False)
        url = urlunsplit(("http", f"{host_for_url}:{validated_port}", path, query, ""))
        auth = aiohttp.BasicAuth(self.user, self.password)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                raise_for_status=False,
                trust_env=False,
            ) as session:
                async with session.get(
                    url,
                    auth=auth,
                    allow_redirects=False,
                    headers=dict(headers or {}),
                ) as response:
                    body = await self._read_bounded_body(response)
                    return DorisHTTPResponse(
                        status=response.status,
                        headers=dict(response.headers),
                        body=body,
                        url=str(response.url),
                    )
        except DorisHTTPError:
            raise
        except TimeoutError as exc:
            raise DorisHTTPRequestError("Doris HTTP request timed out") from exc
        except (aiohttp.ClientError, OSError) as exc:
            raise DorisHTTPRequestError("Doris HTTP request failed") from exc

    async def _resolve_addresses(self, host: str, port: int) -> tuple[str, ...]:
        addresses: tuple[str, ...]
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            addresses = (str(literal),)
        else:
            loop = asyncio.get_running_loop()
            try:
                results = await asyncio.wait_for(
                    loop.getaddrinfo(
                        host,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=self.connect_timeout_seconds,
                )
            except (OSError, TimeoutError) as exc:
                raise DorisHTTPRequestError(
                    "Doris HTTP hostname resolution failed"
                ) from exc
            addresses = tuple(
                dict.fromkeys(result[4][0].split("%", 1)[0] for result in results)
            )
        if not addresses or any(not _address_allowed(address) for address in addresses):
            raise DorisHTTPPolicyError(
                "Doris HTTP endpoint resolves to a prohibited address"
            )
        return addresses

    async def _read_bounded_body(
        self,
        response: aiohttp.ClientResponse,
    ) -> bytes:
        content_length = response.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > self.max_response_bytes:
                    raise DorisHTTPResponseTooLarge(
                        "Doris HTTP response exceeds the configured byte limit"
                    )
            except ValueError as exc:
                raise DorisHTTPRequestError(
                    "Doris HTTP response has an invalid Content-Length"
                ) from exc
        body = bytearray()
        async for chunk in response.content.iter_chunked(64 * 1024):
            body.extend(chunk)
            if len(body) > self.max_response_bytes:
                raise DorisHTTPResponseTooLarge(
                    "Doris HTTP response exceeds the configured byte limit"
                )
        return bytes(body)

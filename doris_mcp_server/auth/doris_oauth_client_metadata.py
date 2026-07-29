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
"""Secure OAuth Client ID Metadata Document discovery."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import socket
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

import aiohttp

from .doris_oauth_redirects import (
    DorisOAuthRedirectPolicy,
    is_loopback_host,
)
from .doris_oauth_scope_policy import DorisOAuthScopePolicy
from .doris_oauth_types import PUBLIC_CLIENT_AUTH_METHOD, TokenEndpointError

FetchDocument = Callable[
    [str],
    Awaitable[tuple[dict[str, Any], Mapping[str, str]]],
]

_CACHE_MAX_AGE = re.compile(r"(?:^|,)\s*max-age\s*=\s*\"?(\d+)\"?", re.I)
_PRIVATE_JWK_PARAMETERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})


class ClientMetadataError(ValueError):
    """A Client ID Metadata Document is unavailable or invalid."""


@dataclass(frozen=True)
class ResolvedClientMetadata:
    """Validated client properties used by the authorization server."""

    client_id: str
    client_name: str
    application_type: str
    redirect_uris: tuple[str, ...]
    client_allowed_scopes: tuple[str, ...]
    token_endpoint_auth_method: str = PUBLIC_CLIENT_AUTH_METHOD


@dataclass(frozen=True)
class _CacheEntry:
    metadata: ResolvedClientMetadata
    expires_at: float


@dataclass
class _LockEntry:
    lock: asyncio.Lock
    users: int = 0


class _PinnedResolver(aiohttp.abc.AbstractResolver):
    """Resolve one validated hostname only to its preflighted addresses."""

    def __init__(self, hostname: str, addresses: tuple[str, ...]):
        self.hostname = hostname.lower()
        self.addresses = addresses

    async def resolve(
        self,
        host: str,
        port: int = 0,
        family: socket.AddressFamily = socket.AF_INET,
    ) -> list[aiohttp.abc.ResolveResult]:
        if host.lower() != self.hostname:
            raise OSError("Unexpected metadata hostname")
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
            raise OSError("No validated metadata address")
        return results

    async def close(self) -> None:
        return None


def validate_client_identifier_url(client_id: str) -> tuple[str, int]:
    """Validate the normative Client Identifier URL syntax."""

    if not isinstance(client_id, str) or not client_id:
        raise ClientMetadataError("Client Identifier URL is missing")
    if "\\" in client_id:
        raise ClientMetadataError("Client Identifier URL is malformed")
    try:
        parsed = urlsplit(client_id)
        port = parsed.port or 443
    except ValueError as exc:
        raise ClientMetadataError("Client Identifier URL is malformed") from exc
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise ClientMetadataError("Client Identifier URL must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ClientMetadataError("Client Identifier URL must not contain userinfo")
    if not parsed.path:
        raise ClientMetadataError("Client Identifier URL must contain a path")
    if parsed.fragment:
        raise ClientMetadataError("Client Identifier URL must not contain a fragment")
    for segment in parsed.path.split("/"):
        decoded = segment
        for _ in range(3):
            decoded_again = unquote(decoded)
            if decoded_again == decoded:
                break
            decoded = decoded_again
        if decoded in {".", ".."}:
            raise ClientMetadataError(
                "Client Identifier URL must not contain dot path segments"
            )
    return parsed.hostname, port


def metadata_address_allowed(address: str, issuer: str) -> bool:
    """Return whether a resolved metadata address is safe to contact."""

    parsed_address = ipaddress.ip_address(address)
    if parsed_address.is_global:
        return True
    issuer_host = urlsplit(issuer).hostname
    if not issuer_host or not is_loopback_host(issuer_host):
        return False
    return parsed_address.is_loopback


class DorisOAuthClientMetadataResolver:
    """Fetch, validate, and cache Client ID Metadata Documents."""

    def __init__(
        self,
        *,
        issuer: str,
        redirect_policy: DorisOAuthRedirectPolicy,
        scope_policy: DorisOAuthScopePolicy,
        timeout_seconds: int = 5,
        max_document_bytes: int = 5120,
        default_cache_seconds: int = 300,
        max_cache_seconds: int = 3600,
        max_cache_entries: int = 1000,
        fetch_document: FetchDocument | None = None,
    ):
        self.issuer = issuer
        self.redirect_policy = redirect_policy
        self.scope_policy = scope_policy
        self.timeout_seconds = timeout_seconds
        self.max_document_bytes = max_document_bytes
        self.default_cache_seconds = default_cache_seconds
        self.max_cache_seconds = max_cache_seconds
        self.max_cache_entries = max_cache_entries
        self._fetch_document_override = fetch_document
        self._cache: dict[str, _CacheEntry] = {}
        self._locks: dict[str, _LockEntry] = {}

    async def resolve(self, client_id: str) -> ResolvedClientMetadata:
        """Resolve one URL client ID without caching invalid responses."""

        validate_client_identifier_url(client_id)
        cached = self._cache.get(client_id)
        now = time.monotonic()
        if cached and cached.expires_at > now:
            return cached.metadata

        lock_entry = self._locks.get(client_id)
        if lock_entry is None:
            lock_entry = _LockEntry(lock=asyncio.Lock())
            self._locks[client_id] = lock_entry
        lock_entry.users += 1
        try:
            async with lock_entry.lock:
                cached = self._cache.get(client_id)
                now = time.monotonic()
                if cached and cached.expires_at > now:
                    return cached.metadata

                fetcher = self._fetch_document_override or self._fetch_document
                document, headers = await fetcher(client_id)
                metadata = self._validate_document(client_id, document)
                cache_seconds = self._cache_seconds(headers)
                if cache_seconds > 0:
                    self._make_cache_space(client_id)
                    self._cache[client_id] = _CacheEntry(
                        metadata=metadata,
                        expires_at=now + cache_seconds,
                    )
                else:
                    self._cache.pop(client_id, None)
                return metadata
        finally:
            lock_entry.users -= 1
            if lock_entry.users == 0 and self._locks.get(client_id) is lock_entry:
                self._locks.pop(client_id, None)

    async def _fetch_document(
        self,
        client_id: str,
    ) -> tuple[dict[str, Any], Mapping[str, str]]:
        hostname, port = validate_client_identifier_url(client_id)
        addresses = await self._resolve_addresses(hostname, port)
        resolver = _PinnedResolver(hostname, addresses)
        connector = aiohttp.TCPConnector(
            resolver=resolver,
            use_dns_cache=False,
            ttl_dns_cache=0,
        )
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                raise_for_status=False,
            ) as session:
                async with session.get(
                    client_id,
                    allow_redirects=False,
                    headers={"Accept": "application/json"},
                ) as response:
                    if response.status != 200:
                        raise ClientMetadataError(
                            "Client metadata fetch did not return 200"
                        )
                    media_type = (
                        response.headers.get("Content-Type", "")
                        .split(";", 1)[0]
                        .strip()
                        .lower()
                    )
                    if media_type != "application/json" and not (
                        media_type.startswith("application/")
                        and media_type.endswith("+json")
                    ):
                        raise ClientMetadataError(
                            "Client metadata response is not JSON"
                        )
                    length = response.headers.get("Content-Length")
                    if length:
                        try:
                            if int(length) > self.max_document_bytes:
                                raise ClientMetadataError(
                                    "Client metadata document is too large"
                                )
                        except ValueError as exc:
                            raise ClientMetadataError(
                                "Client metadata Content-Length is invalid"
                            ) from exc

                    body = bytearray()
                    async for chunk in response.content.iter_chunked(1024):
                        body.extend(chunk)
                        if len(body) > self.max_document_bytes:
                            raise ClientMetadataError(
                                "Client metadata document is too large"
                            )
                    try:
                        document = json.loads(body.decode("utf-8"))
                    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                        raise ClientMetadataError(
                            "Client metadata document is invalid JSON"
                        ) from exc
                    if not isinstance(document, dict):
                        raise ClientMetadataError(
                            "Client metadata document must be a JSON object"
                        )
                    return document, dict(response.headers)
        except ClientMetadataError:
            raise
        except (aiohttp.ClientError, TimeoutError, OSError) as exc:
            raise ClientMetadataError("Client metadata fetch failed") from exc

    async def _resolve_addresses(
        self,
        hostname: str,
        port: int,
    ) -> tuple[str, ...]:
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        addresses: tuple[str, ...]
        if literal is not None:
            addresses = (str(literal),)
        else:
            loop = asyncio.get_running_loop()
            try:
                results = await asyncio.wait_for(
                    loop.getaddrinfo(
                        hostname,
                        port,
                        family=socket.AF_UNSPEC,
                        type=socket.SOCK_STREAM,
                    ),
                    timeout=self.timeout_seconds,
                )
            except (OSError, TimeoutError) as exc:
                raise ClientMetadataError(
                    "Client metadata hostname resolution failed"
                ) from exc
            addresses = tuple(
                dict.fromkeys(result[4][0].split("%", 1)[0] for result in results)
            )
        if not addresses or any(
            not metadata_address_allowed(address, self.issuer) for address in addresses
        ):
            raise ClientMetadataError(
                "Client metadata hostname resolves to a prohibited address"
            )
        return addresses

    def _validate_document(
        self,
        client_id: str,
        document: dict[str, Any],
    ) -> ResolvedClientMetadata:
        if document.get("client_id") != client_id:
            raise ClientMetadataError(
                "Client metadata client_id does not match its URL"
            )
        client_name = document.get("client_name")
        if (
            not isinstance(client_name, str)
            or not client_name.strip()
            or len(client_name) > 200
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in client_name
            )
        ):
            raise ClientMetadataError("Client metadata client_name is invalid")
        if "client_secret" in document or "client_secret_expires_at" in document:
            raise ClientMetadataError(
                "Client metadata must not contain a shared secret"
            )
        self._reject_private_jwk_material(document.get("jwks"))

        token_auth_method = document.get(
            "token_endpoint_auth_method",
            PUBLIC_CLIENT_AUTH_METHOD,
        )
        if token_auth_method != PUBLIC_CLIENT_AUTH_METHOD:
            raise ClientMetadataError(
                "Unsupported Client ID Metadata token authentication method"
            )
        grant_types = document.get("grant_types", ["authorization_code"])
        if (
            not isinstance(grant_types, list)
            or not grant_types
            or any(
                not isinstance(grant, str)
                or grant not in {"authorization_code", "refresh_token"}
                for grant in grant_types
            )
            or "authorization_code" not in grant_types
            or len(grant_types) != len(set(grant_types))
        ):
            raise ClientMetadataError("Client metadata grant_types are invalid")
        response_types = document.get("response_types", ["code"])
        if response_types != ["code"]:
            raise ClientMetadataError('Client metadata response_types must be ["code"]')

        redirect_uris = document.get("redirect_uris")
        if (
            not isinstance(redirect_uris, list)
            or not redirect_uris
            or any(not isinstance(uri, str) for uri in redirect_uris)
            or len(redirect_uris) != len(set(redirect_uris))
        ):
            raise ClientMetadataError("Client metadata redirect_uris are invalid")
        application_type = document.get("application_type")
        if application_type is None:
            application_type, validated_redirects = self._infer_application_type(
                redirect_uris
            )
        else:
            if application_type not in {"native", "web"}:
                raise ClientMetadataError("Client metadata application_type is invalid")
            validated_redirects = self._validate_redirects(
                redirect_uris,
                application_type,
            )

        requested_scope = document.get("scope")
        if requested_scope is not None and not isinstance(requested_scope, str):
            raise ClientMetadataError("Client metadata scope is invalid")
        try:
            if requested_scope:
                scopes = self.scope_policy.grant_client_scopes(
                    requested_scope,
                    explicit=True,
                )
            else:
                scopes = tuple(sorted(self.scope_policy.server_allowed_scopes))
        except TokenEndpointError as exc:
            raise ClientMetadataError("Client metadata scope is invalid") from exc

        return ResolvedClientMetadata(
            client_id=client_id,
            client_name=client_name.strip(),
            application_type=application_type,
            redirect_uris=validated_redirects,
            client_allowed_scopes=scopes,
            token_endpoint_auth_method=token_auth_method,
        )

    def _infer_application_type(
        self,
        redirect_uris: list[str],
    ) -> tuple[str, tuple[str, ...]]:
        matches: list[tuple[str, tuple[str, ...]]] = []
        for application_type in ("native", "web"):
            try:
                matches.append(
                    (
                        application_type,
                        self._validate_redirects(
                            redirect_uris,
                            application_type,
                        ),
                    )
                )
            except ClientMetadataError:
                continue
        if len(matches) != 1:
            raise ClientMetadataError(
                "Client metadata redirect_uris do not identify one application type"
            )
        return matches[0]

    def _validate_redirects(
        self,
        redirect_uris: list[str],
        application_type: str,
    ) -> tuple[str, ...]:
        try:
            return self.redirect_policy.validate_redirect_uris(
                redirect_uris,
                application_type=application_type,
                source="client_id_metadata",
            )
        except TokenEndpointError as exc:
            raise ClientMetadataError(
                "Client metadata redirect_uris are invalid"
            ) from exc

    def _reject_private_jwk_material(self, jwks: Any) -> None:
        if jwks is None:
            return
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            raise ClientMetadataError("Client metadata jwks is invalid")
        for key in jwks["keys"]:
            if not isinstance(key, dict) or _PRIVATE_JWK_PARAMETERS.intersection(key):
                raise ClientMetadataError(
                    "Client metadata must not contain private key material"
                )

    def _cache_seconds(self, headers: Mapping[str, str]) -> int:
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        cache_control = normalized.get("cache-control", "")
        directives = {
            directive.strip().lower()
            for directive in cache_control.split(",")
            if directive.strip()
        }
        if "no-store" in directives or "no-cache" in directives:
            return 0
        match = _CACHE_MAX_AGE.search(cache_control)
        if match:
            max_age = int(match.group(1))
            try:
                age = max(0, int(normalized.get("age", "0")))
            except ValueError:
                age = 0
            return min(max(0, max_age - age), self.max_cache_seconds)
        return min(self.default_cache_seconds, self.max_cache_seconds)

    def _make_cache_space(self, client_id: str) -> None:
        now = time.monotonic()
        self._cache = {
            key: entry for key, entry in self._cache.items() if entry.expires_at > now
        }
        if client_id in self._cache or len(self._cache) < self.max_cache_entries:
            return
        oldest = min(
            self._cache,
            key=lambda key: self._cache[key].expires_at,
        )
        self._cache.pop(oldest, None)

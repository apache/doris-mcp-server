#!/usr/bin/env python3
"""Redirect URI policy for Doris-backed OAuth."""

from urllib.parse import urlparse

from .doris_oauth_types import TokenEndpointError


LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def is_loopback_host(hostname: str | None) -> bool:
    return bool(hostname and hostname.lower() in LOOPBACK_HOSTS)


def is_loopback_url(url: str) -> bool:
    parsed = urlparse(url)
    return is_loopback_host(parsed.hostname)


class DorisOAuthRedirectPolicy:
    """Validate and match OAuth redirect URIs."""

    def __init__(self, allow_production_wildcards: bool = False):
        self.allow_production_wildcards = allow_production_wildcards

    def validate_redirect_uri(self, uri: str, *, source: str = "dcr") -> str:
        parsed = urlparse(uri)
        if not parsed.scheme or not parsed.netloc:
            raise TokenEndpointError("invalid_redirect_uri", "Redirect URI must be absolute", status_code=400)
        if parsed.fragment:
            raise TokenEndpointError("invalid_redirect_uri", "Redirect URI must not contain a fragment", status_code=400)
        if parsed.username or parsed.password:
            raise TokenEndpointError("invalid_redirect_uri", "Redirect URI credentials are not allowed", status_code=400)
        if "*" in uri:
            if source == "dcr" or not self.allow_production_wildcards:
                raise TokenEndpointError("invalid_redirect_uri", "Wildcard redirect URI is not allowed", status_code=400)
        if parsed.scheme == "https":
            return uri
        if parsed.scheme == "http" and is_loopback_host(parsed.hostname):
            return uri
        raise TokenEndpointError("invalid_redirect_uri", "Redirect URI must use HTTPS", status_code=400)

    def validate_redirect_uris(self, uris: list[str] | tuple[str, ...], *, source: str = "dcr") -> tuple[str, ...]:
        if not uris:
            raise TokenEndpointError("invalid_redirect_uri", "At least one redirect URI is required", status_code=400)
        return tuple(self.validate_redirect_uri(str(uri), source=source) for uri in uris)

    def choose_redirect_uri(self, registered_uris: tuple[str, ...], requested_uri: str | None) -> str:
        if requested_uri:
            if requested_uri not in registered_uris:
                raise TokenEndpointError("invalid_redirect_uri", "Redirect URI is not registered", status_code=400)
            return requested_uri
        if len(registered_uris) == 1:
            return registered_uris[0]
        raise TokenEndpointError("invalid_request", "redirect_uri is required", status_code=400)

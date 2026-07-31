"""Sensitive data masking for logs and error messages."""

import re

_MASK = "****"

# key=value / key: value forms for common secret keys, with optional quotes so
# JSON forms like "password": "value" are covered as well.
_PASSWORD_PATTERNS = [
    re.compile(
        r"([\"']?(?:password|passwd|pwd|secret|token)[\"']?\s*[=:]\s*[\"']?)([^\s,;'\"}]+)",
        re.IGNORECASE,
    ),
]

# Authorization header (any scheme) and standalone Bearer tokens.
_HEADER_PATTERNS = [
    re.compile(r"(authorization[\"']?\s*[=:]\s*[\"']?)([^\r\n\"']+)", re.IGNORECASE),
    re.compile(r"(\bbearer\s+)([a-zA-Z0-9._~+/=-]{6,})", re.IGNORECASE),
]

# Cookie / Set-Cookie headers (header and JSON forms).
_COOKIE_PATTERNS = [
    re.compile(r"(\b(?:set-cookie|cookie)\b[\"']?\s*[=:]\s*[\"']?)([^\r\n\"']+)", re.IGNORECASE),
]

_TOKEN_PATTERN = re.compile(r"(sk-[a-zA-Z0-9_-]+)")


def mask_password(text: str) -> str:
    """Mask password/secret/token values in key=value or JSON key-value text."""
    result = text
    for pattern in _PASSWORD_PATTERNS:
        result = pattern.sub(rf"\g<1>{_MASK}", result)
    return result


def mask_token(text: str) -> str:
    """Mask MCP tokens in text."""
    return _TOKEN_PATTERN.sub(_MASK, text)


def mask_sensitive(text: str) -> str:
    """Mask all sensitive data (passwords, tokens, auth headers, cookies)."""
    result = text
    for pattern in _HEADER_PATTERNS + _COOKIE_PATTERNS:
        result = pattern.sub(rf"\g<1>{_MASK}", result)
    return mask_token(mask_password(result))


def mask_dict(d: dict, sensitive_keys: set[str] | None = None) -> dict:
    """Mask sensitive values in a dictionary (recursive)."""
    if sensitive_keys is None:
        sensitive_keys = {"password", "passwd", "pwd", "token", "secret", "authorization", "cookie", "set-cookie"}
    result = {}
    for k, v in d.items():
        if k.lower() in sensitive_keys:
            result[k] = _MASK
        elif isinstance(v, dict):
            result[k] = mask_dict(v, sensitive_keys)
        elif isinstance(v, list):
            result[k] = _mask_list(v, sensitive_keys)
        elif isinstance(v, str):
            result[k] = mask_sensitive(v)
        else:
            result[k] = v
    return result


def _mask_list(lst: list, sensitive_keys: set[str]) -> list:
    """Recursively mask sensitive values in a list."""
    result = []
    for item in lst:
        if isinstance(item, dict):
            result.append(mask_dict(item, sensitive_keys))
        elif isinstance(item, list):
            result.append(_mask_list(item, sensitive_keys))
        elif isinstance(item, str):
            result.append(mask_sensitive(item))
        else:
            result.append(item)
    return result

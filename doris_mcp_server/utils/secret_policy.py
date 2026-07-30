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
"""Shared policy for operator-provided authentication secrets."""

import hashlib

MIN_SECRET_LENGTH = 32
MIN_DISTINCT_CHARACTERS = 10
TOKEN_DIGEST_ALGORITHMS = {
    "sha256": 64,
    "sha512": 128,
}

_INSECURE_MARKERS = (
    "123456",
    "changeme",
    "defaultsecret",
    "exampletoken",
    "password",
    "yoursecret",
    "yoursecure",
)

_RESERVED_TOKEN_ENV_NAMES = frozenset(
    {
        "TOKEN_EXPIRY",
        "TOKEN_EXPIRY_HOURS",
        "TOKEN_FILE_PATH",
        "TOKEN_HASH_ALGORITHM",
        "TOKEN_HOT_RELOAD",
        "TOKEN_DB_VALIDATION_TTL_SECONDS",
        "TOKEN_SECRET",
    }
)

_RESERVED_TOKEN_ENV_PREFIXES = (
    "TOKEN_HASH_",
    "TOKEN_MANAGEMENT_",
)


def validate_high_entropy_secret(value: str, *, setting: str) -> str:
    """Reject missing, short, repetitive, or placeholder authentication secrets."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{setting} is required")
    if value != value.strip():
        raise ValueError(f"{setting} must not contain leading or trailing whitespace")
    if len(value) < MIN_SECRET_LENGTH:
        raise ValueError(
            f"{setting} must be at least {MIN_SECRET_LENGTH} characters; "
            "generate it with a cryptographically secure random generator"
        )
    if value.startswith("<") or value.endswith(">"):
        raise ValueError(f"{setting} must not be a placeholder")
    compact = "".join(
        character for character in value.casefold() if character.isalnum()
    )
    if any(marker in compact for marker in _INSECURE_MARKERS):
        raise ValueError(
            f"{setting} must not contain a known weak or placeholder value"
        )
    if len(set(value)) < MIN_DISTINCT_CHARACTERS:
        raise ValueError(
            f"{setting} must contain at least {MIN_DISTINCT_CHARACTERS} distinct characters"
        )
    return value


def normalize_token_hash_algorithm(
    value: str,
    *,
    setting: str = "TOKEN_HASH_ALGORITHM",
) -> str:
    """Return a supported token digest algorithm name."""
    algorithm = str(value or "").strip().lower()
    if algorithm not in TOKEN_DIGEST_ALGORITHMS:
        supported = ", ".join(sorted(TOKEN_DIGEST_ALGORITHMS))
        raise ValueError(f"{setting} must be one of: {supported}")
    return algorithm


def build_token_digest(value: str, algorithm: str) -> str:
    """Build a self-describing digest for a high-entropy bearer token."""
    normalized_algorithm = normalize_token_hash_algorithm(algorithm)
    digest = hashlib.new(normalized_algorithm, value.encode("utf-8")).hexdigest()
    return f"{normalized_algorithm}:{digest}"


def normalize_token_digest(value: str, *, setting: str) -> str:
    """Validate and normalize a persisted self-describing token digest."""
    if not isinstance(value, str) or not value:
        raise ValueError(f"{setting} is required")
    if value != value.strip():
        raise ValueError(f"{setting} must not contain leading or trailing whitespace")

    algorithm, separator, digest = value.partition(":")
    algorithm = normalize_token_hash_algorithm(
        algorithm,
        setting=f"{setting} algorithm",
    )
    expected_length = TOKEN_DIGEST_ALGORITHMS[algorithm]
    if (
        separator != ":"
        or len(digest) != expected_length
        or any(character not in "0123456789abcdefABCDEF" for character in digest)
    ):
        raise ValueError(
            f"{setting} must use {algorithm}: followed by "
            f"{expected_length} hexadecimal characters"
        )
    return f"{algorithm}:{digest.lower()}"


def is_static_token_environment_variable(name: str) -> bool:
    """Return whether an environment variable defines a static bearer token."""
    if not name.startswith("TOKEN_"):
        return False
    if name in _RESERVED_TOKEN_ENV_NAMES:
        return False
    if name.startswith(_RESERVED_TOKEN_ENV_PREFIXES):
        return False
    return not name.endswith(("_DESCRIPTION", "_EXPIRES_HOURS"))

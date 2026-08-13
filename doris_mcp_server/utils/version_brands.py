# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""Canonical validation for Doris version-comment brand aliases.

Both configuration validation and the runtime brand registry share this
normalization contract so an alias accepted by one is accepted by the
other.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

DEFAULT_VERSION_BRAND = "doris"
BRAND_TOKEN_PATTERN = re.compile(r"^[a-z][a-z0-9]*$")
RESERVED_BRAND_TOKENS = frozenset({"apache", "version"})


def normalize_version_brand_aliases(aliases: Iterable[object]) -> tuple[str, ...]:
    """Normalize and validate configured version-comment brand aliases.

    Each alias must be a string holding a single lowercase alphanumeric
    word. Reserved tokens (``apache``, ``version``) are rejected. Empty
    entries are ignored and duplicates collapse while preserving order.

    Raises:
        TypeError: if an entry is not a string.
        ValueError: if an entry is not a valid brand token.
    """
    normalized: list[str] = []
    for alias in aliases:
        if not isinstance(alias, str):
            raise TypeError(
                "Doris version brand aliases must be strings, "
                f"got: {alias!r}"
            )
        token = " ".join(alias.casefold().split())
        if not token:
            continue
        if (
            BRAND_TOKEN_PATTERN.fullmatch(token) is None
            or token in RESERVED_BRAND_TOKENS
        ):
            raise ValueError(f"Invalid Doris version brand alias: {alias!r}")
        normalized.append(token)
    return tuple(dict.fromkeys(normalized))

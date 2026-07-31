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

"""Fail-closed Apache Doris version probing, parsing, and comparison."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from ..utils.db import DorisConnection

DORIS_VERSION_COMMENT_QUERY = "SELECT @@version_comment;"
_VERSION_COMMENT_COLUMN = "@@version_comment"
_VERSION_COMMENT_MAX_BYTES = 4096

_VERSION_PATTERN = re.compile(
    r"""
    (?<![A-Za-z0-9_])
    (?:apache\s+)?doris
    (?:\s*,?\s*version)?
    (?:\s+doris-|\s*-\s*|\s+)
    (?P<core>\d+\.\d+\.\d+)
    (?:-(?P<prerelease>rc\d+|alpha\d*|beta\d*))?
    (?:-(?P<commit>[0-9a-f]{7,40}))?
    (?=\s|\(|,|$)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_DEPLOYMENT_PATTERNS = (
    ("cloud", re.compile(r"\bcloud\s+mode\b", re.IGNORECASE)),
    ("shared_data", re.compile(r"\bshared[-\s]+data\b", re.IGNORECASE)),
    ("shared_nothing", re.compile(r"\bshared[-\s]+nothing\b", re.IGNORECASE)),
)


class DorisVersionParseStatus(StrEnum):
    PARSED = "parsed"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DorisVersion:
    raw: str
    major: int | None = None
    minor: int | None = None
    patch: int | None = None
    prerelease: str | None = None
    commit: str | None = None
    deployment_hint: str | None = None
    parse_status: DorisVersionParseStatus = DorisVersionParseStatus.UNKNOWN

    @property
    def is_parsed(self) -> bool:
        return self.parse_status is DorisVersionParseStatus.PARSED

    @property
    def core(self) -> str | None:
        if (
            not self.is_parsed
            or self.major is None
            or self.minor is None
            or self.patch is None
        ):
            return None
        return f"{self.major}.{self.minor}.{self.patch}"

    @property
    def normalized(self) -> str | None:
        """Return the three-part version used for every capability decision."""
        return self.core

    def compare(self, other: DorisVersion) -> int:
        left = self._comparison_key()
        right = other._comparison_key()
        return (left > right) - (left < right)

    def is_at_least(self, other: DorisVersion) -> bool:
        return self.compare(other) >= 0

    def _comparison_key(self) -> tuple[int, int, int]:
        if (
            not self.is_parsed
            or self.major is None
            or self.minor is None
            or self.patch is None
        ):
            raise ValueError("Cannot compare an unparsed Doris version")

        return (self.major, self.minor, self.patch)


def parse_doris_version_comment(comment: str) -> DorisVersion:
    deployment_hint = _detect_deployment_hint(comment)
    match = _VERSION_PATTERN.search(comment)
    if match is None:
        return DorisVersion(raw=comment, deployment_hint=deployment_hint)

    major, minor, patch = (int(part) for part in match.group("core").split("."))
    prerelease = match.group("prerelease")
    commit = match.group("commit")

    return DorisVersion(
        raw=comment,
        major=major,
        minor=minor,
        patch=patch,
        prerelease=prerelease.lower() if prerelease else None,
        commit=commit.lower() if commit else None,
        deployment_hint=deployment_hint,
        parse_status=DorisVersionParseStatus.PARSED,
    )


def parse_doris_version_rows(
    rows: Sequence[Mapping[str, Any]],
) -> DorisVersion:
    if not rows:
        return DorisVersion(raw="")

    for key, value in rows[0].items():
        if key.strip().casefold() != _VERSION_COMMENT_COLUMN:
            continue
        if isinstance(value, str):
            return parse_doris_version_comment(value)
        return DorisVersion(raw="")

    return DorisVersion(raw="")


async def probe_doris_version(connection: DorisConnection) -> DorisVersion:
    result = await connection.execute(
        DORIS_VERSION_COMMENT_QUERY,
        mask_result=False,
        max_rows=1,
        max_bytes=_VERSION_COMMENT_MAX_BYTES,
    )
    return parse_doris_version_rows(result.data)


def _detect_deployment_hint(comment: str) -> str | None:
    for name, pattern in _DEPLOYMENT_PATTERNS:
        if pattern.search(comment):
            return name
    return None

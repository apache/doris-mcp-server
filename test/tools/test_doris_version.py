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

from collections.abc import Iterator
from unittest.mock import AsyncMock, MagicMock

import pytest

from doris_mcp_server.tools.doris_version import (
    DORIS_VERSION_COMMENT_QUERY,
    DorisVersionParseStatus,
    configure_version_brands,
    known_version_brands,
    parse_doris_version_comment,
    parse_doris_version_rows,
    probe_doris_version,
)
from doris_mcp_server.utils.db import DorisConnection, QueryResult


@pytest.fixture
def enterprise_brand_alias() -> Iterator[str]:
    configure_version_brands(("enterprisedb",))
    try:
        yield "enterprisedb"
    finally:
        configure_version_brands(())


def test_version_probe_uses_version_comment() -> None:
    assert DORIS_VERSION_COMMENT_QUERY == "SELECT @@version_comment;"


@pytest.mark.parametrize(
    ("comment", "core", "prerelease", "commit", "deployment_hint", "normalized"),
    [
        (
            "Doris version doris-3.0.3-rc03-43f06a5e26 (Cloud Mode)",
            "3.0.3",
            "rc03",
            "43f06a5e26",
            "cloud",
            "3.0.3",
        ),
        (
            "Apache Doris version 4.0.7",
            "4.0.7",
            None,
            None,
            None,
            "4.0.7",
        ),
        (
            "doris-4.1.3-abcdef1234",
            "4.1.3",
            None,
            "abcdef1234",
            None,
            "4.1.3",
        ),
    ],
)
def test_parse_supported_version_comments(
    comment: str,
    core: str,
    prerelease: str | None,
    commit: str | None,
    deployment_hint: str | None,
    normalized: str,
) -> None:
    version = parse_doris_version_comment(comment)

    assert version.parse_status is DorisVersionParseStatus.PARSED
    assert version.core == core
    assert version.prerelease == prerelease
    assert version.commit == commit
    assert version.deployment_hint == deployment_hint
    assert version.normalized == normalized
    assert version.raw == comment


@pytest.mark.parametrize(
    "comment",
    [
        "enterprisedb version 2.1.5",
        "enterprisedb-4.0.6-abc1234",
    ],
)
def test_unregistered_brand_comments_fail_closed(comment: str) -> None:
    version = parse_doris_version_comment(comment)

    assert version.parse_status is DorisVersionParseStatus.UNKNOWN
    assert version.is_parsed is False
    assert version.core is None


@pytest.mark.parametrize(
    ("comment", "core"),
    [
        ("enterprisedb version 2.1.5", "2.1.5"),
        ("enterprisedb version enterprisedb-2.1.5-rc04", "2.1.5"),
        ("enterprisedb-4.0.6-abc1234", "4.0.6"),
    ],
)
def test_registered_brand_alias_comments_parse_three_part_version(
    comment: str,
    core: str,
    enterprise_brand_alias: str,
) -> None:
    version = parse_doris_version_comment(comment)

    assert version.parse_status is DorisVersionParseStatus.PARSED
    assert version.core == core
    assert version.normalized == core
    assert version.brand == enterprise_brand_alias
    assert version.brand_verified is False


def test_brand_alias_configuration_replaces_previous_set(
    enterprise_brand_alias: str,
) -> None:
    assert known_version_brands() == ("doris", enterprise_brand_alias)

    configure_version_brands(("forkdb",))

    assert known_version_brands() == ("doris", "forkdb")
    assert (
        parse_doris_version_comment("enterprisedb version 2.1.5").is_parsed
        is False
    )
    assert parse_doris_version_comment("forkdb version 2.1.5").brand == "forkdb"


@pytest.mark.parametrize(
    "alias",
    [
        "version",
        "apache",
        "bad-token!",
        "two words",
        "1db",
    ],
)
def test_configure_version_brands_rejects_invalid_aliases(alias: str) -> None:
    with pytest.raises(ValueError, match="Invalid Doris version brand alias"):
        configure_version_brands((alias,))


def test_configure_version_brands_rejects_non_string_aliases() -> None:
    with pytest.raises(TypeError, match="must be strings"):
        configure_version_brands(("enterprisedb", 42))


def test_configure_version_brands_ignores_empty_aliases() -> None:
    assert configure_version_brands(("", "  ")) == ("doris",)
    assert known_version_brands() == ("doris",)


@pytest.mark.parametrize(
    "comment",
    [
        "Doris version doris-3.0.3-rc03-43f06a5e26 (Cloud Mode)",
        "Apache Doris version 4.0.7",
        "doris-4.1.3-abcdef1234",
    ],
)
def test_apache_doris_comments_carry_verified_brand(comment: str) -> None:
    version = parse_doris_version_comment(comment)

    assert version.brand == "doris"
    assert version.brand_verified is True


@pytest.mark.parametrize(
    "comment",
    [
        "",
        "MySQL 8.0.36",
        "8.0.33",
        "otherdb version 3.2.0",
        "version 4.1.3",
        "Doris version unknown",
        "Doris version 4.1.3-preview1",
        "Doris version 4.1",
    ],
)
def test_unknown_version_comments_fail_closed(comment: str) -> None:
    version = parse_doris_version_comment(comment)

    assert version.parse_status is DorisVersionParseStatus.UNKNOWN
    assert version.is_parsed is False
    assert version.core is None
    assert version.normalized is None


def test_comparison_uses_only_three_part_version() -> None:
    alpha = parse_doris_version_comment("Doris version 3.0.3-alpha1")
    beta = parse_doris_version_comment("Doris version 3.0.3-beta2")
    release_candidate = parse_doris_version_comment("Doris version 3.0.3-rc03")
    stable_a = parse_doris_version_comment("Doris version 3.0.3-43f06a5e26")
    stable_b = parse_doris_version_comment("Doris version 3.0.3-abcdef1234")

    assert beta.compare(alpha) == 0
    assert release_candidate.compare(beta) == 0
    assert stable_a.compare(release_candidate) == 0
    assert stable_a.compare(stable_b) == 0
    assert stable_a.is_at_least(release_candidate) is True


def test_unparsed_version_cannot_be_compared() -> None:
    unknown = parse_doris_version_comment("Doris version unknown")
    stable = parse_doris_version_comment("Doris version 4.1.3")

    with pytest.raises(ValueError, match="unparsed Doris version"):
        unknown.compare(stable)


@pytest.mark.parametrize(
    "rows",
    [
        [],
        [{"version_comment": "Doris version 4.1.3"}],
        [{"@@version_comment": None}],
    ],
)
def test_version_rows_fail_closed_without_expected_string_column(
    rows: list[dict[str, object]],
) -> None:
    version = parse_doris_version_rows(rows)

    assert version.parse_status is DorisVersionParseStatus.UNKNOWN


async def test_probe_executes_exact_read_only_query() -> None:
    connection = MagicMock(spec=DorisConnection)
    connection.execute = AsyncMock(
        return_value=QueryResult(
            data=[
                {
                    "@@version_comment": (
                        "Doris version doris-3.0.3-rc03-43f06a5e26 "
                        "(Cloud Mode)"
                    )
                }
            ],
            metadata={},
            execution_time=0.01,
            row_count=1,
            sql=DORIS_VERSION_COMMENT_QUERY,
        )
    )

    version = await probe_doris_version(connection)

    assert version.normalized == "3.0.3"
    assert version.deployment_hint == "cloud"
    connection.execute.assert_awaited_once_with(
        DORIS_VERSION_COMMENT_QUERY,
        mask_result=False,
        max_rows=1,
        max_bytes=4096,
    )

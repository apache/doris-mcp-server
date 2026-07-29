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

from datetime import UTC, datetime, timedelta, timezone

from doris_mcp_server.utils.datetime_utils import (
    as_utc,
    format_rfc3339,
    utc_now,
)


def test_utc_now_is_timezone_aware_utc():
    current = utc_now()

    assert current.tzinfo is UTC
    assert current.utcoffset() == timedelta(0)


def test_as_utc_accepts_legacy_naive_and_non_utc_values():
    assert as_utc(datetime(2026, 7, 30, 1, 2, 3)) == datetime(
        2026,
        7,
        30,
        1,
        2,
        3,
        tzinfo=UTC,
    )
    assert as_utc(
        datetime(2026, 7, 30, 9, 2, 3, tzinfo=timezone(timedelta(hours=8)))
    ) == datetime(2026, 7, 30, 1, 2, 3, tzinfo=UTC)


def test_format_rfc3339_emits_one_utc_designator():
    assert format_rfc3339(datetime(2026, 7, 30, 1, 2, 3, tzinfo=UTC)) == (
        "2026-07-30T01:02:03Z"
    )

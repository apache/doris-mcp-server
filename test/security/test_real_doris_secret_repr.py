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

from typing import cast

import pymysql

from test.integration.test_real_doris_transports import (
    DorisSandbox,
    RealDorisSettings,
)


def test_real_doris_fixture_repr_redacts_passwords() -> None:
    admin_password = "admin-secret-that-must-not-be-rendered"
    readonly_password = "readonly-secret-that-must-not-be-rendered"
    settings = RealDorisSettings(
        host="127.0.0.1",
        port=9030,
        user="admin",
        password=admin_password,
        database="test",
    )
    sandbox = DorisSandbox(
        settings=settings,
        admin_connection=cast(pymysql.Connection, object()),
        table="fixture",
        restricted_table="restricted_fixture",
        readonly_user="readonly",
        readonly_password=readonly_password,
        marker="marker",
    )

    rendered = repr(sandbox)
    assert admin_password not in rendered
    assert readonly_password not in rendered

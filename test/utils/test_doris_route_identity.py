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
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for secret-free Doris route cache identities."""

from doris_mcp_server.utils.config import DorisConfig
from doris_mcp_server.utils.db import DorisConnectionManager
from doris_mcp_server.utils.security import AuthContext


def test_route_identity_is_stable_isolated_and_secret_free() -> None:
    config = DorisConfig()
    config.database.host = "doris.internal"
    config.database.hosts = ["doris.internal", "doris-backup.internal"]
    config.database.port = 9030
    config.database.user = "service_user"
    config.database.password = "database-password"
    config.database.database = "analytics"
    manager = DorisConnectionManager(config)

    global_route = manager.get_route_identity()
    token_route = manager.get_route_identity(
        AuthContext(
            auth_method="token",
            token="raw-static-token",
        )
    )
    doris_user_route = manager.get_route_identity(
        AuthContext(
            auth_method="doris_oauth",
            doris_user="analyst",
        )
    )

    assert global_route.route_key == "global"
    assert token_route.route_key.startswith("static_token:")
    assert doris_user_route.route_key == "doris_user:analyst"
    assert len(
        {
            global_route.fingerprint,
            token_route.fingerprint,
            doris_user_route.fingerprint,
        }
    ) == 3
    rendered = repr(
        (global_route, token_route, doris_user_route)
    )
    assert "database-password" not in rendered
    assert "raw-static-token" not in rendered

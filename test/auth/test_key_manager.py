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

from datetime import UTC
from types import SimpleNamespace

import pytest

from doris_mcp_server.auth.key_manager import KeyManager


@pytest.mark.asyncio
async def test_existing_key_files_load_with_timezone_aware_generation_time(
    tmp_path,
):
    security = SimpleNamespace(
        jwt_algorithm="RS256",
        key_rotation_interval=3600,
        jwt_private_key_path=str(tmp_path / "private.pem"),
        jwt_public_key_path=str(tmp_path / "public.pem"),
        jwt_secret_key=None,
    )
    config = SimpleNamespace(security=security)

    generated = KeyManager(config)
    await generated.generate_key_pair()

    loaded = KeyManager(config)
    assert await loaded.initialize() is True
    assert loaded._key_generated_at.tzinfo is UTC
    assert await loaded.is_key_expired() is False

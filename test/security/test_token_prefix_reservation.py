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

import json

import pytest

from doris_mcp_server.auth.token_manager import TokenManager
from doris_mcp_server.utils.config import DorisConfig


def _config(tmp_path):
    config = DorisConfig()
    config.security.token_file_path = str(tmp_path / "tokens.json")
    return config


@pytest.mark.asyncio
async def test_token_file_rejects_reserved_doris_oauth_prefix(tmp_path):
    config = _config(tmp_path)
    with open(config.security.token_file_path, "w", encoding="utf-8") as f:
        json.dump({"tokens": [{"token_id": "bad", "token": "doa_bad"}]}, f)

    with pytest.raises(ValueError, match="reserved Doris OAuth prefix"):
        TokenManager(config)


@pytest.mark.asyncio
async def test_env_token_rejects_reserved_doris_oauth_prefix(tmp_path, monkeypatch):
    config = _config(tmp_path)
    monkeypatch.setenv("TOKEN_BAD", "doa_bad")

    with pytest.raises(ValueError, match="reserved Doris OAuth prefix"):
        TokenManager(config)


@pytest.mark.asyncio
async def test_create_token_rejects_reserved_doris_oauth_prefix(tmp_path):
    config = _config(tmp_path)
    with open(config.security.token_file_path, "w", encoding="utf-8") as f:
        json.dump({"tokens": []}, f)
    manager = TokenManager(config)
    try:
        with pytest.raises(ValueError, match="reserved Doris OAuth prefix"):
            await manager.create_token("bad", custom_token="doa_bad")
    finally:
        manager.stop_hot_reload()

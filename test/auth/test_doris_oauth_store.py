from dataclasses import asdict, is_dataclass

from doris_mcp_server.auth.doris_oauth_store import DorisOAuthStore


def _assert_raw_absent(store, raw_values):
    for raw in raw_values:
        assert raw
        for name, value in store.__dict__.items():
            if name == "_hash_key":
                continue
            assert raw not in repr(value)
            if isinstance(value, dict):
                for key, item in value.items():
                    assert raw not in repr(key)
                    assert raw not in repr(item)
                    if is_dataclass(item):
                        assert raw not in repr(asdict(item))


def test_store_keeps_tokens_codes_and_client_secret_hash_only():
    store = DorisOAuthStore()
    client_secret = "dos_RAW_CLIENT_SECRET_123"
    store.add_client(
        client_id="client-1",
        client_secret=client_secret,
        token_endpoint_auth_method="client_secret_post",
        redirect_uris=("http://localhost:7777/callback",),
        client_allowed_scopes=("tool:list",),
        source="dcr",
        expires_at=None,
        registration_ip="127.0.0.1",
    )
    txn_id, _txn = store.create_auth_transaction(
        client_id="client-1",
        redirect_uri="http://localhost:7777/callback",
        state="state-1",
        code_challenge="challenge",
        requested_scopes=("tool:list",),
        candidate_granted_scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        client_ip="127.0.0.1",
        ttl_seconds=300,
    )
    csrf = "dcsrf_RAW_CSRF_123"
    store.set_transaction_csrf(txn_id, csrf)
    code, _code_record = store.create_authorization_code(
        client_id="client-1",
        doris_user="alice",
        redirect_uri="http://localhost:7777/callback",
        scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        code_challenge="challenge",
        code_challenge_method="S256",
        ttl_seconds=300,
    )
    pair = store.issue_token_pair(
        client_id="client-1",
        doris_user="alice",
        scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
    )

    _assert_raw_absent(
        store,
        [
            client_secret,
            txn_id,
            csrf,
            code,
            pair.access_token,
            pair.refresh_token,
        ],
    )


def test_authorization_code_is_single_use():
    store = DorisOAuthStore()
    code, _record = store.create_authorization_code(
        client_id="client-1",
        doris_user="alice",
        redirect_uri="http://localhost:7777/callback",
        scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        code_challenge="challenge",
        code_challenge_method="S256",
        ttl_seconds=300,
    )

    assert store.pop_authorization_code(code) is not None
    assert store.pop_authorization_code(code) is None


def test_refresh_rotation_revokes_old_pair_but_keeps_new_family_active():
    store = DorisOAuthStore()
    old_pair = store.issue_token_pair(
        client_id="client-1",
        doris_user="alice",
        scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
    )
    store.revoke_pair_for_refresh_id(old_pair.refresh_record.token_id)
    new_pair = store.issue_token_pair(
        client_id="client-1",
        doris_user="alice",
        scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
        family_id=old_pair.refresh_record.family_id,
        rotated_from=old_pair.refresh_record.token_id,
    )

    assert store.get_access_token(old_pair.access_token).revoked_at is not None
    assert store.get_refresh_token(old_pair.refresh_token).revoked_at is not None
    assert store.get_access_token(new_pair.access_token).revoked_at is None
    assert store.get_refresh_token(new_pair.refresh_token).revoked_at is None
    assert store.active_users() == {"alice"}


def test_pool_missing_family_revoke_makes_access_and_refresh_inactive():
    store = DorisOAuthStore()
    pair = store.issue_token_pair(
        client_id="client-1",
        doris_user="alice",
        scopes=("tool:list",),
        resource="http://localhost:3000/mcp",
        access_ttl_seconds=900,
        refresh_ttl_seconds=86400,
    )

    store.revoke_family_by_access_token_id(pair.access_record.token_id)

    assert store.get_access_token(pair.access_token).revoked_at is not None
    assert store.get_refresh_token(pair.refresh_token).revoked_at is not None
    assert store.active_users() == set()

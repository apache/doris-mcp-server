#!/usr/bin/env python3
"""In-memory HMAC-backed store for Doris-backed OAuth."""

import hmac
import hashlib
import secrets
import time
from dataclasses import replace

from .doris_oauth_types import (
    AccessTokenRecord,
    AuthTransactionRecord,
    AuthorizationCodeRecord,
    IssuedTokenPair,
    RefreshTokenRecord,
    RegisteredClientRecord,
)
from ..utils.security import RESERVED_DORIS_OAUTH_TOKEN_PREFIX


class DorisOAuthStore:
    """Process-local OAuth store with hash-only credential lookup."""

    def __init__(self):
        self._hash_key = secrets.token_bytes(32)
        self.clients_by_id: dict[str, RegisteredClientRecord] = {}
        self.transactions_by_txn_hash: dict[str, AuthTransactionRecord] = {}
        self.codes_by_hash: dict[str, AuthorizationCodeRecord] = {}
        self.access_by_hash: dict[str, AccessTokenRecord] = {}
        self.refresh_by_hash: dict[str, RefreshTokenRecord] = {}
        self.access_id_to_hash: dict[str, str] = {}
        self.refresh_id_to_hash: dict[str, str] = {}
        self.access_to_refresh_id: dict[str, str] = {}
        self.refresh_to_access_id: dict[str, str] = {}
        self.user_token_ids: dict[str, set[str]] = {}

    def hmac_lookup(self, value: str, purpose: str) -> str:
        payload = f"{purpose}:{value}".encode("utf-8")
        return hmac.new(self._hash_key, payload, hashlib.sha256).hexdigest()

    def hash_client_secret(self, client_secret: str) -> str:
        return self.hmac_lookup(client_secret, "client_secret")

    def hash_public_value(self, value: str) -> str:
        return self.hmac_lookup(value, "public")

    def add_client(
        self,
        *,
        client_id: str,
        client_secret: str | None,
        token_endpoint_auth_method: str,
        redirect_uris: tuple[str, ...],
        client_allowed_scopes: tuple[str, ...],
        source: str,
        expires_at: float | None,
        registration_ip: str | None = None,
    ) -> RegisteredClientRecord:
        record = RegisteredClientRecord(
            client_id=client_id,
            client_secret_hash=self.hash_client_secret(client_secret) if client_secret else None,
            token_endpoint_auth_method=token_endpoint_auth_method,
            redirect_uris=redirect_uris,
            client_allowed_scopes=client_allowed_scopes,
            source=source,
            created_at=time.time(),
            expires_at=expires_at,
            registration_ip_hash=self.hash_public_value(registration_ip) if registration_ip else None,
        )
        self.clients_by_id[client_id] = record
        return record

    def get_client(self, client_id: str) -> RegisteredClientRecord | None:
        record = self.clients_by_id.get(client_id)
        if record and record.expires_at is not None and record.expires_at <= time.time():
            self.clients_by_id.pop(client_id, None)
            return None
        return record

    def validate_client_secret(self, client: RegisteredClientRecord, client_secret: str | None) -> bool:
        if client.token_endpoint_auth_method == "none":
            return True
        if not client_secret or not client.client_secret_hash:
            return False
        return hmac.compare_digest(self.hash_client_secret(client_secret), client.client_secret_hash)

    def create_auth_transaction(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        code_challenge: str,
        requested_scopes: tuple[str, ...],
        candidate_granted_scopes: tuple[str, ...],
        resource: str,
        client_ip: str,
        ttl_seconds: int,
    ) -> tuple[str, AuthTransactionRecord]:
        txn_id = f"dot_{secrets.token_urlsafe(32)}"
        txn_hash = self.hmac_lookup(txn_id, "txn")
        now = time.time()
        record = AuthTransactionRecord(
            txn_id_hash=txn_hash,
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method="S256",
            requested_scopes=requested_scopes,
            candidate_granted_scopes=candidate_granted_scopes,
            resource=resource,
            login_csrf_hash="",
            client_ip_hash=self.hash_public_value(client_ip),
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        self.transactions_by_txn_hash[txn_hash] = record
        return txn_id, record

    def get_auth_transaction(self, txn_id: str) -> AuthTransactionRecord | None:
        txn_hash = self.hmac_lookup(txn_id, "txn")
        record = self.transactions_by_txn_hash.get(txn_hash)
        if record and record.expires_at <= time.time():
            self.transactions_by_txn_hash.pop(txn_hash, None)
            return None
        return record

    def set_transaction_csrf(self, txn_id: str, csrf_value: str) -> AuthTransactionRecord | None:
        txn_hash = self.hmac_lookup(txn_id, "txn")
        record = self.get_auth_transaction(txn_id)
        if not record:
            return None
        updated = replace(record, login_csrf_hash=self.hmac_lookup(csrf_value, "csrf"))
        self.transactions_by_txn_hash[txn_hash] = updated
        return updated

    def validate_transaction_csrf(self, txn_id: str, csrf_value: str) -> bool:
        record = self.get_auth_transaction(txn_id)
        if not record or not record.login_csrf_hash:
            return False
        return hmac.compare_digest(record.login_csrf_hash, self.hmac_lookup(csrf_value, "csrf"))

    def delete_auth_transaction(self, txn_id: str) -> None:
        self.transactions_by_txn_hash.pop(self.hmac_lookup(txn_id, "txn"), None)

    def create_authorization_code(
        self,
        *,
        client_id: str,
        doris_user: str,
        redirect_uri: str,
        scopes: tuple[str, ...],
        resource: str,
        code_challenge: str,
        code_challenge_method: str,
        ttl_seconds: int,
    ) -> tuple[str, AuthorizationCodeRecord]:
        code = f"doc_{secrets.token_urlsafe(32)}"
        code_hash = self.hmac_lookup(code, "code")
        now = time.time()
        record = AuthorizationCodeRecord(
            code_hash=code_hash,
            code_id=f"code_{secrets.token_urlsafe(12)}",
            client_id=client_id,
            doris_user=doris_user,
            redirect_uri=redirect_uri,
            scopes=scopes,
            resource=resource,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            created_at=now,
            expires_at=now + ttl_seconds,
        )
        self.codes_by_hash[code_hash] = record
        return code, record

    def pop_authorization_code(self, code: str) -> AuthorizationCodeRecord | None:
        code_hash = self.hmac_lookup(code, "code")
        record = self.codes_by_hash.pop(code_hash, None)
        if record and record.expires_at <= time.time():
            return None
        if record and record.used_at is not None:
            return None
        return record

    def issue_token_pair(
        self,
        *,
        client_id: str,
        doris_user: str,
        scopes: tuple[str, ...],
        resource: str,
        access_ttl_seconds: int,
        refresh_ttl_seconds: int,
        family_id: str | None = None,
        rotated_from: str | None = None,
    ) -> IssuedTokenPair:
        access_token = f"{RESERVED_DORIS_OAUTH_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"
        refresh_token = f"dor_{secrets.token_urlsafe(40)}"
        access_hash = self.hmac_lookup(access_token, "access")
        refresh_hash = self.hmac_lookup(refresh_token, "refresh")
        now = time.time()
        access_id = f"at_{secrets.token_urlsafe(12)}"
        refresh_id = f"rt_{secrets.token_urlsafe(12)}"
        token_family_id = family_id or f"fam_{secrets.token_urlsafe(12)}"

        access_record = AccessTokenRecord(
            token_hash=access_hash,
            token_id=access_id,
            client_id=client_id,
            doris_user=doris_user,
            scopes=scopes,
            resource=resource,
            refresh_token_id=refresh_id,
            family_id=token_family_id,
            issued_at=now,
            expires_at=now + access_ttl_seconds,
        )
        refresh_record = RefreshTokenRecord(
            token_hash=refresh_hash,
            token_id=refresh_id,
            client_id=client_id,
            doris_user=doris_user,
            scopes=scopes,
            resource=resource,
            access_token_id=access_id,
            family_id=token_family_id,
            issued_at=now,
            expires_at=now + refresh_ttl_seconds,
            rotated_from=rotated_from,
        )

        self.access_by_hash[access_hash] = access_record
        self.refresh_by_hash[refresh_hash] = refresh_record
        self.access_id_to_hash[access_id] = access_hash
        self.refresh_id_to_hash[refresh_id] = refresh_hash
        self.access_to_refresh_id[access_id] = refresh_id
        self.refresh_to_access_id[refresh_id] = access_id
        self.user_token_ids.setdefault(doris_user, set()).update({access_id, refresh_id})
        return IssuedTokenPair(access_token, refresh_token, access_record, refresh_record)

    def get_access_token(self, raw_access_token: str) -> AccessTokenRecord | None:
        record = self.access_by_hash.get(self.hmac_lookup(raw_access_token, "access"))
        if record and record.expires_at <= time.time():
            return None
        return record

    def get_refresh_token(self, raw_refresh_token: str) -> RefreshTokenRecord | None:
        record = self.refresh_by_hash.get(self.hmac_lookup(raw_refresh_token, "refresh"))
        if record and record.expires_at <= time.time():
            return None
        return record

    def find_access_or_refresh(self, raw_token: str) -> AccessTokenRecord | RefreshTokenRecord | None:
        return self.get_access_token(raw_token) or self.get_refresh_token(raw_token)

    def update_access_last_used(self, access_token_id: str) -> AccessTokenRecord | None:
        access_hash = self.access_id_to_hash.get(access_token_id)
        if not access_hash:
            return None
        record = self.access_by_hash.get(access_hash)
        if not record:
            return None
        updated = replace(record, last_used_at=time.time())
        self.access_by_hash[access_hash] = updated
        return updated

    def revoke_pair_for_refresh_id(self, refresh_token_id: str) -> None:
        refresh_hash = self.refresh_id_to_hash.get(refresh_token_id)
        if not refresh_hash:
            return
        now = time.time()
        refresh = self.refresh_by_hash.get(refresh_hash)
        if refresh:
            self.refresh_by_hash[refresh_hash] = replace(refresh, revoked_at=refresh.revoked_at or now)
            access_hash = self.access_id_to_hash.get(refresh.access_token_id)
            access = self.access_by_hash.get(access_hash or "")
            if access:
                self.access_by_hash[access_hash] = replace(access, revoked_at=access.revoked_at or now)

    def revoke_family_by_access_token_id(self, access_token_id: str) -> None:
        access_hash = self.access_id_to_hash.get(access_token_id)
        access = self.access_by_hash.get(access_hash or "")
        if access:
            self._revoke_family(access.family_id)

    def revoke_family_by_refresh_token_id(self, refresh_token_id: str) -> None:
        refresh_hash = self.refresh_id_to_hash.get(refresh_token_id)
        refresh = self.refresh_by_hash.get(refresh_hash or "")
        if refresh:
            self._revoke_family(refresh.family_id)

    def revoke_token(self, raw_token: str) -> bool:
        record = self.find_access_or_refresh(raw_token)
        if isinstance(record, AccessTokenRecord):
            self.revoke_family_by_access_token_id(record.token_id)
            return True
        if isinstance(record, RefreshTokenRecord):
            self.revoke_family_by_refresh_token_id(record.token_id)
            return True
        return False

    def _revoke_family(self, family_id: str) -> None:
        now = time.time()
        for token_hash, access in list(self.access_by_hash.items()):
            if access.family_id == family_id:
                self.access_by_hash[token_hash] = replace(access, revoked_at=access.revoked_at or now)
        for token_hash, refresh in list(self.refresh_by_hash.items()):
            if refresh.family_id == family_id:
                self.refresh_by_hash[token_hash] = replace(refresh, revoked_at=refresh.revoked_at or now)

    def active_users(self) -> set[str]:
        now = time.time()
        users: set[str] = set()
        for record in self.access_by_hash.values():
            if record.revoked_at is None and record.expires_at > now:
                users.add(record.doris_user)
        for record in self.refresh_by_hash.values():
            if record.revoked_at is None and record.expires_at > now:
                users.add(record.doris_user)
        return users

    def cleanup_expired(self) -> None:
        now = time.time()
        for client_id, record in list(self.clients_by_id.items()):
            if record.source == "dcr" and record.expires_at is not None and record.expires_at <= now:
                self.clients_by_id.pop(client_id, None)
        for txn_hash, record in list(self.transactions_by_txn_hash.items()):
            if record.expires_at <= now:
                self.transactions_by_txn_hash.pop(txn_hash, None)
        for code_hash, record in list(self.codes_by_hash.items()):
            if record.expires_at <= now or record.used_at is not None:
                self.codes_by_hash.pop(code_hash, None)
        for access_hash, record in list(self.access_by_hash.items()):
            if record.expires_at <= now and record.revoked_at is not None:
                self.access_by_hash.pop(access_hash, None)
                self.access_id_to_hash.pop(record.token_id, None)
        for refresh_hash, record in list(self.refresh_by_hash.items()):
            if record.expires_at <= now and record.revoked_at is not None:
                self.refresh_by_hash.pop(refresh_hash, None)
                self.refresh_id_to_hash.pop(record.token_id, None)

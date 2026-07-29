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

import pytest

from doris_mcp_server.auth.oauth_token_validation import (
    ExternalOAuthTokenValidator,
    OAuthAccessTokenValidationError,
)

ISSUER_A = "https://issuer-a.example.test"
ISSUER_B = "https://issuer-b.example.test"
RESOURCE_A = "https://mcp-a.example.test/mcp"
RESOURCE_B = "https://mcp-b.example.test/mcp"
ALLOWED_SCOPES = ("tool:list", "resource:list", "resource:read")
REQUIRED_SCOPES = ("tool:list", "resource:read")


def _validator() -> ExternalOAuthTokenValidator:
    return ExternalOAuthTokenValidator(
        issuer=ISSUER_A,
        resource=RESOURCE_A,
        audience=RESOURCE_A,
        allowed_scopes=ALLOWED_SCOPES,
        required_scopes=REQUIRED_SCOPES,
    )


def _claims(
    *,
    issuer: str = ISSUER_A,
    resource: str = RESOURCE_A,
    scopes: tuple[str, ...] = REQUIRED_SCOPES,
) -> dict[str, object]:
    return {
        "active": True,
        "iss": issuer,
        "aud": [resource],
        "resource": resource,
        "scope": " ".join(scopes),
        "sub": "user-1",
        "client_id": "client-1",
        "jti": "token-1",
        "exp": 200,
    }


@pytest.mark.parametrize("issuer", [ISSUER_A, ISSUER_B])
@pytest.mark.parametrize("resource", [RESOURCE_A, RESOURCE_B])
@pytest.mark.parametrize(
    ("scope_case", "scopes", "scope_is_valid", "expected_scopes"),
    [
        ("insufficient", ("tool:list",), False, ()),
        ("minimum", REQUIRED_SCOPES, True, tuple(sorted(REQUIRED_SCOPES))),
        (
            "superset",
            (*ALLOWED_SCOPES, "unconfigured:admin"),
            True,
            tuple(sorted(ALLOWED_SCOPES)),
        ),
    ],
)
def test_two_issuer_two_resource_three_scope_matrix_is_least_privilege(
    issuer,
    resource,
    scope_case,
    scopes,
    scope_is_valid,
    expected_scopes,
):
    claims = _claims(issuer=issuer, resource=resource, scopes=scopes)
    should_accept = issuer == ISSUER_A and resource == RESOURCE_A and scope_is_valid

    if not should_accept:
        with pytest.raises(OAuthAccessTokenValidationError) as exc_info:
            _validator().validate(claims, current_time=100)
        if issuer != ISSUER_A or resource != RESOURCE_A:
            assert exc_info.value.error == "invalid_token"
        else:
            assert scope_case == "insufficient"
            assert exc_info.value.error == "insufficient_scope"
        return

    context = _validator().validate(claims, current_time=100)

    assert context.issuer == ISSUER_A
    assert context.resource == RESOURCE_A
    assert context.audiences == (RESOURCE_A,)
    assert context.scopes == expected_scopes
    assert "unconfigured:admin" not in context.scopes
    assert context.subject == "user-1"
    assert context.client_id == "client-1"
    assert context.token_id == "token-1"
    assert context.expires_at == 200


@pytest.mark.parametrize(
    ("claim", "value", "error"),
    [
        ("active", False, "invalid_token"),
        ("exp", 100, "invalid_token"),
        ("exp", float("nan"), "invalid_token"),
        ("nbf", 101, "invalid_token"),
        ("sub", "", "invalid_token"),
    ],
)
def test_invalid_lifecycle_or_identity_claims_fail_closed(claim, value, error):
    claims = _claims()
    claims[claim] = value

    with pytest.raises(OAuthAccessTokenValidationError) as exc_info:
        _validator().validate(claims, current_time=100)

    assert exc_info.value.error == error


def test_resource_claim_cannot_override_a_valid_audience():
    claims = _claims()
    claims["resource"] = RESOURCE_B

    with pytest.raises(
        OAuthAccessTokenValidationError,
        match="resource mismatch",
    ):
        _validator().validate(claims, current_time=100)


def test_rfc7662_response_without_nonstandard_resource_uses_audience_binding():
    claims = _claims()
    del claims["resource"]

    context = _validator().validate(claims, current_time=100)

    assert context.resource == RESOURCE_A

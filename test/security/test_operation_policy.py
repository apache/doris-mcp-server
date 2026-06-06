from types import SimpleNamespace

import pytest

from doris_mcp_server.auth.operation_policy import (
    HIGH_RISK_TOOLS,
    OperationAuthorizationError,
    P4_DORIS_OAUTH_METADATA_TOOLS,
    authorize_operation,
    filter_tools_for_auth_context,
)
from doris_mcp_server.auth.doris_oauth_scope_policy import DorisOAuthScopePolicy
from doris_mcp_server.auth.doris_oauth_types import TokenEndpointError
from doris_mcp_server.utils.security import AuthContext


def doris_context(
    scopes,
    *,
    db_tools_enabled=False,
    allowlist=None,
    query_tools_enabled=False,
    query_allowlist=None,
    explain_tools_enabled=False,
    explain_allowlist=None,
):
    context = AuthContext(
        user_id="doris_user",
        auth_method="doris_oauth",
        oauth_scopes=list(scopes),
        pool_key="doris_user:doris_user",
    )
    context.doris_oauth_db_tools_enabled = db_tools_enabled
    context.doris_oauth_db_tool_allowlist = tuple(
        allowlist if allowlist is not None else sorted(P4_DORIS_OAUTH_METADATA_TOOLS)
    )
    context.doris_oauth_query_tools_enabled = query_tools_enabled
    context.doris_oauth_query_tool_allowlist = tuple(
        query_allowlist if query_allowlist is not None else ("exec_query",)
    )
    context.doris_oauth_explain_tools_enabled = explain_tools_enabled
    context.doris_oauth_explain_tool_allowlist = tuple(
        explain_allowlist if explain_allowlist is not None else ("get_sql_explain",)
    )
    return context


def test_legacy_auth_methods_pass_through_operation_policy():
    authorize_operation(AuthContext(auth_method="token"), "tool:get_sql_profile")


def test_missing_auth_context_passes_for_legacy_stdio_paths():
    authorize_operation(None, "tool:get_sql_profile")


@pytest.mark.parametrize("tool_name", sorted(P4_DORIS_OAUTH_METADATA_TOOLS))
def test_doris_oauth_rejects_metadata_tools_when_db_gate_false(tool_name):
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context([f"tool:call:{tool_name}"]),
            f"tool:{tool_name}",
        )

    assert exc.value.error_code == "DORIS_OAUTH_DB_TOOLS_NOT_ENABLED"


@pytest.mark.parametrize("tool_name", sorted(P4_DORIS_OAUTH_METADATA_TOOLS))
def test_doris_oauth_allows_metadata_tools_with_gate_allowlist_and_matching_scope(tool_name):
    authorize_operation(
        doris_context(
            [f"tool:call:{tool_name}"],
            db_tools_enabled=True,
            allowlist=sorted(P4_DORIS_OAUTH_METADATA_TOOLS),
        ),
        f"tool:{tool_name}",
    )


def test_doris_oauth_metadata_gate_respects_configured_allowlist():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context(
                ["tool:call:get_table_schema"],
                db_tools_enabled=True,
                allowlist=["get_db_list"],
            ),
            "tool:get_table_schema",
        )

    assert exc.value.error_code == "DORIS_OAUTH_TOOL_NOT_ALLOWED"


@pytest.mark.parametrize(
    ("tool_name", "error_code"),
    [
        ("exec_query", "DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED"),
        ("get_sql_explain", "DORIS_OAUTH_EXPLAIN_TOOL_NOT_ENABLED"),
    ],
)
def test_doris_oauth_query_and_explain_remain_denied_with_db_gate_true(tool_name, error_code):
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context(
                [f"tool:call:{tool_name}"],
                db_tools_enabled=True,
                allowlist=sorted(P4_DORIS_OAUTH_METADATA_TOOLS),
            ),
            f"tool:{tool_name}",
        )

    assert exc.value.error_code == error_code


def test_doris_oauth_allows_query_with_query_gate_and_matching_scope():
    authorize_operation(
        doris_context(
            ["tool:call:exec_query"],
            query_tools_enabled=True,
        ),
        "tool:exec_query",
    )


def test_doris_oauth_allows_explain_with_explain_gate_and_matching_scope():
    authorize_operation(
        doris_context(
            ["tool:call:get_sql_explain"],
            explain_tools_enabled=True,
        ),
        "tool:get_sql_explain",
    )


def test_doris_oauth_query_gate_respects_configured_allowlist():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context(
                ["tool:call:exec_query"],
                query_tools_enabled=True,
                query_allowlist=[],
            ),
            "tool:exec_query",
        )

    assert exc.value.error_code == "DORIS_OAUTH_TOOL_NOT_ALLOWED"


def test_doris_oauth_explain_gate_respects_configured_allowlist():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context(
                ["tool:call:get_sql_explain"],
                explain_tools_enabled=True,
                explain_allowlist=[],
            ),
            "tool:get_sql_explain",
        )

    assert exc.value.error_code == "DORIS_OAUTH_TOOL_NOT_ALLOWED"


@pytest.mark.parametrize(
    ("tool_name", "error_code"),
    [
        ("exec_query", "DORIS_OAUTH_QUERY_TOOL_NOT_ENABLED"),
        ("get_sql_explain", "DORIS_OAUTH_EXPLAIN_TOOL_NOT_ENABLED"),
    ],
)
def test_invalid_metadata_allowlist_cannot_open_query_or_explain(tool_name, error_code):
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context(
                [f"tool:call:{tool_name}"],
                db_tools_enabled=True,
                allowlist=["get_db_list", tool_name],
            ),
            f"tool:{tool_name}",
        )

    assert exc.value.error_code == error_code


def test_doris_oauth_rejects_missing_scope_for_allowed_operations():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(doris_context([]), "list_tools")

    assert exc.value.status_code == 403
    assert exc.value.error_code == "PERMISSION_DENIED"


@pytest.mark.parametrize(
    ("operation", "scope"),
    [
        ("list_resources", "resource:list"),
        ("read_resource", "resource:read"),
    ],
)
def test_doris_oauth_allows_resources_with_matching_scope(operation, scope):
    authorize_operation(doris_context([scope]), operation)


@pytest.mark.parametrize(
    ("operation", "scope"),
    [
        ("list_resources", "resource:list"),
        ("read_resource", "resource:read"),
    ],
)
def test_doris_oauth_rejects_resources_without_matching_scope(operation, scope):
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(doris_context([]), operation)

    assert exc.value.error_code == "PERMISSION_DENIED"
    assert exc.value.required_scope == scope


def test_doris_oauth_prompts_remain_denied_even_with_scope():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(doris_context(["prompt:list"]), "list_prompts")

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"


@pytest.mark.parametrize("tool_name", sorted(HIGH_RISK_TOOLS))
def test_doris_oauth_rejects_high_risk_tools_even_with_forged_matching_scope(tool_name):
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context([f"tool:call:{tool_name}"]),
            f"tool:{tool_name}",
        )

    assert exc.value.error_code == "UNSUPPORTED_FOR_DORIS_OAUTH"


def test_filter_tools_for_doris_oauth_hides_all_high_risk_tools_even_with_forged_scopes():
    tools = [SimpleNamespace(name=tool_name) for tool_name in sorted(HIGH_RISK_TOOLS)]
    forged_scopes = [f"tool:call:{tool_name}" for tool_name in sorted(HIGH_RISK_TOOLS)]

    filtered = filter_tools_for_auth_context(
        doris_context(forged_scopes),
        tools,
    )

    assert filtered == []


@pytest.mark.parametrize(
    "scope",
    [
        "scope:profile:read",
        "scope:monitoring:read",
        "scope:adbc:execute",
        "scope:audit:read",
        "scope:governance:read",
        "scope:performance:read",
        "scope:admin",
        "scope:service_account",
    ],
)
def test_doris_oauth_scope_policy_rejects_forbidden_channel_scopes(scope):
    policy = DorisOAuthScopePolicy()

    with pytest.raises(TokenEndpointError) as exc:
        policy.grant_client_scopes(scope, explicit=True)

    assert exc.value.error == "invalid_scope"


def test_doris_oauth_forged_wildcard_scope_does_not_satisfy_metadata_scope():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(
            doris_context(
                ["*"],
                db_tools_enabled=True,
                allowlist=["get_db_list"],
            ),
            "tool:get_db_list",
        )

    assert exc.value.error_code == "PERMISSION_DENIED"


def test_doris_oauth_unknown_tool_rejected_before_dispatch():
    with pytest.raises(OperationAuthorizationError) as exc:
        authorize_operation(doris_context(["tool:call:not_real"]), "tool:not_real")

    assert exc.value.error_code == "UNKNOWN_OPERATION"


def test_filter_tools_for_doris_oauth_hides_disabled_or_denied_tools():
    tools = [
        SimpleNamespace(name="get_db_list"),
        SimpleNamespace(name="exec_query"),
        SimpleNamespace(name="get_sql_profile"),
    ]

    filtered = filter_tools_for_auth_context(
        doris_context(
            ["tool:call:get_db_list", "tool:call:exec_query", "tool:call:get_sql_profile"],
            db_tools_enabled=True,
            query_tools_enabled=True,
            allowlist=["get_db_list"],
        ),
        tools,
    )

    assert [tool.name for tool in filtered] == ["get_db_list", "exec_query"]

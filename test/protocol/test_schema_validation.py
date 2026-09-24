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
"""JSON Schema 2020-12 definition and resource-boundary tests."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from mcp.types import Tool

from doris_mcp_server.result_limits import DEFAULT_MAX_RESULT_BYTES
from doris_mcp_server.schema_validation import (
    DEFAULT_SCHEMA_LIMITS,
    JSON_SCHEMA_2020_12,
    SchemaLimits,
    ToolArgumentsValidationError,
    ToolOutputValidationError,
    ToolSchemaDefinitionError,
    ToolSchemaGuard,
)


def _advanced_tool(
    *,
    input_schema: dict | None = None,
    output_schema: dict | None = None,
) -> Tool:
    return Tool(
        name="select_rows",
        description="Select rows by identifier or name.",
        input_schema=input_schema
        or {
            "$schema": JSON_SCHEMA_2020_12,
            "type": "object",
            "$defs": {
                "selector": {
                    "oneOf": [
                        {
                            "type": "object",
                            "properties": {"id": {"type": "integer"}},
                            "required": ["id"],
                            "additionalProperties": False,
                        },
                        {
                            "type": "object",
                            "properties": {
                                "name": {
                                    "type": "string",
                                    "minLength": 1,
                                }
                            },
                            "required": ["name"],
                            "additionalProperties": False,
                        },
                    ]
                }
            },
            "properties": {
                "selector": {"$ref": "#/$defs/selector"},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": ["selector"],
            "additionalProperties": False,
        },
        output_schema=output_schema
        or {
            "$schema": JSON_SCHEMA_2020_12,
            "type": "array",
            "items": {
                "type": "object",
                "properties": {"id": {"type": "integer"}},
                "required": ["id"],
                "additionalProperties": False,
            },
        },
    )


def test_full_2020_12_schema_validates_inputs_and_outputs_without_value_echo():
    compiled = ToolSchemaGuard().compile_tool(_advanced_tool())

    compiled.validate_arguments({"selector": {"id": 7}, "limit": 10})
    compiled.validate_arguments({"selector": {"name": "orders"}})
    compiled.validate_output([{"id": 7}])

    with pytest.raises(ToolArgumentsValidationError) as invalid:
        compiled.validate_arguments(
            {
                "selector": {"name": ""},
                "limit": 101,
                "secret": "must-not-echo",
            }
        )
    assert invalid.value.violations
    assert all(
        set(violation.as_dict()) == {"instancePath", "keyword"}
        for violation in invalid.value.violations
    )
    assert "must-not-echo" not in repr(
        [violation.as_dict() for violation in invalid.value.violations]
    )

    with pytest.raises(ToolOutputValidationError):
        compiled.validate_output([{"id": "not-an-integer"}])


@pytest.mark.parametrize(
    "schema, expected",
    [
        ({"properties": {}}, 'type: "object"'),
        (
            {
                "$schema": "https://json-schema.org/draft/2019-09/schema",
                "type": "object",
            },
            "only the JSON Schema 2020-12 dialect",
        ),
        (
            {
                "type": "object",
                "required": "not-an-array",
            },
            "not valid JSON Schema 2020-12",
        ),
        (
            {
                "type": "object",
                "properties": {"value": {"$ref": "#/$defs/missing"}},
            },
            "missing JSON Pointer",
        ),
    ],
)
def test_invalid_server_owned_schema_is_rejected(
    schema: dict,
    expected: str,
):
    with pytest.raises(ToolSchemaDefinitionError, match=expected):
        ToolSchemaGuard().compile_tool(_advanced_tool(input_schema=schema))


@pytest.mark.parametrize(
    ("keyword", "reference"),
    [
        ("$ref", "https://example.invalid/schema.json"),
        ("$ref", "file:///etc/passwd"),
        ("$ref", "other-schema.json#/$defs/value"),
        ("$dynamicRef", "https://example.invalid/schema.json#value"),
    ],
)
def test_external_references_are_rejected_before_network_access(
    keyword: str,
    reference: str,
):
    schema = {
        "type": "object",
        "properties": {
            "value": {
                keyword: reference,
            }
        },
    }
    with (
        patch("urllib.request.urlopen") as urlopen,
        pytest.raises(ToolSchemaDefinitionError, match="same-document"),
    ):
        ToolSchemaGuard().compile_tool(_advanced_tool(input_schema=schema))
    urlopen.assert_not_called()


def test_recursive_local_reference_is_rejected_by_bounded_policy():
    schema = {
        "type": "object",
        "$defs": {
            "node": {
                "type": "object",
                "properties": {
                    "next": {"$ref": "#/$defs/node"},
                },
            }
        },
        "properties": {
            "root": {"$ref": "#/$defs/node"},
        },
    }
    with pytest.raises(ToolSchemaDefinitionError, match="recursive local"):
        ToolSchemaGuard().compile_tool(_advanced_tool(input_schema=schema))


def test_schema_and_instance_complexity_limits_fail_closed():
    branch_limited = ToolSchemaGuard(
        SchemaLimits(max_combinator_branches=1)
    )
    with pytest.raises(ToolSchemaDefinitionError, match="combinator branches"):
        branch_limited.compile_tool(_advanced_tool())

    instance_limited = ToolSchemaGuard(
        SchemaLimits(
            max_instance_bytes=64,
            max_instance_nodes=8,
            max_instance_depth=3,
            max_instance_string_length=8,
        )
    ).compile_tool(
        Tool(
            name="bounded",
            input_schema={
                "type": "object",
                "properties": {
                    "value": {"type": "string"},
                },
            },
        )
    )
    with pytest.raises(ToolArgumentsValidationError) as oversized:
        instance_limited.validate_arguments({"value": "x" * 9})
    assert oversized.value.violations[0].keyword == "maxStringLength"


def test_output_schema_requires_structured_content():
    compiled = ToolSchemaGuard().compile_tool(_advanced_tool())
    with pytest.raises(ToolOutputValidationError, match="no structured content"):
        compiled.validate_output(None)


def test_limits_for_result_bytes_follow_the_result_ceiling():
    base = DEFAULT_SCHEMA_LIMITS
    ceiling = 16 * 1024 * 1024
    limits = SchemaLimits.for_result_bytes(ceiling)

    assert limits.max_instance_bytes == ceiling + base.max_instance_bytes
    assert limits.max_instance_nodes == limits.max_instance_bytes // 2
    assert limits.max_instance_string_length == ceiling
    assert limits.max_instance_depth == base.max_instance_depth
    assert limits.max_schema_bytes == base.max_schema_bytes

    # Nothing shrinks below the base, whatever the ceiling.
    small = SchemaLimits.for_result_bytes(0)
    assert small.max_instance_bytes == base.max_instance_bytes
    assert small.max_instance_nodes == base.max_instance_bytes // 2
    assert small.max_instance_string_length == base.max_instance_string_length

    custom = SchemaLimits.for_result_bytes(
        1024, base=SchemaLimits(max_instance_bytes=4096, max_instance_nodes=4)
    )
    assert custom.max_instance_bytes == 4096 + 1024
    assert custom.max_instance_nodes == (4096 + 1024) // 2


def test_default_guard_refuses_a_result_inside_the_default_result_ceiling():
    tool = Tool(
        name="rows",
        description="Rows under the default result ceiling.",
        input_schema={"type": "object"},
        output_schema={"type": "object"},
    )
    # 6,000 small rows: far below DEFAULT_MAX_RESULT_BYTES, above the default
    # node budget; one 300 KiB cell: below the ceiling, above the string budget.
    payloads = [
        {"rows": [{"n": index} for index in range(6_000)]},
        {"cell": "x" * 300_000},
    ]
    default_schema = ToolSchemaGuard().compile_tool(tool)
    derived_schema = ToolSchemaGuard(
        SchemaLimits.for_result_bytes(DEFAULT_MAX_RESULT_BYTES)
    ).compile_tool(tool)

    for payload in payloads:
        with pytest.raises(ToolOutputValidationError, match="exceeds output limits"):
            default_schema.validate_output(payload)
        derived_schema.validate_output(payload)

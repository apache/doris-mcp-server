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

"""Security and strict-validation evidence for the pinned Ossie loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from doris_mcp_server.semantic.loader import (
    OssieRegistryLoader,
    SemanticConfigurationError,
    SemanticLoaderLimits,
)
from doris_mcp_server.semantic.models import (
    OSSIE_SCHEMA_SHA256,
    OSSIE_SPEC_COMMIT,
    OSSIE_SPEC_VERSION,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _model_yaml(
    *,
    metric_expression: str = "SUM(orders.amount)",
    source: str = "sales.orders",
    extra_field_dialect: str = "",
) -> str:
    return f"""
version: "0.2.0.dev0"
semantic_model:
  - name: retail
    description: Governed retail semantics
    datasets:
      - name: orders
        source: {source}
        primary_key: [order_id]
        fields:
          - name: order_id
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: order_id
                {extra_field_dialect}
            datatype: Integer
          - name: amount
            expression:
              dialects:
                - dialect: ANSI_SQL
                  expression: amount
            datatype: Decimal
            ai_context:
              synonyms: [revenue]
    metrics:
      - name: total_sales
        expression:
          dialects:
            - dialect: ANSI_SQL
              expression: {metric_expression}
        datatype: Decimal
""".strip()


def _binding_yaml(
    model_file: str = "retail.yaml",
    *,
    model_ref: str = "retail/main",
) -> str:
    return f"""
api_version: doris-mcp.apache.org/ossie-binding/v1alpha1
model_sources:
  {model_ref}:
    model_file: {model_file}
    model_name: retail
    namespace: commerce
    tags: [certified]
    route_profile: global
    datasets:
      orders:
        catalog: internal
        database: sales
        object: orders
        kind: table
""".strip()


def _loader(tmp_path: Path) -> OssieRegistryLoader:
    return OssieRegistryLoader(
        model_directory=str(tmp_path),
        binding_manifest=str(tmp_path / "bindings.yaml"),
    )


def test_loads_exact_model_and_pinned_schema(tmp_path: Path) -> None:
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")

    registry = _loader(tmp_path).load()

    assert OSSIE_SPEC_VERSION == "0.2.0.dev0"
    assert OSSIE_SPEC_COMMIT == "9ffc3be3886e82fddc9bbf28722440864644d371"
    assert OSSIE_SCHEMA_SHA256 == (
        "8ce9f82aa92080265f9ae119e31cda5bef062f489674d3c467245c2d4c5ff264"
    )
    model = registry.get("retail/main")
    assert model is not None
    assert model.namespace == "commerce"
    assert model.tags == ("certified",)
    assert model.route_profile == "global"
    assert model.bindings[0].logical_key == (
        "internal",
        "sales",
        "orders",
        "table",
    )
    assert len(model.revision) == 16
    assert model.binding_id.startswith("binding.")


def test_loads_exact_model_ref_with_revision_metadata(tmp_path: Path) -> None:
    model_ref = "sales/commerce@2026.08.05+4f91c2a"
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(
        _binding_yaml(model_ref=model_ref),
        encoding="utf-8",
    )

    registry = _loader(tmp_path).load()

    assert registry.get(model_ref) is not None


@pytest.mark.parametrize(
    "model_ref",
    (
        "+sales/commerce@2026.08.05",
        "sales/commerce@2026.08.05+",
        "sales/commerce@2026.08.05++4f91c2a",
    ),
)
def test_rejects_malformed_revision_metadata(
    tmp_path: Path,
    model_ref: str,
) -> None:
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(
        _binding_yaml(model_ref=model_ref),
        encoding="utf-8",
    )

    with pytest.raises(SemanticConfigurationError) as failure:
        _loader(tmp_path).load()

    assert failure.value.reason_code == "OSSIE_BINDING_INVALID"


@pytest.mark.parametrize(
    ("model_text", "reason_code"),
    [
        (
            _model_yaml(metric_expression="SELECT SUM(orders.amount) FROM orders"),
            "OSSIE_EXPRESSION_UNSAFE",
        ),
        (
            _model_yaml(metric_expression="SUM(missing.amount)"),
            "SEMANTIC_DEPENDENCY_UNRESOLVED",
        ),
        (
            _model_yaml(source="SELECT * FROM sales.orders"),
            "OSSIE_QUERY_SOURCE_UNSUPPORTED",
        ),
        (
            _model_yaml(
                extra_field_dialect=(
                    "- dialect: ANSI_SQL\n"
                    "                  expression: order_id"
                )
            ),
            "OSSIE_DUPLICATE_DIALECT",
        ),
    ],
)
def test_rejects_unsafe_or_unresolved_models(
    tmp_path: Path,
    model_text: str,
    reason_code: str,
) -> None:
    (tmp_path / "retail.yaml").write_text(model_text, encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")

    with pytest.raises(SemanticConfigurationError) as failure:
        _loader(tmp_path).load()

    assert failure.value.reason_code == reason_code


def test_rejects_duplicate_keys_and_multiple_documents(tmp_path: Path) -> None:
    duplicate = _model_yaml().replace(
        'version: "0.2.0.dev0"',
        'version: "0.2.0.dev0"\nversion: "0.2.0.dev0"',
    )
    (tmp_path / "retail.yaml").write_text(duplicate, encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")
    with pytest.raises(SemanticConfigurationError) as duplicate_failure:
        _loader(tmp_path).load()
    assert duplicate_failure.value.reason_code == "OSSIE_DUPLICATE_KEY"

    (tmp_path / "retail.yaml").write_text(
        _model_yaml() + "\n---\n" + _model_yaml(),
        encoding="utf-8",
    )
    with pytest.raises(SemanticConfigurationError) as document_failure:
        _loader(tmp_path).load()
    assert (
        document_failure.value.reason_code
        == "OSSIE_MULTIDOCUMENT_YAML_REJECTED"
    )


def test_rejects_path_escape_symlink_and_alias_limit(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-ossie.yaml"
    outside.write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(
        _binding_yaml(str(outside)),
        encoding="utf-8",
    )
    with pytest.raises(SemanticConfigurationError) as escape_failure:
        _loader(tmp_path).load()
    assert (
        escape_failure.value.reason_code
        == "OSSIE_MODEL_PATH_OUTSIDE_ROOT"
    )

    linked = tmp_path / "linked.yaml"
    linked.symlink_to(outside)
    (tmp_path / "bindings.yaml").write_text(
        _binding_yaml("linked.yaml"),
        encoding="utf-8",
    )
    with pytest.raises(SemanticConfigurationError) as symlink_failure:
        _loader(tmp_path).load()
    assert (
        symlink_failure.value.reason_code
        == "OSSIE_MODEL_PATH_OUTSIDE_ROOT"
    )

    alias_document = """
version: "0.2.0.dev0"
semantic_model:
  - &model
    name: retail
    datasets:
      - name: orders
        source: sales.orders
        fields: []
  - *model
""".strip()
    (tmp_path / "retail.yaml").write_text(alias_document, encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")
    with pytest.raises(SemanticConfigurationError) as alias_failure:
        OssieRegistryLoader(
            model_directory=str(tmp_path),
            binding_manifest=str(tmp_path / "bindings.yaml"),
            limits=SemanticLoaderLimits(max_aliases=0),
        ).load()
    assert alias_failure.value.reason_code == "OSSIE_ALIAS_LIMIT_EXCEEDED"


def test_requires_exact_binding_coverage(tmp_path: Path) -> None:
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(
        _binding_yaml().replace(
            "    datasets:\n      orders:",
            "    datasets:\n      unexpected:",
        ),
        encoding="utf-8",
    )

    with pytest.raises(SemanticConfigurationError) as failure:
        _loader(tmp_path).load()

    assert failure.value.reason_code == "OSSIE_BINDING_INVALID"


def test_rejects_unsupported_version_custom_tag_and_nonfinite_value(
    tmp_path: Path,
) -> None:
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")

    (tmp_path / "retail.yaml").write_text(
        _model_yaml().replace('version: "0.2.0.dev0"', 'version: "1.0.0"'),
        encoding="utf-8",
    )
    with pytest.raises(SemanticConfigurationError) as version_failure:
        _loader(tmp_path).load()
    assert version_failure.value.reason_code == "OSSIE_VERSION_UNSUPPORTED"

    (tmp_path / "retail.yaml").write_text(
        _model_yaml().replace(
            "description: Governed retail semantics",
            "description: !python/object/apply:os.system ['id']",
        ),
        encoding="utf-8",
    )
    with pytest.raises(SemanticConfigurationError) as tag_failure:
        _loader(tmp_path).load()
    assert tag_failure.value.reason_code == "OSSIE_MODEL_INVALID"

    (tmp_path / "retail.yaml").write_text(
        _model_yaml().replace(
            "description: Governed retail semantics",
            "description: .nan",
        ),
        encoding="utf-8",
    )
    with pytest.raises(SemanticConfigurationError) as number_failure:
        _loader(tmp_path).load()
    assert (
        number_failure.value.reason_code
        == "OSSIE_NONFINITE_NUMBER_REJECTED"
    )


def test_rejects_size_and_nesting_limits(tmp_path: Path) -> None:
    (tmp_path / "retail.yaml").write_text(_model_yaml(), encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")

    with pytest.raises(SemanticConfigurationError) as size_failure:
        OssieRegistryLoader(
            model_directory=str(tmp_path),
            binding_manifest=str(tmp_path / "bindings.yaml"),
            limits=SemanticLoaderLimits(max_file_bytes=32),
        ).load()
    assert (
        size_failure.value.reason_code
        == "OSSIE_BINDING_FILE_SIZE_INVALID"
    )

    with pytest.raises(SemanticConfigurationError) as depth_failure:
        OssieRegistryLoader(
            model_directory=str(tmp_path),
            binding_manifest=str(tmp_path / "bindings.yaml"),
            limits=SemanticLoaderLimits(max_depth=2),
        ).load()
    assert depth_failure.value.reason_code == "OSSIE_NESTING_LIMIT_EXCEEDED"


def test_multiple_models_require_exact_model_name(tmp_path: Path) -> None:
    dataset = {
        "name": "orders",
        "source": "sales.orders",
        "fields": [
            {
                "name": "order_id",
                "expression": {
                    "dialects": [
                        {
                            "dialect": "ANSI_SQL",
                            "expression": "order_id",
                        }
                    ]
                },
                "datatype": "Integer",
            }
        ],
    }
    document = {
        "version": "0.2.0.dev0",
        "semantic_model": [
            {"name": "retail", "datasets": [dataset]},
            {"name": "wholesale", "datasets": [dataset]},
        ],
    }
    (tmp_path / "retail.json").write_text(
        json.dumps(document),
        encoding="utf-8",
    )
    binding = _binding_yaml("retail.json").replace(
        "    model_name: retail\n",
        "",
    )
    (tmp_path / "bindings.yaml").write_text(binding, encoding="utf-8")

    with pytest.raises(SemanticConfigurationError) as failure:
        _loader(tmp_path).load()

    assert failure.value.reason_code == "SEMANTIC_MODEL_AMBIGUOUS"


def test_custom_extensions_are_validated_but_never_enter_runtime_ir(
    tmp_path: Path,
) -> None:
    model = _model_yaml().replace(
        "    description: Governed retail semantics",
        (
            "    description: Governed retail semantics\n"
            "    custom_extensions:\n"
            "      - vendor_name: TEST\n"
            '        data: \'{"execute":"DROP TABLE orders"}\''
        ),
    )
    (tmp_path / "retail.yaml").write_text(model, encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")

    registry = _loader(tmp_path).load()

    loaded = registry.get("retail/main")
    assert loaded is not None
    assert "DROP TABLE" not in repr(loaded)


@pytest.mark.parametrize(
    "model",
    [
        _model_yaml().replace("name: orders", "name: sales.orders", 1),
        _model_yaml().replace("name: amount", "name: order.amount", 1),
    ],
)
def test_rejects_ambiguous_dimension_selector_components(
    tmp_path: Path,
    model: str,
) -> None:
    (tmp_path / "retail.yaml").write_text(model, encoding="utf-8")
    (tmp_path / "bindings.yaml").write_text(_binding_yaml(), encoding="utf-8")

    with pytest.raises(SemanticConfigurationError) as failure:
        _loader(tmp_path).load()

    assert failure.value.reason_code == "OSSIE_MODEL_INVALID"


def test_checked_in_ossie_example_is_loadable() -> None:
    example_root = PROJECT_ROOT / "examples" / "ossie"

    registry = OssieRegistryLoader(
        model_directory=str(example_root),
        binding_manifest=str(example_root / "bindings.example.yaml"),
    ).load()

    model = registry.get("retail/main")
    assert model is not None
    assert model.name == "retail"
    assert model.route_profile == "global"

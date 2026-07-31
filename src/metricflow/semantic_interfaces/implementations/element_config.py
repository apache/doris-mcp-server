from __future__ import annotations

from typing import Any, Dict

from metricflow.msi_pydantic_shim import Field
from typing_extensions import override

from metricflow.semantic_interfaces.implementations.base import HashableBaseModel
from metricflow.semantic_interfaces.protocols.meta import SemanticLayerElementConfig
from metricflow.semantic_interfaces.protocols.protocol_hint import ProtocolHint


class PydanticSemanticLayerElementConfig(HashableBaseModel, ProtocolHint[SemanticLayerElementConfig]):
    """PydanticDimension config."""

    @override
    def _implements_protocol(self) -> SemanticLayerElementConfig:  # noqa: D102
        return self

    meta: Dict[str, Any] = Field(default_factory=dict)  # type: ignore[misc]

from __future__ import annotations

from typing import List, Optional

from importlib_metadata import PackageNotFoundError, version
from metricflow.msi_pydantic_shim import Field, validator
from typing_extensions import override

from metricflow.semantic_interfaces.implementations.base import (
    HashableBaseModel,
    ModelWithMetadataParsing,
)
from metricflow.semantic_interfaces.implementations.metadata import PydanticMetadata
from metricflow.semantic_interfaces.implementations.semantic_version import (
    UNKNOWN_VERSION_SENTINEL,
    PydanticSemanticVersion,
)
from metricflow.semantic_interfaces.implementations.time_spine import PydanticTimeSpine
from metricflow.semantic_interfaces.implementations.time_spine_table_configuration import (
    PydanticTimeSpineTableConfiguration,
)
from metricflow.semantic_interfaces.protocols import ProtocolHint
from metricflow.semantic_interfaces.protocols.project_configuration import ProjectConfiguration


class PydanticProjectConfiguration(HashableBaseModel, ModelWithMetadataParsing, ProtocolHint[ProjectConfiguration]):
    """Pydantic implementation of ProjectConfiguration."""

    @override
    def _implements_protocol(self) -> ProjectConfiguration:
        return self

    time_spine_table_configurations: List[PydanticTimeSpineTableConfiguration] = Field(default_factory=list)
    metadata: Optional[PydanticMetadata] = None
    dsi_package_version: PydanticSemanticVersion = UNKNOWN_VERSION_SENTINEL
    time_spines: List[PydanticTimeSpine] = Field(default_factory=list)

    @validator("dsi_package_version", always=True)
    @classmethod
    def __create_default_dsi_package_version(cls, value: Optional[PydanticSemanticVersion]) -> PydanticSemanticVersion:
        """Returns the version of the dbt_semantic_interfaces package that generated this manifest."""
        if value is not None and value != UNKNOWN_VERSION_SENTINEL:
            return value
        try:
            return PydanticSemanticVersion.create_from_string(version("dbt_semantic_interfaces"))
        except PackageNotFoundError:
            pass
        # Fallback: this project is distributed as "doris-new-mcp" (see pyproject.toml).
        # It may not be installed as a dist (e.g. running from source), so keep 0.0.0 as last resort.
        try:
            return PydanticSemanticVersion.create_from_string(version("doris-new-mcp"))
        except PackageNotFoundError:
            return PydanticSemanticVersion.create_from_string("0.0.0")

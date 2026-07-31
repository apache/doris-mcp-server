from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from metricflow.semantic_interfaces.dataclass_serialization import SerializableDataclass
from metricflow.semantics.specs.dimension_spec import DimensionSpec
from metricflow.semantics.specs.time_dimension_spec import TimeDimensionSpec


@dataclass(frozen=True)
class PartitionSpecSet(SerializableDataclass):
    """Grouping of the linkable specs."""

    dimension_specs: Tuple[DimensionSpec, ...] = ()
    time_dimension_specs: Tuple[TimeDimensionSpec, ...] = ()

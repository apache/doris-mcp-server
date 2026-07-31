"""Pydantic v2 compatibility (uses v1 API via pydantic.v1)."""
from __future__ import annotations

from pydantic.v1 import (  # type: ignore
    BaseModel,
    Extra,
    Field,
    create_model,
    root_validator,
    validator,
)

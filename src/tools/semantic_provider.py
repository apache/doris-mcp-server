"""Semantic provider tools: provider-agnostic model lifecycle + runtime queries.

These functions implement the upload -> validate -> parse -> compile ->
artifact -> generate SQL -> execute pipeline on top of the provider SPI
(src/providers). They are wired to MCP tools in server.py and stay
transport-agnostic (plain dicts in, JSON strings out).
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from core.connection import ConnectionPool
from core.response import ErrorCode, error_response, success_response
from core.sql_validator import validate_readonly
from providers.base import Filter, ModelSource, ProviderError, QueryRequest
from providers.registry import (
    detect_provider,
    get_provider,
    get_runtime,
    list_providers,
)
from store.artifacts import ArtifactStore


def _artifact_store(workspace_dir: Path) -> ArtifactStore:
    return ArtifactStore(workspace_dir)


def _parse_filters(raw_filters: list[dict[str, Any]] | None) -> list[Filter]:
    filters: list[Filter] = []
    for f in raw_filters or []:
        try:
            filters.append(
                Filter(
                    dimension=str(f["dimension"]),
                    operator=str(f.get("operator", "eq")).lower(),
                    value=f.get("value"),
                )
            )
        except (KeyError, AttributeError, TypeError) as e:
            raise ProviderError(
                f"Invalid filter {f!r}: expected {{'dimension', 'operator', 'value'}} ({e})"
            ) from e
    return filters


def _build_query_request(
    metrics: list[str],
    dimensions: list[str] | None,
    filters: list[dict[str, Any]] | None,
    order_by: list[str] | None,
    limit: int | None,
) -> QueryRequest:
    if not metrics:
        raise ProviderError("At least one metric is required")
    return QueryRequest(
        metrics=[str(m) for m in metrics],
        dimensions=[str(d) for d in (dimensions or [])],
        filters=_parse_filters(filters),
        order_by=[str(o) for o in (order_by or [])],
        limit=int(limit) if limit else None,
    )


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


async def list_semantic_providers() -> str:
    """List registered semantic model providers."""
    try:
        return success_response(list_providers())
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def compile_semantic_model(
    workspace_dir: Path,
    filename: str,
    content: str,
    provider: str | None = None,
) -> str:
    """Validate + parse + compile an uploaded model file and store the artifact.

    provider: explicit provider name, or empty for auto-detection.
    """
    try:
        source = ModelSource(filename=filename, content=content)
        if provider:
            chosen = get_provider(provider)
            confidence = chosen.detect(source)
        else:
            name, confidence = detect_provider(source)
            chosen = get_provider(name)

        problems = chosen.validate(source)
        if problems:
            return error_response(
                ErrorCode.VALIDATION_ERROR,
                f"Validation failed for provider '{chosen.name}'",
                {"problems": problems},
            )

        artifact = chosen.build(source)
        store = _artifact_store(workspace_dir)
        artifact_id = store.save(artifact, source_filename=filename)
        return success_response(
            {
                "artifact_id": artifact_id,
                "provider": chosen.name,
                "detect_confidence": round(confidence, 2),
                "name": artifact.name,
                "source_digest": artifact.source_digest,
                "metrics": [m.name for m in chosen.parse(source).metrics],
                "dimensions": [d.name for d in chosen.parse(source).dimensions],
            }
        )
    except ProviderError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e))
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def list_semantic_artifacts(workspace_dir: Path) -> str:
    """List compiled artifacts stored for a workspace."""
    try:
        return success_response(_artifact_store(workspace_dir).list())
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def delete_semantic_artifact(workspace_dir: Path, artifact_id: str) -> str:
    """Delete a compiled artifact."""
    try:
        if not _artifact_store(workspace_dir).delete(artifact_id):
            return error_response(ErrorCode.VALIDATION_ERROR, f"Artifact not found: '{artifact_id}'")
        return success_response({"deleted": artifact_id})
    except ProviderError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e))
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def get_semantic_metadata(
    workspace_dir: Path,
    artifact_id: str,
    metric: str | None = None,
) -> str:
    """Metric/dimension discovery over a compiled artifact."""
    try:
        artifact = _artifact_store(workspace_dir).load(artifact_id)
        runtime = get_runtime(artifact.provider)
        metrics = runtime.get_metrics(artifact)
        dims = runtime.get_dimensions(artifact, metric or None)
        return success_response(
            {
                "artifact_id": artifact_id,
                "provider": artifact.provider,
                "metrics": [m.__dict__ for m in metrics],
                "dimensions": [d.__dict__ for d in dims],
                "filtered_by_metric": metric or None,
            }
        )
    except ProviderError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e))
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def generate_semantic_sql(
    workspace_dir: Path,
    artifact_id: str,
    metrics: list[str],
    dimensions: list[str] | None = None,
    filters: list[dict[str, Any]] | None = None,
    order_by: list[str] | None = None,
    limit: int | None = None,
) -> str:
    """Generate (but do not execute) Doris SQL for a semantic query."""
    try:
        artifact = _artifact_store(workspace_dir).load(artifact_id)
        runtime = get_runtime(artifact.provider)
        request = _build_query_request(metrics, dimensions, filters, order_by, limit)
        sql = runtime.generate_sql(artifact, request)
        return success_response(
            {"sql": sql},
            {"artifact_id": artifact_id, "provider": artifact.provider},
        )
    except ProviderError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e))
    except Exception as e:
        return error_response(ErrorCode.INTERNAL_ERROR, str(e))


async def query_semantic_model(
    workspace_dir: Path,
    pool: ConnectionPool,
    artifact_id: str,
    metrics: list[str],
    dimensions: list[str] | None = None,
    filters: list[dict[str, Any]] | None = None,
    order_by: list[str] | None = None,
    limit: int | None = None,
    database: str | None = None,
    max_rows: int | None = None,
) -> str:
    """Generate Doris SQL via the provider runtime, then execute it."""
    try:
        artifact = _artifact_store(workspace_dir).load(artifact_id)
        runtime = get_runtime(artifact.provider)
        request = _build_query_request(metrics, dimensions, filters, order_by, limit)
        sql = runtime.generate_sql(artifact, request)

        # Same read-only policy as execute_query / query_metric.
        is_valid, err_msg = validate_readonly(sql)
        if not is_valid:
            return error_response(ErrorCode.INVALID_SQL, err_msg)

        start = time.monotonic()
        rows, columns = await pool.execute(sql, database=database, max_rows=max_rows)
        duration_ms = (time.monotonic() - start) * 1000

        return success_response(
            {"columns": columns, "rows": rows, "sql": sql},
            {
                "duration_ms": round(duration_ms, 2),
                "row_count": len(rows),
                "artifact_id": artifact_id,
                "provider": artifact.provider,
            },
        )
    except ProviderError as e:
        return error_response(ErrorCode.VALIDATION_ERROR, str(e))
    except TimeoutError:
        return error_response(ErrorCode.QUERY_TIMEOUT, "Semantic query timed out")
    except Exception as e:
        return error_response(ErrorCode.CONNECTION_ERROR, str(e))

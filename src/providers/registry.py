"""Provider registry and format auto-detection.

Providers register themselves here; uploads are routed to the right provider
either explicitly (by name) or via confidence-based content sniffing.
"""

from __future__ import annotations

import logging

from providers.base import ModelSource, ProviderError, SemanticProvider, SemanticRuntime

logger = logging.getLogger(__name__)

_providers: dict[str, SemanticProvider] = {}
_runtimes: dict[str, SemanticRuntime] = {}

#: Minimum detection confidence accepted for auto-routing an upload.
DETECT_THRESHOLD = 0.5


def register_provider(provider: SemanticProvider, runtime: SemanticRuntime) -> None:
    """Register a provider plugin (build-time + runtime halves)."""
    if not provider.name:
        raise ProviderError("Provider must have a non-empty name")
    if runtime.name != provider.name:
        raise ProviderError(
            f"Provider/runtime name mismatch: '{provider.name}' vs '{runtime.name}'"
        )
    _providers[provider.name] = provider
    _runtimes[provider.name] = runtime
    logger.debug("Registered semantic provider: %s", provider.name)


def get_provider(name: str) -> SemanticProvider:
    try:
        return _providers[name]
    except KeyError:
        raise ProviderError(
            f"Unknown semantic provider '{name}'. Available: {sorted(_providers)}"
        ) from None


def get_runtime(name: str) -> SemanticRuntime:
    try:
        return _runtimes[name]
    except KeyError:
        raise ProviderError(
            f"No runtime registered for provider '{name}'. Available: {sorted(_runtimes)}"
        ) from None


def list_providers() -> list[dict[str, object]]:
    """Metadata about all registered providers (for the list tool)."""
    return [
        {
            "name": p.name,
            "description": (p.__doc__ or "").strip().splitlines()[0] if p.__doc__ else "",
        }
        for p in sorted(_providers.values(), key=lambda p: p.name)
    ]


def detect_provider(source: ModelSource) -> tuple[str, float]:
    """Auto-detect which provider owns ``source``.

    Returns (provider_name, confidence). Raises ProviderError when no
    provider reaches DETECT_THRESHOLD.
    """
    best_name, best_score = "", 0.0
    scores: dict[str, float] = {}
    for name, provider in _providers.items():
        try:
            score = provider.detect(source)
        except Exception as e:  # a broken detector must not break routing
            logger.warning("Provider %s detect() failed: %s", name, e)
            score = 0.0
        scores[name] = score
        if score > best_score:
            best_name, best_score = name, score
    if best_score < DETECT_THRESHOLD:
        raise ProviderError(
            f"Could not detect semantic model format of '{source.filename}' "
            f"(best score {best_score:.2f}, threshold {DETECT_THRESHOLD}; scores={scores})"
        )
    return best_name, best_score


def _register_builtin() -> None:
    """Register the built-in providers shipped with the server.

    Each import is guarded: a provider with missing optional dependencies
    (or one not yet installed) must not prevent the others from loading.
    """
    from providers.cube.provider import CubeProvider, CubeRuntime

    register_provider(CubeProvider(), CubeRuntime())

    try:
        from providers.lookml.provider import LookmlProvider, LookmlRuntime

        register_provider(LookmlProvider(), LookmlRuntime())
    except ImportError as e:  # lkml is an optional dependency
        logger.info("LookML provider unavailable: %s", e)

    from providers.metricflow_adapter.provider import (
        MetricFlowProviderAdapter,
        MetricFlowRuntimeAdapter,
    )

    register_provider(MetricFlowProviderAdapter(), MetricFlowRuntimeAdapter())


_register_builtin()

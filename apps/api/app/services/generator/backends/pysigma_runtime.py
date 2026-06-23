"""In-process pySigma backend.

Runs pySigma directly (no subprocess) for the targets whose backend
packages are installed. Falls back gracefully — if a backend package is
missing, a rule cannot be parsed, or pySigma raises a feature error, this
returns ``(None, warnings)`` and the engine drops to the builtin AST
compiler.

Backend/format/pipeline wiring is declarative in ``_REGISTRY`` so adding a
SIEM in a later phase is a data change, not new control flow.
"""

from __future__ import annotations

import importlib
import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import yaml

from app.services.generator.profiles import profile_base_selector
from app.services.generator.warnings import GeneratorWarning, emit

# Stable namespace for deriving UUIDs from non-UUID rule ids.
_TF_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_DNS, "threatforge.detectionforge")


def _is_uuid(value: Any) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, AttributeError, TypeError):
        return False


def _sanitize_for_pysigma(raw_yaml: str) -> str:
    """Make a rule acceptable to pySigma's strict schema.

    pySigma requires ``id`` to be a UUID. Many curated/custom rules use
    short ids (e.g. ``df-local-0001``). Replace a non-UUID id with a
    deterministic UUID derived from it so conversion succeeds while the
    mapping stays stable across runs.
    """
    try:
        data = yaml.safe_load(raw_yaml)
    except Exception:
        return raw_yaml
    if not isinstance(data, dict):
        return raw_yaml
    rule_id = data.get("id")
    if rule_id is not None and not _is_uuid(rule_id):
        data["id"] = str(uuid.uuid5(_TF_NAMESPACE, str(rule_id)))
        try:
            return yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
        except Exception:
            return raw_yaml
    return raw_yaml


@dataclass
class BackendVariant:
    """One concrete (backend class, pySigma output format) pairing."""

    module: str
    cls: str
    pysigma_format: str


@dataclass
class TargetSpec:
    """How to drive pySigma for one of our targets."""

    # our_output_format -> BackendVariant. "*" is the default for the target.
    variants: dict[str, BackendVariant]
    pipeline_module: str | None = None
    pipeline_func: str | None = None
    # If True, prepend the profile base selector to the produced query
    # (Splunk default/spl lacks an index; pySigma only emits predicates).
    prepend_profile_base: bool = False


_REGISTRY: dict[str, TargetSpec] = {
    "splunk": TargetSpec(
        variants={
            "*": BackendVariant("sigma.backends.splunk", "SplunkBackend", "default"),
            "spl": BackendVariant("sigma.backends.splunk", "SplunkBackend", "default"),
            "default": BackendVariant("sigma.backends.splunk", "SplunkBackend", "default"),
            "savedsearches": BackendVariant("sigma.backends.splunk", "SplunkBackend", "savedsearches"),
            "savedsearches_conf": BackendVariant("sigma.backends.splunk", "SplunkBackend", "savedsearches"),
            "datamodel_tstats": BackendVariant("sigma.backends.splunk", "SplunkBackend", "data_model"),
        },
        pipeline_module="sigma.pipelines.splunk",
        pipeline_func="splunk_windows_pipeline",
        prepend_profile_base=True,
    ),
    "sentinel": TargetSpec(
        variants={
            "*": BackendVariant("sigma.backends.kusto", "KustoBackend", "default"),
            "kql": BackendVariant("sigma.backends.kusto", "KustoBackend", "default"),
            "default": BackendVariant("sigma.backends.kusto", "KustoBackend", "default"),
        },
        pipeline_module="sigma.pipelines.microsoftxdr",
        pipeline_func="microsoft_xdr_pipeline",
    ),
    "elastic": TargetSpec(
        variants={
            "lucene": BackendVariant("sigma.backends.elasticsearch", "LuceneBackend", "default"),
            "eql": BackendVariant("sigma.backends.elasticsearch", "EqlBackend", "default"),
            "esql": BackendVariant("sigma.backends.elasticsearch", "ESQLBackend", "default"),
            "detection_rule_ndjson": BackendVariant("sigma.backends.elasticsearch", "LuceneBackend", "siem_rule_ndjson"),
            # NOTE: "kql"/"default" deliberately omitted — pySigma emits
            # Lucene, not Kibana KQL; the builtin compiler renders KQL.
        },
        pipeline_module="sigma.pipelines.elasticsearch",
        pipeline_func="ecs_windows",
    ),
    "opensearch": TargetSpec(
        variants={
            "lucene": BackendVariant("sigma.backends.opensearch", "OpensearchLuceneBackend", "default"),
            "dsl": BackendVariant("sigma.backends.opensearch", "OpensearchLuceneBackend", "dsl_lucene"),
            "detection_rule_ndjson": BackendVariant("sigma.backends.opensearch", "OpensearchLuceneBackend", "monitor_rule"),
        },
        pipeline_module="sigma.pipelines.elasticsearch",
        pipeline_func="ecs_windows",
    ),
}


@lru_cache(maxsize=64)
def _load_attr(module: str, attr: str) -> Any | None:
    try:
        mod = importlib.import_module(module)
    except Exception:
        return None
    return getattr(mod, attr, None)


def _select_variant(target: str, output_format: str) -> BackendVariant | None:
    spec = _REGISTRY.get(target)
    if not spec:
        return None
    return spec.variants.get(output_format) or spec.variants.get("*")


def supports(target: str, output_format: str = "*") -> bool:
    """True if a pySigma backend for (target, output_format) is importable."""
    variant = _select_variant(target, output_format)
    if not variant:
        return False
    return _load_attr(variant.module, variant.cls) is not None


def _build_pipeline(spec: TargetSpec):
    if not spec.pipeline_module or not spec.pipeline_func:
        return None
    func = _load_attr(spec.pipeline_module, spec.pipeline_func)
    if func is None:
        return None
    try:
        return func()
    except Exception:
        return None


def _normalize_result(result: Any) -> str:
    if isinstance(result, list):
        return "\n\n".join(str(item) for item in result if str(item).strip())
    return str(result)


def convert(
    raw_yaml: str,
    target: str,
    *,
    profile: str | None,
    output_format: str,
) -> tuple[str | None, list[GeneratorWarning]]:
    warnings: list[GeneratorWarning] = []
    spec = _REGISTRY.get(target)
    variant = _select_variant(target, output_format)
    if not spec or not variant:
        return None, [
            emit(
                "BACKEND_UNAVAILABLE",
                message=f"No in-process pySigma backend for {target}/{output_format}",
                target=target,
                profile=profile,
                output_format=output_format,
            )
        ]

    backend_cls = _load_attr(variant.module, variant.cls)
    if backend_cls is None:
        return None, [
            emit(
                "BACKEND_UNAVAILABLE",
                message=f"pySigma backend package for {target} is not installed",
                target=target,
                profile=profile,
                output_format=output_format,
            )
        ]

    try:
        from sigma.collection import SigmaCollection
    except Exception:
        return None, [
            emit("BACKEND_UNAVAILABLE", message="pySigma core not installed", target=target, output_format=output_format)
        ]

    try:
        collection = SigmaCollection.from_yaml(_sanitize_for_pysigma(raw_yaml))
    except Exception as exc:
        return None, [
            emit(
                "BACKEND_UNAVAILABLE",
                message=f"pySigma could not parse rule: {type(exc).__name__}: {str(exc)[:200]}",
                target=target,
                profile=profile,
                output_format=output_format,
            )
        ]

    pipeline = _build_pipeline(spec)
    try:
        backend = backend_cls(processing_pipeline=pipeline) if pipeline is not None else backend_cls()
    except Exception:
        try:
            backend = backend_cls()
        except Exception as exc:
            return None, [
                emit(
                    "BACKEND_UNAVAILABLE",
                    message=f"Could not instantiate pySigma backend: {type(exc).__name__}",
                    target=target,
                    output_format=output_format,
                )
            ]

    try:
        result = backend.convert(collection, output_format=variant.pysigma_format)
    except TypeError:
        # Some backends/formats don't accept output_format kwarg.
        try:
            result = backend.convert(collection)
        except Exception as exc:
            return None, [_conversion_failed(exc, target, profile, output_format)]
    except Exception as exc:
        return None, [_conversion_failed(exc, target, profile, output_format)]

    query = _normalize_result(result)
    if not query.strip():
        return None, [
            emit(
                "BACKEND_UNAVAILABLE",
                message="pySigma produced an empty query",
                target=target,
                profile=profile,
                output_format=output_format,
            )
        ]

    # pySigma Splunk default/spl emits only predicates; prepend the profile
    # base selector (index/sourcetype) so the query is runnable.
    if spec.prepend_profile_base and variant.pysigma_format == "default":
        base = profile_base_selector(profile, target)
        if base and not query.lstrip().lower().startswith("index="):
            query = f"{base} {query}".strip()

    return query, warnings


def _conversion_failed(exc: Exception, target: str, profile: str | None, output_format: str) -> GeneratorWarning:
    return emit(
        "BACKEND_UNAVAILABLE",
        message=f"pySigma conversion failed ({type(exc).__name__}); fell back to builtin: {str(exc)[:200]}",
        target=target,
        profile=profile,
        output_format=output_format,
    )


def available_targets() -> dict[str, list[str]]:
    """Map of target -> output formats that have an importable pySigma backend."""
    out: dict[str, list[str]] = {}
    for target, spec in _REGISTRY.items():
        fmts = [fmt for fmt in spec.variants if fmt != "*" and supports(target, fmt)]
        if fmts:
            out[target] = sorted(set(fmts))
    return out

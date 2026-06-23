"""Generator engine — orchestrates conversion across backends.

This module is the entry point for ``POST /api/generator/convert`` and the
new structured result shape. The legacy ``conversion_service.convert_rule``
delegates here so the old ``/api/convert`` endpoint keeps working with the
new pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.models.rule import ConvertedQuery, NormalizedRule, RawRule
from app.services.generator import cache, formats
from app.services.generator import targets as targets_module
from app.services.generator.backends import builtin, pysigma_runtime
from app.services.generator.profiles import ProfileDefinition, get_profile
from app.services.generator.warnings import GeneratorWarning, emit


def _json_list(value: str | None) -> list[str]:
    import json

    if not value:
        return []
    try:
        data = json.loads(value)
        return [str(x) for x in data] if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def _format_context(
    normalized: NormalizedRule,
    raw: RawRule,
    target: str,
    output_format: str,
    profile_id: str | None,
    profile_def: "ProfileDefinition | None",
) -> "formats.FormatContext":
    source_repo = None
    try:
        source_repo = raw.repository.name if raw.repository else None
    except Exception:
        source_repo = None
    return formats.FormatContext(
        target=target,
        output_format=output_format,
        title=normalized.title,
        description=normalized.description,
        severity=normalized.severity,
        rule_id=normalized.id,
        external_rule_id=normalized.external_rule_id,
        source_repo=source_repo,
        mitre_tactics=_json_list(normalized.mitre_tactics),
        mitre_techniques=_json_list(normalized.mitre_techniques),
        profile=profile_def,
        profile_id=profile_id,
    )


@dataclass
class ConvertResult:
    rule_id: int
    target: str
    profile: str | None
    output_format: str
    query: str
    status: str
    warnings: list[GeneratorWarning]
    error: str | None = None
    backend: str | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "target": self.target,
            "profile": self.profile,
            "output_format": self.output_format,
            "query": self.query,
            "status": self.status,
            "warnings": [w.to_dict() for w in self.warnings],
            "error": self.error,
            "backend": self.backend,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }


def _resolve_rule(db: Session, rule_id: int) -> tuple[NormalizedRule, RawRule]:
    normalized = db.query(NormalizedRule).filter(NormalizedRule.id == rule_id).first()
    if not normalized:
        raise ValueError(f"Rule {rule_id} not found")
    raw = db.query(RawRule).filter(RawRule.id == normalized.raw_rule_id).first()
    if not raw:
        raise ValueError(f"Raw rule for normalized id {rule_id} not found")
    return normalized, raw


def _attempt_chain(
    raw_yaml: str,
    target: str,
    profile: str | None,
    output_format: str,
) -> tuple[str | None, list[GeneratorWarning], str | None]:
    """Try backends in priority order, collecting warnings along the way.

    Order (mode "auto"): in-process pySigma -> builtin AST compiler.
    Mode "builtin" forces the AST compiler; mode "pysigma" disables the
    builtin fallback (used for parity testing).
    """
    warnings: list[GeneratorWarning] = []
    mode = get_settings().generator_backend

    if mode in ("auto", "pysigma") and pysigma_runtime.supports(target, output_format):
        query, ps_warnings = pysigma_runtime.convert(
            raw_yaml, target, profile=profile, output_format=output_format
        )
        if query:
            return query, ps_warnings, "pysigma"
        # pySigma was available but failed/empty; remember why and fall back.
        warnings.extend(ps_warnings)
        if mode == "pysigma":
            return None, warnings, "pysigma"

    if mode == "pysigma":
        warnings.append(
            emit(
                "BACKEND_UNAVAILABLE",
                message=f"No pySigma backend for {target}/{output_format} and builtin fallback disabled",
                target=target,
                profile=profile,
                output_format=output_format,
            )
        )
        return None, warnings, "pysigma"

    query, builtin_warnings = builtin.convert(raw_yaml, target, profile=profile, output_format=output_format)
    warnings.extend(builtin_warnings)
    return query, warnings, "builtin"


def _validate_target_and_format(target: str, output_format: str) -> tuple[str, str, list[GeneratorWarning]]:
    pre_warnings: list[GeneratorWarning] = []
    normalized_target = targets_module.normalize_target(target)
    target_spec = targets_module.TARGETS.get(normalized_target)
    if target_spec is None:
        normalized_target = "elastic"
        pre_warnings.append(
            emit(
                "UNMAPPED_TARGET",
                message=f"Unknown target {target!r}; mapped to {normalized_target!r}",
                target=target,
                output_format=output_format,
            )
        )
        target_spec = targets_module.TARGETS[normalized_target]
    valid_formats = {f.id for f in target_spec.formats}
    valid_formats.add("default")
    if output_format not in valid_formats:
        pre_warnings.append(
            emit(
                "UNMAPPED_TARGET",
                message=(
                    f"Output format {output_format!r} is not in catalog for target "
                    f"{normalized_target!r}; passing through anyway"
                ),
                target=normalized_target,
                output_format=output_format,
            )
        )
    return normalized_target, output_format, pre_warnings


def convert(
    db: Session,
    rule_id: int,
    *,
    target: str,
    profile: str | None,
    output_format: str = "default",
    persist: bool = True,
) -> ConvertResult:
    normalized, raw = _resolve_rule(db, rule_id)

    normalized_target, normalized_format, pre_warnings = _validate_target_and_format(target, output_format)

    profile_def = get_profile(profile) if profile else None
    if profile and profile_def is None:
        pre_warnings.append(
            emit(
                "BASE_SELECTOR_GUESSED",
                message=f"Profile {profile!r} not found; using target defaults",
                target=normalized_target,
                profile=profile,
                output_format=normalized_format,
            )
        )

    # Resolve the output format -> (what to ask the backend for, how to wrap).
    plan = formats.resolve(normalized_target, normalized_format)
    backend_format = plan.backend_format if plan else normalized_format

    # Cache lookup on the final (target, profile, output_format) for this rule.
    cache_key = cache.make_key(raw.raw_hash, normalized_target, profile, normalized_format)
    cached = cache.lookup(db, cache_key)
    if cached is not None:
        cached_warnings = pre_warnings + _warnings_from_json(cached.warnings_json)
        return ConvertResult(
            rule_id=rule_id,
            target=normalized_target,
            profile=profile,
            output_format=normalized_format,
            query=cached.query_text,
            status="success",
            warnings=cached_warnings,
            backend=cached.backend,
            metadata={"cache": "hit", "rule_title": normalized.title},
        )

    query, backend_warnings, backend_name = _attempt_chain(
        raw.raw_yaml,
        normalized_target,
        profile,
        backend_format,
    )
    all_warnings = pre_warnings + backend_warnings

    if not query:
        result = ConvertResult(
            rule_id=rule_id,
            target=normalized_target,
            profile=profile,
            output_format=normalized_format,
            query="",
            status="error",
            warnings=all_warnings,
            error="No backend produced a query.",
            backend=backend_name,
        )
        return result

    # Apply the formatter (savedsearches.conf, RBA, dashboard panel, ...).
    if plan and plan.formatter:
        ctx = _format_context(normalized, raw, normalized_target, normalized_format, profile, profile_def)
        query = formats.apply(plan, query, ctx)

    result = ConvertResult(
        rule_id=rule_id,
        target=normalized_target,
        profile=profile,
        output_format=normalized_format,
        query=query,
        status="success",
        warnings=all_warnings,
        backend=backend_name,
        metadata={
            "profile_loaded": profile_def is not None,
            "rule_title": normalized.title,
            "rule_severity": normalized.severity,
            "backend_format": backend_format,
        },
    )

    # Populate the conversion cache (independent of persist flag).
    cache.store(
        db,
        cache_key=cache_key,
        rule_id=rule_id,
        target=normalized_target,
        profile=profile,
        output_format=normalized_format,
        backend=backend_name,
        query_text=query,
        warnings=all_warnings,
    )

    if persist:
        record = ConvertedQuery(
            normalized_rule_id=normalized.id,
            target_siem=normalized_target,
            profile=profile,
            output_format=normalized_format,
            query_text=query,
            conversion_status="success",
            conversion_error=None,
            warnings=_serialize_warnings_for_db(all_warnings),
        )
        db.add(record)
        db.commit()

    return result


def _serialize_warnings_for_db(warnings: list[GeneratorWarning]) -> str:
    import json

    return json.dumps([w.to_dict() for w in warnings], default=str)


def _warnings_from_json(payload: str | None) -> list[GeneratorWarning]:
    import json

    if not payload:
        return []
    try:
        data = json.loads(payload)
    except (ValueError, TypeError):
        return []
    out: list[GeneratorWarning] = []
    for item in data if isinstance(data, list) else []:
        out.append(
            emit(
                item.get("code", "LEGACY_FALLBACK"),
                message=item.get("message"),
                field=item.get("field"),
                target=item.get("target"),
                profile=item.get("profile"),
                output_format=item.get("output_format"),
                context=item.get("context") or {},
            )
        )
    return out

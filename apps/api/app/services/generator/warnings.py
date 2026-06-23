"""Structured warnings for the generator.

Every warning carries a stable ``code`` so the UI can render tooltips,
suggestions, and coverage analytics without parsing free text.

See docs/design/05-generator-v2.md, section "Structured warnings".
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any


class WarningSeverity:
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class WarningCodeSpec:
    code: str
    severity: str
    title: str
    description: str
    suggestion: str | None = None


WARNING_CODES: dict[str, WarningCodeSpec] = {
    spec.code: spec
    for spec in [
        WarningCodeSpec(
            code="FIELD_NOT_IN_PROFILE",
            severity=WarningSeverity.WARNING,
            title="Field not in profile",
            description="A Sigma field does not exist in the chosen profile's field map.",
            suggestion="Pick a profile that covers this telemetry, or add a field mapping.",
        ),
        WarningCodeSpec(
            code="FIELD_FALLBACK_USED",
            severity=WarningSeverity.INFO,
            title="Field fallback used",
            description="Generic field name used because no mapping was found in the profile.",
        ),
        WarningCodeSpec(
            code="MODIFIER_NOT_SUPPORTED",
            severity=WarningSeverity.WARNING,
            title="Modifier not supported by target",
            description="A Sigma modifier has no native expression in the target SIEM; it was emulated.",
        ),
        WarningCodeSpec(
            code="MODIFIER_EMULATED_LOSSY",
            severity=WarningSeverity.WARNING,
            title="Modifier emulation is lossy",
            description="Emulation is best-effort and may produce false positives or negatives.",
            suggestion="Review the generated query before production deployment.",
        ),
        WarningCodeSpec(
            code="CONDITION_AMBIGUOUS",
            severity=WarningSeverity.WARNING,
            title="Ambiguous condition",
            description="Boolean condition has mixed operators without explicit grouping; default precedence was applied.",
            suggestion="Add parentheses in the source rule to make precedence explicit.",
        ),
        WarningCodeSpec(
            code="AGGREGATION_NOT_SUPPORTED",
            severity=WarningSeverity.WARNING,
            title="Aggregation not supported in this output format",
            description="The target does not support inline aggregation in this format.",
        ),
        WarningCodeSpec(
            code="TIMEFRAME_REQUIRED_BUT_MISSING",
            severity=WarningSeverity.WARNING,
            title="Timeframe required but missing",
            description="Rule uses correlation but no timeframe was provided; a default was applied.",
        ),
        WarningCodeSpec(
            code="BASE_SELECTOR_GUESSED",
            severity=WarningSeverity.INFO,
            title="Base selector guessed",
            description="Logsource category/service was unknown; a generic base index/table was used.",
        ),
        WarningCodeSpec(
            code="INDEX_FALLBACK_USED",
            severity=WarningSeverity.WARNING,
            title="Index fallback used",
            description="Profile lacks an index hint for this category; a generic index was used.",
        ),
        WarningCodeSpec(
            code="LICENSE_RESTRICTION",
            severity=WarningSeverity.ERROR,
            title="License restriction",
            description="Source rule license prohibits redistribution in this output format.",
        ),
        WarningCodeSpec(
            code="EMPTY_DETECTION",
            severity=WarningSeverity.ERROR,
            title="Empty detection",
            description="The detection has no selections; cannot produce a query.",
        ),
        WarningCodeSpec(
            code="UNMAPPED_TARGET",
            severity=WarningSeverity.WARNING,
            title="Unmapped target",
            description="Target id was unknown; mapped to the closest equivalent.",
        ),
        WarningCodeSpec(
            code="BACKEND_UNAVAILABLE",
            severity=WarningSeverity.INFO,
            title="Backend unavailable",
            description="A preferred backend was not available; another backend was used.",
        ),
        WarningCodeSpec(
            code="OPTIMIZER_REWRITE",
            severity=WarningSeverity.INFO,
            title="Optimizer rewrite",
            description="The generated query was rewritten for performance.",
        ),
        WarningCodeSpec(
            code="ENTITY_MAPPING_INCOMPLETE",
            severity=WarningSeverity.WARNING,
            title="Entity mapping incomplete",
            description="Some expected entities could not be inferred from the logsource.",
        ),
        WarningCodeSpec(
            code="RBA_REQUIRES_FIELD",
            severity=WarningSeverity.WARNING,
            title="Risk-based alert requires field",
            description="Risk-based alert output requires a field the rule does not produce.",
        ),
        WarningCodeSpec(
            code="MITRE_TAG_INVALID",
            severity=WarningSeverity.WARNING,
            title="MITRE tag invalid",
            description="A MITRE tag could not be resolved against the loaded ATT&CK bundle.",
        ),
        WarningCodeSpec(
            code="LEGACY_FALLBACK",
            severity=WarningSeverity.INFO,
            title="Legacy fallback",
            description="The legacy free-text converter was used; structured detail is not available.",
        ),
    ]
}


@dataclass
class GeneratorWarning:
    code: str
    severity: str
    message: str
    field: str | None = None
    target: str | None = None
    profile: str | None = None
    output_format: str | None = None
    suggestion: str | None = None
    context: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "field": self.field,
            "target": self.target,
            "profile": self.profile,
            "output_format": self.output_format,
            "suggestion": self.suggestion,
            "context": self.context,
        }


def emit(
    code: str,
    message: str | None = None,
    *,
    field: str | None = None,
    target: str | None = None,
    profile: str | None = None,
    output_format: str | None = None,
    suggestion: str | None = None,
    context: dict[str, Any] | None = None,
) -> GeneratorWarning:
    spec = WARNING_CODES.get(code)
    if spec is None:
        return GeneratorWarning(
            code=code,
            severity=WarningSeverity.WARNING,
            message=message or code,
            field=field,
            target=target,
            profile=profile,
            output_format=output_format,
            suggestion=suggestion,
            context=context or {},
        )
    return GeneratorWarning(
        code=spec.code,
        severity=spec.severity,
        message=message or spec.description,
        field=field,
        target=target,
        profile=profile,
        output_format=output_format,
        suggestion=suggestion or spec.suggestion,
        context=context or {},
    )


def from_compiler_warnings(
    compiler_warnings: list[Any],
    *,
    target: str | None = None,
    profile: str | None = None,
    output_format: str | None = None,
) -> list[GeneratorWarning]:
    """Translate rule_engine ``CompilerWarning`` objects into structured ones.

    The compiler emits the same ``code`` strings as this catalog, so we map
    them straight through and attach the request context.
    """
    out: list[GeneratorWarning] = []
    for cw in compiler_warnings:
        out.append(
            emit(
                getattr(cw, "code", "LEGACY_FALLBACK"),
                message=getattr(cw, "message", None),
                field=getattr(cw, "field", None),
                target=target,
                profile=profile,
                output_format=output_format,
                context=getattr(cw, "context", None) or {},
            )
        )
    return out


def from_legacy_strings(
    strings: list[str],
    *,
    target: str | None = None,
    profile: str | None = None,
    output_format: str | None = None,
) -> list[GeneratorWarning]:
    """Wrap legacy free-text warnings into structured ones.

    Used while the built-in converter still emits strings; G2 will replace
    these at the source.
    """
    return [
        emit(
            "LEGACY_FALLBACK",
            message=text,
            target=target,
            profile=profile,
            output_format=output_format,
        )
        for text in strings
    ]


def warning_code_catalog() -> list[dict[str, Any]]:
    return [
        {
            "code": spec.code,
            "severity": spec.severity,
            "title": spec.title,
            "description": spec.description,
            "suggestion": spec.suggestion,
        }
        for spec in WARNING_CODES.values()
    ]

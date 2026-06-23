"""Public entry point for the AST-based Sigma compiler.

``compile_rule(rule_dict, target, ...)`` parses the detection + condition
into an AST, renders it for the target, prepends a base selector derived
from the logsource (and optional profile override), and returns
``(query, warnings)`` where warnings are ``CompilerWarning`` objects.
"""

from __future__ import annotations

from typing import Any

from .ast import DetectionAST
from .backends import get_renderer
from .condition import parse_condition
from .detection import parse_detection
from .field_maps import BASES
from .warnings import CompilerWarning, warn

SUPPORTED_TARGETS = {"splunk", "sentinel", "elastic", "opensearch", "qradar", "chronicle", "logscale"}


def _base_key(logsource: dict[str, Any]) -> str:
    category = str(logsource.get("category") or "").lower()
    service = str(logsource.get("service") or "").lower()
    if category:
        return category
    if service:
        return service
    return "default"


def _base_selector(
    target: str,
    logsource: dict[str, Any],
    profile_base: str | None,
    warnings: list[CompilerWarning],
) -> str:
    if profile_base:
        return profile_base
    bases = BASES.get(target) or BASES["elastic"]
    key = _base_key(logsource)
    if key not in bases:
        warnings.append(
            warn("BASE_SELECTOR_GUESSED", message=f"No base selector for logsource {key!r} on {target}; used default.")
        )
    return bases.get(key) or bases.get("default") or "*"


def _assemble(target: str, base: str, body: str) -> str:
    if not body:
        return base
    if target == "splunk":
        return f"{base} {body}".strip()
    if target == "sentinel":
        sep = " | where " if "| where" not in base else " "
        return f"{base}{sep}{body}"
    if target == "qradar":
        return f"{base} {body}".strip()
    if target == "chronicle":
        return f"{base}\nand {body}"
    if target == "logscale":
        return f"{base} {body}".strip()
    # elastic / opensearch KQL
    if base in ("*", ""):
        return body
    return f"{base} and {body}"


def compile_rule(
    rule: dict[str, Any],
    target: str,
    *,
    profile_base: str | None = None,
    field_overrides: dict[str, str] | None = None,
) -> tuple[str, list[CompilerWarning]]:
    warnings: list[CompilerWarning] = []
    if target not in SUPPORTED_TARGETS:
        warnings.append(warn("UNMAPPED_TARGET", message=f"Target {target!r} not supported by compiler; using elastic syntax."))
        target = "elastic"

    detection = rule.get("detection") or {}
    logsource = rule.get("logsource") or {}

    searches = parse_detection(detection, warnings)
    if not searches:
        warnings.append(warn("EMPTY_DETECTION", message="Detection has no selections; only a base selector was produced."))
        base = _base_selector(target, logsource, profile_base, warnings)
        return base, warnings

    condition = detection.get("condition")
    if isinstance(condition, list):
        # Sigma allows a list of conditions => OR them.
        condition = " or ".join(f"({c})" for c in condition)
    root, aggregation = parse_condition(condition if isinstance(condition, str) else None, list(searches.keys()), warnings)

    renderer = get_renderer(target, searches, warnings, field_overrides=field_overrides)
    body = renderer.render(root)

    base = _base_selector(target, logsource, profile_base, warnings)
    query = _assemble(target, base, body)

    if aggregation and aggregation.op:
        query = _append_aggregation(target, query, aggregation, warnings)

    return query, warnings


def _append_aggregation(target: str, query: str, agg, warnings: list[CompilerWarning]) -> str:
    by = ", ".join(agg.group_by) if agg.group_by else None
    if target == "splunk":
        stats = f"| stats {agg.func}"
        if agg.agg_field:
            stats += f"({agg.agg_field})"
        else:
            stats += "(*) as count"
        if by:
            stats += f" by {by}"
        op = agg.op
        metric = "count" if not agg.agg_field else f"{agg.func}({agg.agg_field})"
        return f"{query} {stats} | where {metric} {op} {int(agg.threshold) if agg.threshold is not None else 0}"
    if target == "sentinel":
        summarize = f"| summarize Count = {agg.func}({agg.agg_field or ''})"
        if by:
            summarize += f" by {by}"
        return f"{query} {summarize} | where Count {agg.op} {int(agg.threshold) if agg.threshold is not None else 0}"
    warnings.append(
        warn("AGGREGATION_NOT_SUPPORTED", message=f"Aggregation tail not rendered for target {target}; base query only.")
    )
    return query

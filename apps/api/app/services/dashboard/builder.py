"""Scope -> panels + summary.

Resolves a dashboard scope (tactics / techniques / use_case ids / explicit
rule ids) into PanelSpecs (each with a SIEM query from Generator V2) plus
a computed summary used to render rich overview tiles.

Scope precedence: an explicit technique is more specific than a tactic, so
when both are given the technique wins (avoids empty "tactic AND technique
don't intersect" results).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.models.rule import NormalizedRule, RawRule
from app.services.generator import engine

_BODY_FORMAT = {
    "splunk": "spl",
    "sentinel": "kql",
    "elastic": "kql",
    "opensearch": "kql",
    "qradar": "aql",
    "chronicle": "udm_search",
    "logscale": "query",
}


@dataclass
class PanelSpec:
    title: str
    query: str
    viz: str
    technique: str | None = None
    tactic: str | None = None
    severity: str | None = None
    rule_id: int | None = None
    backend: str | None = None
    warnings: int = 0


@dataclass
class DashboardSummary:
    detection_count: int = 0
    technique_count: int = 0
    tactic_count: int = 0
    severity_counts: dict[str, int] = field(default_factory=dict)
    top_techniques: list[tuple[str, int]] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)


@dataclass
class DashboardPlan:
    name: str
    target: str
    layout: str
    profile: str | None
    panels: list[PanelSpec] = field(default_factory=list)
    scope: dict[str, Any] = field(default_factory=dict)
    summary: DashboardSummary = field(default_factory=DashboardSummary)


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
        return [str(x) for x in data] if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def _matching_rules(db: Session, scope: dict[str, Any], cap: int) -> list[NormalizedRule]:
    techniques = [t.upper() for t in scope.get("techniques", [])]
    tactics = scope.get("tactics", [])
    severity = scope.get("severity")
    rule_ids = scope.get("rule_ids", [])

    q = db.query(NormalizedRule).join(RawRule, NormalizedRule.raw_rule_id == RawRule.id)
    if rule_ids:
        q = q.filter(NormalizedRule.id.in_(rule_ids))
    if severity:
        q = q.filter(NormalizedRule.severity == severity)
    q = q.order_by(NormalizedRule.quality_score.desc(), NormalizedRule.id.desc())
    rows = q.limit(8000).all()

    matched: list[NormalizedRule] = []
    for r in rows:
        r_techs = _json_list(r.mitre_techniques)
        r_tactics = _json_list(r.mitre_tactics)
        # Technique is more specific; when provided it takes precedence.
        if techniques:
            if not any(t in r_techs for t in techniques):
                continue
        elif tactics:
            if not any(t in r_tactics for t in tactics):
                continue
        matched.append(r)
    return matched


def _summarize(rules: list[NormalizedRule]) -> DashboardSummary:
    sev = Counter()
    techs = Counter()
    tactics: set[str] = set()
    for r in rules:
        sev[(r.severity or "unknown").lower()] += 1
        for t in _json_list(r.mitre_techniques):
            techs[t] += 1
        for ta in _json_list(r.mitre_tactics):
            tactics.add(ta)
    return DashboardSummary(
        detection_count=len(rules),
        technique_count=len(techs),
        tactic_count=len(tactics),
        severity_counts=dict(sev),
        top_techniques=techs.most_common(10),
        tactics=sorted(tactics),
    )


def _viz_for(rule: NormalizedRule) -> str:
    cat = (rule.category or "").lower()
    if cat in ("authentication", "network_connection", "dns_query"):
        return "top_n"
    return "event_table"


def build_plan(
    db: Session,
    *,
    name: str,
    target: str,
    layout: str,
    profile: str | None,
    scope: dict[str, Any],
    max_panels: int = 16,
) -> DashboardPlan:
    body_format = _BODY_FORMAT.get(target, "default")
    all_matches = _matching_rules(db, scope, max_panels)
    summary = _summarize(all_matches)

    # Keep the best rule per technique for panel diversity, capped.
    chosen: dict[str, NormalizedRule] = {}
    for r in all_matches:
        techs = _json_list(r.mitre_techniques)
        key = techs[0] if techs else f"rule-{r.id}"
        if key not in chosen:
            chosen[key] = r
        if len(chosen) >= max_panels:
            break
    panel_rules = list(chosen.values()) or all_matches[:max_panels]

    panels: list[PanelSpec] = []
    for rule in panel_rules:
        try:
            result = engine.convert(db, rule.id, target=target, profile=profile, output_format=body_format, persist=False)
        except Exception:
            continue
        if result.status != "success" or not result.query:
            continue
        techs = _json_list(rule.mitre_techniques)
        tactics = _json_list(rule.mitre_tactics)
        panels.append(
            PanelSpec(
                title=f"{techs[0] + ' — ' if techs else ''}{rule.title}"[:120],
                query=result.query,
                viz=_viz_for(rule),
                technique=techs[0] if techs else None,
                tactic=tactics[0] if tactics else None,
                severity=rule.severity,
                rule_id=rule.id,
                backend=result.backend,
                warnings=len(result.warnings),
            )
        )

    return DashboardPlan(
        name=name, target=target, layout=layout, profile=profile,
        panels=panels, scope=scope, summary=summary,
    )

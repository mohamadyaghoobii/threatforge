"""Output formatters.

A backend produces a bare query *body* (SPL / KQL / ...). A formatter
wraps that body together with rule metadata and the profile's output
defaults into a SIEM-native artifact: a savedsearches.conf stanza, an
ES notable, a risk-based alert, a dashboard panel, an analytic rule, etc.

``resolve(target, output_format)`` returns a ``FormatPlan`` telling the
engine which *backend format* to request and which formatter to apply.
``apply(plan, body, ctx)`` runs the formatter.

This indirection is what lets one query body fan out into many artifacts
without the backends knowing about schedules, notables, or RBA.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from app.services.generator.profiles import ProfileDefinition


@dataclass
class FormatContext:
    """Everything a formatter needs beyond the query body."""

    target: str
    output_format: str
    title: str
    description: str | None = None
    severity: str | None = None
    rule_id: int | None = None
    external_rule_id: str | None = None
    source_repo: str | None = None
    references: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    profile: ProfileDefinition | None = None
    profile_id: str | None = None

    def output_defaults(self) -> dict[str, Any]:
        if not self.profile:
            return {}
        od = self.profile.output_defaults.get(self.output_format)
        if od is None:
            return {}
        return od.model_dump(exclude_none=True)

    def severity_number(self, default: int = 3) -> int:
        if not self.profile or not self.severity:
            return default
        val = self.profile.severity_map.get(self.severity)
        return int(val) if isinstance(val, (int, float)) else default


@dataclass
class FormatPlan:
    """How to fulfil an output_format request."""

    backend_format: str  # what to ask the backend for (e.g. "spl", "data_model")
    formatter: Callable[[str, FormatContext], str] | None  # None => return body as-is


# (target, output_format) -> FormatPlan
_REGISTRY: dict[tuple[str, str], FormatPlan] = {}


def register(target: str, output_format: str, plan: FormatPlan) -> None:
    _REGISTRY[(target, output_format)] = plan


def resolve(target: str, output_format: str) -> FormatPlan | None:
    return _REGISTRY.get((target, output_format))


def apply(plan: FormatPlan, body: str, ctx: FormatContext) -> str:
    if plan.formatter is None:
        return body
    return plan.formatter(body, ctx)


# Register built-in formatters. Import side effects populate the registry.
from app.services.generator.formats import splunk as _splunk  # noqa: E402,F401
from app.services.generator.formats import sentinel as _sentinel  # noqa: E402,F401
from app.services.generator.formats import elastic as _elastic  # noqa: E402,F401
from app.services.generator.formats import others as _others  # noqa: E402,F401

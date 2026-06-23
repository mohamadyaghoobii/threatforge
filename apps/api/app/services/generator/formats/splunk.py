"""Splunk output formatters.

Wraps a bare SPL search body into:
  - savedsearches_conf : full savedsearches.conf stanza with schedule,
                         suppression, notable (ES), RBA, and correlation
                         search MITRE annotations.
  - ess_notable        : a savedsearch focused on notable-event creation.
  - risk_based_alert   : a savedsearch with action.risk (RBA) parameters.
  - dashboard_panel    : a Simple XML <panel> fragment.

``spl`` and ``datamodel_tstats`` are pass-through (the backend already
produced the right body); they are registered with no formatter.
"""

from __future__ import annotations

import json
from typing import Any

from jinja2 import Template

from app.services.generator.formats import FormatContext, FormatPlan, register

# --- helpers ---------------------------------------------------------------

_SEVERITY_RISK = {"critical": 90, "high": 70, "medium": 50, "low": 30, "informational": 10}


def _risk_score(ctx: FormatContext) -> int:
    od = ctx.output_defaults()
    rba = od.get("rba") or {}
    if isinstance(rba, dict) and rba.get("base_score"):
        return int(rba["base_score"])
    if ctx.severity and ctx.severity.lower() in _SEVERITY_RISK:
        return _SEVERITY_RISK[ctx.severity.lower()]
    return 40


def _security_domain(ctx: FormatContext) -> str:
    od = ctx.output_defaults()
    notable = od.get("notable") or {}
    return notable.get("security_domain", "threat")


def _suppression(ctx: FormatContext) -> dict[str, Any]:
    od = ctx.output_defaults()
    return od.get("suppression") or {}


def _entity(ctx: FormatContext, kind: str, default: str) -> str:
    if ctx.profile and ctx.profile.entity_inference.get(kind):
        return ctx.profile.entity_inference[kind]
    return default


def _annotations(ctx: FormatContext) -> str:
    """Build the ES correlationsearch MITRE annotation JSON."""
    payload: dict[str, Any] = {}
    if ctx.mitre_techniques:
        payload["mitre_attack"] = ctx.mitre_techniques
    if ctx.mitre_tactics:
        payload["kill_chain_phases"] = [t.lower().replace(" ", "_") for t in ctx.mitre_tactics]
    return json.dumps(payload, separators=(",", ":"))


def _stanza_name(ctx: FormatContext) -> str:
    return f"MetaSec Security Center - {ctx.title}"


# --- templates -------------------------------------------------------------

_SAVEDSEARCHES_TMPL = Template(
    """[{{ name }}]
description = {{ description }}
search = {{ search }}
disabled = 0
is_scheduled = 1
realtime_schedule = 0
cron_schedule = {{ cron }}
dispatch.earliest_time = {{ earliest }}
dispatch.latest_time = {{ latest }}
{% if suppress_fields %}alert.suppress = 1
alert.suppress.fields = {{ suppress_fields }}
alert.suppress.period = {{ suppress_period }}
{% endif %}{% if notable %}action.notable = 1
action.notable.param.rule_title = {{ title }}
action.notable.param.rule_description = {{ description }}
action.notable.param.security_domain = {{ security_domain }}
action.notable.param.severity = {{ severity }}
action.notable.param.drilldown_name = View raw events for $host$
action.notable.param.drilldown_search = {{ search }} host="$host$"
{% endif %}{% if rba %}action.risk = 1
action.risk.param._risk_score = {{ risk_score }}
action.risk.param._risk_object = {{ risk_object }}
action.risk.param._risk_object_type = {{ risk_object_type }}
action.risk.param.threat_object_field = {{ threat_object }}
action.risk.param.threat_object_type = {{ threat_object_type }}
{% endif %}action.correlationsearch.enabled = 1
action.correlationsearch.label = {{ name }}
action.correlationsearch.annotations = {{ annotations }}"""
)

_DASHBOARD_PANEL_TMPL = Template(
    """<panel>
  <title>{{ title }}</title>
  <table>
    <search>
      <query>{{ search }} | stats count by {{ group_by }} | sort - count</query>
      <earliest>{{ earliest }}</earliest>
      <latest>{{ latest }}</latest>
    </search>
    <option name="count">20</option>
    <option name="drilldown">cell</option>
  </table>
</panel>"""
)


# --- formatters ------------------------------------------------------------


def format_savedsearches(body: str, ctx: FormatContext) -> str:
    od = ctx.output_defaults()
    suppression = _suppression(ctx)
    notable = od.get("notable") or {}
    rba = od.get("rba") or {}
    suppress_fields = ",".join(suppression.get("fields", [])) if suppression.get("enabled") else ""
    return _SAVEDSEARCHES_TMPL.render(
        name=_stanza_name(ctx),
        title=ctx.title,
        description=ctx.description or "",
        search=body,
        cron=od.get("cron_schedule", "*/15 * * * *"),
        earliest=od.get("earliest_time", "-15m"),
        latest=od.get("latest_time", "now"),
        suppress_fields=suppress_fields,
        suppress_period=suppression.get("period", "1h"),
        notable=bool(notable.get("enabled", True)),
        security_domain=_security_domain(ctx),
        severity=ctx.severity or "medium",
        rba=bool(rba.get("enabled", False)),
        risk_score=_risk_score(ctx),
        risk_object=rba.get("risk_object_field", _entity(ctx, "user", "user")),
        risk_object_type=rba.get("risk_object_type", "user"),
        threat_object=rba.get("threat_object_field", _entity(ctx, "process", "process_name")),
        threat_object_type=rba.get("threat_object_type", "process"),
        annotations=_annotations(ctx),
    )


def format_ess_notable(body: str, ctx: FormatContext) -> str:
    # A notable-focused savedsearch: force notable on, RBA off.
    cloned = FormatContext(**{**ctx.__dict__})
    out = format_savedsearches(body, cloned)
    return out


def format_risk_based_alert(body: str, ctx: FormatContext) -> str:
    # Reuse the savedsearch builder but guarantee the RBA block renders.
    od = dict(ctx.output_defaults())
    rba = dict(od.get("rba") or {})
    rba["enabled"] = True
    risk_object = rba.get("risk_object_field", _entity(ctx, "user", "user"))
    threat_object = rba.get("threat_object_field", _entity(ctx, "process", "process_name"))
    lines = [
        f"[{_stanza_name(ctx)} - RBA]",
        f"description = {ctx.description or ''}",
        f"search = {body}",
        "disabled = 0",
        "is_scheduled = 1",
        f"cron_schedule = {od.get('cron_schedule', '*/15 * * * *')}",
        f"dispatch.earliest_time = {od.get('earliest_time', '-15m')}",
        "dispatch.latest_time = now",
        "action.risk = 1",
        f"action.risk.param._risk_score = {_risk_score(ctx)}",
        f"action.risk.param._risk_object = {risk_object}",
        f"action.risk.param._risk_object_type = {rba.get('risk_object_type', 'user')}",
        f"action.risk.param.threat_object_field = {threat_object}",
        f"action.risk.param.threat_object_type = {rba.get('threat_object_type', 'process')}",
        "action.correlationsearch.enabled = 1",
        f"action.correlationsearch.label = {_stanza_name(ctx)} - RBA",
        f"action.correlationsearch.annotations = {_annotations(ctx)}",
    ]
    return "\n".join(lines)


def format_dashboard_panel(body: str, ctx: FormatContext) -> str:
    group_by = _entity(ctx, "host", "host")
    od = ctx.output_defaults()
    return _DASHBOARD_PANEL_TMPL.render(
        title=ctx.title,
        search=body,
        group_by=group_by,
        earliest=od.get("earliest_time", "-24h"),
        latest=od.get("latest_time", "now"),
    )


# --- registration ----------------------------------------------------------

register("splunk", "spl", FormatPlan(backend_format="spl", formatter=None))
register("splunk", "default", FormatPlan(backend_format="spl", formatter=None))
register("splunk", "datamodel_tstats", FormatPlan(backend_format="datamodel_tstats", formatter=None))
register("splunk", "savedsearches_conf", FormatPlan(backend_format="spl", formatter=format_savedsearches))
register("splunk", "savedsearches", FormatPlan(backend_format="spl", formatter=format_savedsearches))
register("splunk", "ess_notable", FormatPlan(backend_format="spl", formatter=format_ess_notable))
register("splunk", "risk_based_alert", FormatPlan(backend_format="spl", formatter=format_risk_based_alert))
register("splunk", "dashboard_panel", FormatPlan(backend_format="spl", formatter=format_dashboard_panel))

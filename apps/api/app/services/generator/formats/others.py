"""Formatters for QRadar, Chronicle, LogScale, Sumo Logic, Devo, Wazuh.

Query bodies come from the builtin AST compiler (these targets have no
installed pySigma backend in the default extra). The formatters wrap the
body into each platform's native rule/alert artifact.
"""

from __future__ import annotations

import json
from xml.sax.saxutils import escape

import yaml

from app.services.generator.formats import FormatContext, FormatPlan, register

_QRADAR_SEVERITY = {"critical": 9, "high": 7, "medium": 5, "low": 3, "informational": 1}
_GENERIC_SEVERITY = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "informational": "INFO"}


def _sev_num(ctx: FormatContext) -> int:
    return _QRADAR_SEVERITY.get((ctx.severity or "medium").lower(), 5)


def _sev_label(ctx: FormatContext) -> str:
    return _GENERIC_SEVERITY.get((ctx.severity or "medium").lower(), "MEDIUM")


def _tech_csv(ctx: FormatContext) -> str:
    return ",".join(ctx.mitre_techniques) or "none"


# --- QRadar ----------------------------------------------------------------


def format_qradar_custom_rule(body: str, ctx: FormatContext) -> str:
    name = escape(f"MetaSec Security Center - {ctx.title}")
    test = escape(body)
    annotate = escape(_tech_csv(ctx))
    return (
        "<rule>\n"
        f"  <name>{name}</name>\n"
        f"  <severity>{_sev_num(ctx)}</severity>\n"
        "  <category>Anomaly</category>\n"
        "  <enabled>true</enabled>\n"
        "  <tests>\n"
        f'    <test type="AQL" op="matches">{test}</test>\n'
        "  </tests>\n"
        "  <actions>\n"
        '    <action type="dispatch_offense">\n'
        "      <field name=\"offense_indexer\">Username</field>\n"
        f'      <field name="annotate">{annotate}</field>\n'
        "    </action>\n"
        "  </actions>\n"
        "</rule>"
    )


def format_qradar_building_block(body: str, ctx: FormatContext) -> str:
    name = escape(f"BB:MetaSec Security Center - {ctx.title}")
    test = escape(body)
    return (
        "<building_block>\n"
        f"  <name>{name}</name>\n"
        "  <enabled>true</enabled>\n"
        "  <tests>\n"
        f'    <test type="AQL" op="matches">{test}</test>\n'
        "  </tests>\n"
        "</building_block>"
    )


def format_qradar_ariel_search(body: str, ctx: FormatContext) -> str:
    return json.dumps({"name": f"MetaSec Security Center - {ctx.title}", "query_expression": body}, indent=2)


# --- Chronicle -------------------------------------------------------------


def format_chronicle_yaral(body: str, ctx: FormatContext) -> str:
    rule_name = (ctx.external_rule_id or f"metasec_{ctx.rule_id}").replace("-", "_").lower()
    technique = ctx.mitre_techniques[0] if ctx.mitre_techniques else "none"
    tactic = ctx.mitre_tactics[0] if ctx.mitre_tactics else "none"
    # body from ChronicleRenderer is a set of UDM predicates joined with and/or.
    events = "\n    ".join(line for line in [body] if line)
    return (
        f"rule {rule_name} {{\n"
        "  meta:\n"
        '    author = "MetaSec Security Center"\n'
        f'    description = "{ctx.description or ctx.title}"\n'
        f'    severity = "{_sev_label(ctx)}"\n'
        f'    mitre_attack_tactic = "{tactic}"\n'
        f'    mitre_attack_technique = "{technique}"\n'
        "  events:\n"
        f"    {events}\n"
        "  condition:\n"
        "    $e\n"
        "}"
    )


def format_chronicle_retrohunt(body: str, ctx: FormatContext) -> str:
    return json.dumps({"rule_text": body, "name": ctx.title}, indent=2)


# --- LogScale --------------------------------------------------------------


def format_logscale_alert(body: str, ctx: FormatContext) -> str:
    doc = {
        "name": f"MetaSec Security Center - {ctx.title}",
        "description": ctx.description or "",
        "query": body,
        "queryStart": "-15m",
        "throttleField": (ctx.profile.entity_inference.get("host") if ctx.profile else None) or "host",
        "throttleTimeMillis": 3600000,
        "severity": _sev_label(ctx),
        "labels": ["MetaSec Security Center", *ctx.mitre_techniques],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def format_logscale_widget(body: str, ctx: FormatContext) -> str:
    return json.dumps(
        {"title": ctx.title, "queryString": body, "widgetType": "table-view", "start": "24h"},
        indent=2,
    )


# --- Sumo Logic ------------------------------------------------------------


def format_sumo_cse_rule(body: str, ctx: FormatContext) -> str:
    doc = {
        "name": f"MetaSec Security Center - {ctx.title}",
        "description": ctx.description or "",
        "enabled": True,
        "expression": body,
        "score": {"critical": 8, "high": 6, "medium": 4, "low": 2, "informational": 1}.get(
            (ctx.severity or "medium").lower(), 4
        ),
        "tags": ["MetaSec Security Center", *ctx.mitre_techniques],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


# --- Devo ------------------------------------------------------------------


def format_devo_alert(body: str, ctx: FormatContext) -> str:
    return json.dumps(
        {
            "name": f"MetaSec Security Center - {ctx.title}",
            "message": ctx.description or ctx.title,
            "query": body,
            "priority": _sev_label(ctx),
            "categories": ctx.mitre_techniques,
        },
        indent=2,
    )


# --- Wazuh -----------------------------------------------------------------


def format_wazuh_rule(body: str, ctx: FormatContext) -> str:
    level_map = {"critical": 15, "high": 12, "medium": 8, "low": 5, "informational": 3}
    level = level_map.get((ctx.severity or "medium").lower(), 8)
    desc = escape(ctx.title)
    field = escape(body)
    technique = escape(ctx.mitre_techniques[0] if ctx.mitre_techniques else "")
    return (
        '<group name="metasec,">\n'
        '  <rule id="100001" level="%d">\n'
        "    <description>%s</description>\n"
        "    <field name=\"detection\">%s</field>\n"
        '    <mitre>\n'
        f"      <id>{technique}</id>\n"
        "    </mitre>\n"
        "  </rule>\n"
        "</group>"
    ) % (level, desc, field)


# --- registration ----------------------------------------------------------

# QRadar
register("qradar", "aql", FormatPlan(backend_format="aql", formatter=None))
register("qradar", "default", FormatPlan(backend_format="aql", formatter=None))
register("qradar", "custom_rule_xml", FormatPlan(backend_format="aql", formatter=format_qradar_custom_rule))
register("qradar", "building_block_xml", FormatPlan(backend_format="aql", formatter=format_qradar_building_block))
register("qradar", "ariel_search_json", FormatPlan(backend_format="aql", formatter=format_qradar_ariel_search))

# Chronicle
register("chronicle", "udm_search", FormatPlan(backend_format="udm_search", formatter=None))
register("chronicle", "default", FormatPlan(backend_format="udm_search", formatter=None))
register("chronicle", "yara_l_rule", FormatPlan(backend_format="udm_search", formatter=format_chronicle_yaral))
register("chronicle", "retrohunt", FormatPlan(backend_format="udm_search", formatter=format_chronicle_retrohunt))

# LogScale
register("logscale", "query", FormatPlan(backend_format="query", formatter=None))
register("logscale", "default", FormatPlan(backend_format="query", formatter=None))
register("logscale", "alert_yaml", FormatPlan(backend_format="query", formatter=format_logscale_alert))
register("logscale", "dashboard_widget", FormatPlan(backend_format="query", formatter=format_logscale_widget))

# Sumo Logic
register("sumologic", "query", FormatPlan(backend_format="query", formatter=None))
register("sumologic", "default", FormatPlan(backend_format="query", formatter=None))
register("sumologic", "cse_rule_yaml", FormatPlan(backend_format="query", formatter=format_sumo_cse_rule))

# Devo
register("devo", "linq", FormatPlan(backend_format="linq", formatter=None))
register("devo", "default", FormatPlan(backend_format="linq", formatter=None))
register("devo", "alert_definition_json", FormatPlan(backend_format="linq", formatter=format_devo_alert))

# Wazuh
register("wazuh", "rule_xml", FormatPlan(backend_format="rule_xml", formatter=format_wazuh_rule))
register("wazuh", "default", FormatPlan(backend_format="rule_xml", formatter=format_wazuh_rule))
register("wazuh", "detection_rule_ndjson", FormatPlan(backend_format="rule_xml", formatter=format_wazuh_rule))

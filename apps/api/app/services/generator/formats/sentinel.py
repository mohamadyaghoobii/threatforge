"""Microsoft Sentinel output formatters.

Wraps a KQL body into:
  - kql                 : pass-through.
  - analytic_rule_arm   : Microsoft.SecurityInsights/alertRules ARM
                          template with schedule, threshold, tactics +
                          techniques + sub-techniques, entity mappings,
                          incident config, and alert details override.
  - hunting_query_yaml  : Sentinel hunting query YAML.
  - workbook_panel      : a workbook query tile (JSON fragment).
"""

from __future__ import annotations

import json
from typing import Any

import yaml

from app.services.generator.formats import FormatContext, FormatPlan, register

# MITRE tactic name -> Sentinel tactic enum (no spaces).
_SENTINEL_TACTIC = {
    "reconnaissance": "Reconnaissance",
    "resource development": "ResourceDevelopment",
    "initial access": "InitialAccess",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege escalation": "PrivilegeEscalation",
    "defense evasion": "DefenseEvasion",
    "credential access": "CredentialAccess",
    "discovery": "Discovery",
    "lateral movement": "LateralMovement",
    "collection": "Collection",
    "command and control": "CommandAndControl",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

_SENTINEL_SEVERITY = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

# Sentinel entity type -> (identifier, default column from entity_inference key)
_ENTITY_TYPES = {
    "user": ("Account", "Name"),
    "host": ("Host", "HostName"),
    "process": ("Process", "CommandLine"),
    "ip": ("IP", "Address"),
}


def _sentinel_tactics(ctx: FormatContext) -> list[str]:
    out = []
    for t in ctx.mitre_tactics:
        mapped = _SENTINEL_TACTIC.get(t.lower())
        if mapped and mapped not in out:
            out.append(mapped)
    return out


def _parent_techniques(ctx: FormatContext) -> list[str]:
    return sorted({t.split(".")[0] for t in ctx.mitre_techniques})


def _sub_techniques(ctx: FormatContext) -> list[str]:
    return sorted({t for t in ctx.mitre_techniques if "." in t})


def _severity(ctx: FormatContext) -> str:
    if ctx.severity and ctx.severity.lower() in _SENTINEL_SEVERITY:
        return _SENTINEL_SEVERITY[ctx.severity.lower()]
    return "Medium"


def _entity_mappings(ctx: FormatContext) -> list[dict[str, Any]]:
    mappings: list[dict[str, Any]] = []
    inference = ctx.profile.entity_inference if ctx.profile else {}
    for kind, column in inference.items():
        spec = _ENTITY_TYPES.get(kind)
        if not spec:
            continue
        entity_type, identifier = spec
        mappings.append(
            {
                "entityType": entity_type,
                "fieldMappings": [{"identifier": identifier, "columnName": column}],
            }
        )
    return mappings


def _iso_duration(value: str | None, default: str) -> str:
    return value or default


def format_analytic_rule_arm(body: str, ctx: FormatContext) -> str:
    od = ctx.output_defaults()
    name_slug = (ctx.external_rule_id or str(ctx.rule_id or "rule")).replace(" ", "-").lower()
    rule = {
        "type": "Microsoft.SecurityInsights/alertRules",
        "apiVersion": "2023-12-01-preview",
        "kind": "Scheduled",
        "name": f"metasec-{name_slug}",
        "properties": {
            "displayName": f"MetaSec Security Center - {ctx.title}",
            "description": ctx.description or "",
            "severity": _severity(ctx),
            "enabled": True,
            "query": body,
            "queryFrequency": _iso_duration(od.get("query_frequency"), "PT15M"),
            "queryPeriod": _iso_duration(od.get("query_period"), "PT15M"),
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": _iso_duration(od.get("suppression_duration"), "PT1H"),
            "suppressionEnabled": bool(od.get("suppression_enabled", False)),
            "tactics": _sentinel_tactics(ctx),
            "techniques": _parent_techniques(ctx),
            "subTechniques": _sub_techniques(ctx),
            "entityMappings": _entity_mappings(ctx),
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": "PT5H",
                    "matchingMethod": "AllEntities",
                },
            },
            "alertDetailsOverride": {
                "alertDisplayNameFormat": f"{ctx.title} (MetaSec Security Center)",
                "alertDescriptionFormat": ctx.description or ctx.title,
            },
            "customDetails": {"Techniques": ",".join(ctx.mitre_techniques) or "none"},
        },
    }
    return json.dumps(rule, indent=2)


def format_hunting_query_yaml(body: str, ctx: FormatContext) -> str:
    doc = {
        "id": ctx.external_rule_id or f"metasec-{ctx.rule_id}",
        "name": ctx.title,
        "description": ctx.description or "",
        "requiredDataConnectors": [],
        "tactics": _sentinel_tactics(ctx),
        "relevantTechniques": _parent_techniques(ctx),
        "query": body,
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)


def format_workbook_panel(body: str, ctx: FormatContext) -> str:
    panel = {
        "type": 3,
        "content": {
            "version": "KqlItem/1.0",
            "query": body,
            "size": 0,
            "title": ctx.title,
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": "table",
        },
        "name": f"query-{ctx.rule_id or 'tf'}",
    }
    return json.dumps(panel, indent=2)


register("sentinel", "kql", FormatPlan(backend_format="kql", formatter=None))
register("sentinel", "default", FormatPlan(backend_format="kql", formatter=None))
register("sentinel", "analytic_rule_arm", FormatPlan(backend_format="kql", formatter=format_analytic_rule_arm))
register("sentinel", "hunting_query_yaml", FormatPlan(backend_format="kql", formatter=format_hunting_query_yaml))
register("sentinel", "workbook_panel", FormatPlan(backend_format="kql", formatter=format_workbook_panel))

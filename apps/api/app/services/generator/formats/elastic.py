"""Elastic / OpenSearch output formatters.

Query bodies (KQL, EQL, ES|QL, Lucene) come from pySigma or the builtin
compiler. The rich artifact this phase adds is the Kibana Security
detection rule NDJSON, which carries severity, risk score, MITRE threat
mapping, interval, and indices -- ready to import via Kibana.
"""

from __future__ import annotations

import json

from app.services.generator.formats import FormatContext, FormatPlan, register

_TACTIC_META = {
    "reconnaissance": ("TA0043", "Reconnaissance"),
    "resource development": ("TA0042", "Resource Development"),
    "initial access": ("TA0001", "Initial Access"),
    "execution": ("TA0002", "Execution"),
    "persistence": ("TA0003", "Persistence"),
    "privilege escalation": ("TA0004", "Privilege Escalation"),
    "defense evasion": ("TA0005", "Defense Evasion"),
    "credential access": ("TA0006", "Credential Access"),
    "discovery": ("TA0007", "Discovery"),
    "lateral movement": ("TA0008", "Lateral Movement"),
    "collection": ("TA0009", "Collection"),
    "command and control": ("TA0011", "Command and Control"),
    "exfiltration": ("TA0010", "Exfiltration"),
    "impact": ("TA0040", "Impact"),
}

_TECH_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1218": "System Binary Proxy Execution",
    "T1218.011": "Rundll32",
    "T1003": "OS Credential Dumping",
    "T1486": "Data Encrypted for Impact",
}

_RISK = {"critical": 90, "high": 73, "medium": 47, "low": 21, "informational": 7}
_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "low"}

_DEFAULT_INDEX = {
    "elastic": ["logs-*", "winlogbeat-*", "logs-windows.*", "logs-endpoint.events.*"],
    "opensearch": ["logs-*", "winlogbeat-*"],
}


def _threat_block(ctx: FormatContext) -> list[dict]:
    """Build the Kibana threat[] block grouping sub-techniques under techniques."""
    if not ctx.mitre_tactics and not ctx.mitre_techniques:
        return []
    # one entry per tactic, attaching all techniques (Kibana tolerates this).
    parents: dict[str, list[str]] = {}
    for t in ctx.mitre_techniques:
        parent = t.split(".")[0]
        parents.setdefault(parent, [])
        if "." in t:
            parents[parent].append(t)
    technique_objs = []
    for parent, subs in sorted(parents.items()):
        obj = {
            "id": parent,
            "name": _TECH_NAMES.get(parent, parent),
            "reference": f"https://attack.mitre.org/techniques/{parent}/",
        }
        if subs:
            obj["subtechnique"] = [
                {
                    "id": s,
                    "name": _TECH_NAMES.get(s, s),
                    "reference": f"https://attack.mitre.org/techniques/{s.replace('.', '/')}/",
                }
                for s in sorted(subs)
            ]
        technique_objs.append(obj)

    blocks = []
    for tactic in ctx.mitre_tactics:
        tid, tname = _TACTIC_META.get(tactic.lower(), ("", tactic))
        blocks.append(
            {
                "framework": "MITRE ATT&CK",
                "tactic": {"id": tid, "name": tname, "reference": f"https://attack.mitre.org/tactics/{tid}/"},
                "technique": technique_objs,
            }
        )
    if not blocks and technique_objs:
        blocks.append({"framework": "MITRE ATT&CK", "technique": technique_objs})
    return blocks


def _detection_rule(body: str, ctx: FormatContext, language: str) -> dict:
    sev = (ctx.severity or "medium").lower()
    indices = _DEFAULT_INDEX.get(ctx.target, _DEFAULT_INDEX["elastic"])
    rule_id = ctx.external_rule_id or f"metasec-{ctx.rule_id or 'rule'}"
    return {
        "id": rule_id,
        "rule_id": rule_id,
        "type": "query",
        "language": language,
        "query": body,
        "name": f"MetaSec Security Center - {ctx.title}",
        "description": ctx.description or ctx.title,
        "severity": _SEVERITY.get(sev, "medium"),
        "risk_score": _RISK.get(sev, 47),
        "interval": "5m",
        "from": "now-9m",
        "to": "now",
        "index": indices,
        "enabled": True,
        "tags": ["MetaSec Security Center", *[f"Tactic: {t}" for t in ctx.mitre_tactics], *ctx.mitre_techniques],
        "threat": _threat_block(ctx),
        "max_signals": 100,
        "references": ctx.references,
    }


def format_detection_rule_ndjson(body: str, ctx: FormatContext) -> str:
    # NDJSON = one compact JSON object per line.
    return json.dumps(_detection_rule(body, ctx, "kuery"), separators=(",", ":"))


def format_opensearch_monitor(body: str, ctx: FormatContext) -> str:
    return json.dumps(_detection_rule(body, ctx, "lucene"), separators=(",", ":"))


# Elastic: query-shape formats pass through; detection rule is wrapped.
register("elastic", "kql", FormatPlan(backend_format="kql", formatter=None))
register("elastic", "default", FormatPlan(backend_format="kql", formatter=None))
register("elastic", "lucene", FormatPlan(backend_format="lucene", formatter=None))
register("elastic", "eql", FormatPlan(backend_format="eql", formatter=None))
register("elastic", "esql", FormatPlan(backend_format="esql", formatter=None))
register("elastic", "detection_rule_ndjson", FormatPlan(backend_format="kql", formatter=format_detection_rule_ndjson))

# OpenSearch.
register("opensearch", "kql", FormatPlan(backend_format="kql", formatter=None))
register("opensearch", "default", FormatPlan(backend_format="kql", formatter=None))
register("opensearch", "dsl", FormatPlan(backend_format="dsl", formatter=None))
register("opensearch", "detection_rule_ndjson", FormatPlan(backend_format="lucene", formatter=format_opensearch_monitor))

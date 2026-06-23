"""Plain-English explanation of a generated query (G10).

Heuristic, target-aware. Not a full parser — it recognizes the common
shapes the generator emits (field=value, contains/startswith/endswith,
IN lists, boolean joins, aggregation tails) and narrates them.
"""

from __future__ import annotations

import re


def _humanize_clause(text: str) -> str:
    text = text.strip()
    # Splunk/LogScale  field="*x*"
    m = re.match(r'^([\w.\-]+)\s*=\s*"?\*(.+?)\*"?$', text)
    if m:
        return f"{m.group(1)} contains \"{m.group(2)}\""
    m = re.match(r'^([\w.\-]+)\s*=\s*"?\*(.+?)"?$', text)
    if m:
        return f"{m.group(1)} ends with \"{m.group(2)}\""
    m = re.match(r'^([\w.\-]+)\s*=\s*"?(.+?)\*"?$', text)
    if m:
        return f"{m.group(1)} starts with \"{m.group(2)}\""
    # KQL contains/startswith/endswith
    m = re.match(r"^([\w.\-]+)\s+(contains|startswith|endswith|has|matches regex)\s+(.+)$", text)
    if m:
        verb = {"contains": "contains", "startswith": "starts with", "endswith": "ends with", "has": "contains the term", "matches regex": "matches regex"}[m.group(2)]
        return f"{m.group(1)} {verb} {m.group(3)}"
    return text


def explain(query: str, target: str) -> str:
    if not query or not query.strip():
        return "Empty query — nothing to explain."

    parts: list[str] = []
    q = query.strip()

    # Base selector / source.
    if target == "splunk":
        base_match = re.match(r"^(index=\S+(?:\s+sourcetype=\S+)?)", q)
        if base_match:
            parts.append(f"Search Splunk events from {base_match.group(1)}.")
    elif target == "sentinel":
        tbl = re.match(r"^(\w+)", q)
        if tbl:
            parts.append(f"Query the {tbl.group(1)} table in Microsoft Sentinel.")
    elif target in ("elastic", "opensearch"):
        parts.append("Match documents where:")
    elif target == "qradar":
        parts.append("Select events in QRadar where:")

    # Field predicates (IN lists are a strong signal).
    in_lists = re.findall(r'([\w.\-]+)\s+IN\s+\(([^)]+)\)', q)
    for field, values in in_lists:
        count = len([v for v in values.split(",") if v.strip()])
        parts.append(f"{field} matches any of {count} values")

    # Aggregation tail.
    agg = re.search(r"(stats|summarize)\s+(\w+).*?(?:by\s+([\w,\s]+?))?\s*\|?\s*where\s+\w+\s*([<>=]+)\s*(\d+)", q)
    if agg:
        grp = agg.group(3).strip() if agg.group(3) else "all events"
        parts.append(f"then aggregate ({agg.group(2)}) grouped by {grp} and keep groups where the count {agg.group(4)} {agg.group(5)}")

    # MITRE annotation hint.
    if "mitre_attack" in q or "attack.mitre.org" in q:
        techs = re.findall(r"T\d{4}(?:\.\d{3})?", q)
        if techs:
            parts.append(f"Mapped to ATT&CK technique(s): {', '.join(sorted(set(techs)))}.")

    # Notable / RBA hints (savedsearches.conf).
    if "action.notable" in q:
        parts.append("Creates an Enterprise Security notable event.")
    if "action.risk" in q:
        score = re.search(r"_risk_score\s*=\s*(\d+)", q)
        parts.append(f"Contributes risk{f' (score {score.group(1)})' if score else ''} via Risk-Based Alerting.")

    if len(parts) <= 1:
        # Fall back to clause-by-clause narration of the predicate body.
        body = re.split(r"\|\s*where|\bwhere\b", q, maxsplit=1)
        predicate = body[-1] if len(body) > 1 else q
        clauses = re.split(r"\s+(?:AND|OR|and|or)\s+", predicate)
        described = [_humanize_clause(c) for c in clauses[:6] if c.strip() and not c.strip().startswith("index=")]
        if described:
            parts.append("Conditions: " + "; ".join(described) + ".")

    return " ".join(parts) if parts else "This query matches events using the conditions shown."

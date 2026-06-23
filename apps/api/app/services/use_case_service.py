import json
from collections import defaultdict
from sqlalchemy.orm import Session
from app.models.rule import NormalizedRule, RawRule, Repository
from app.services.rule_service import public_source, to_rule_item

TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TACTIC_ALIASES = {item.lower(): item for item in TACTIC_ORDER}


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def _technique_name(technique_id: str) -> str:
    return technique_id


def _rows(db: Session):
    return db.query(NormalizedRule, RawRule, Repository).join(RawRule, NormalizedRule.raw_rule_id == RawRule.id).join(Repository, RawRule.repository_id == Repository.id).all()


def list_use_cases(
    db: Session,
    tactic: str | None = None,
    technique: str | None = None,
    product: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    q: str | None = None,
    limit: int = 250,
):
    groups: dict[str, dict] = {}
    query_text = q.lower().strip() if q else None
    tactic_filter = TACTIC_ALIASES.get(tactic.lower(), tactic) if tactic else None
    technique_filter = technique.upper() if technique else None
    for normalized, raw, repo in _rows(db):
        tactics = _json_list(normalized.mitre_tactics)
        techniques = _json_list(normalized.mitre_techniques)
        if tactic_filter and tactic_filter not in tactics:
            continue
        if technique_filter and technique_filter not in techniques:
            continue
        if product and normalized.product != product:
            continue
        if category and normalized.category != category:
            continue
        if severity and normalized.severity != severity:
            continue
        if source and public_source(repo.name) != source:
            continue
        if query_text:
            haystack = " ".join([normalized.title or "", normalized.description or "", repo.name, " ".join(tactics), " ".join(techniques)]).lower()
            if query_text not in haystack:
                continue
        keys = techniques or [f"TACTIC:{item}" for item in tactics] or ["UNMAPPED"]
        for key in keys:
            if key not in groups:
                label_tactics = tactics
                if key.startswith("TACTIC:"):
                    label_tactics = [key.removeprefix("TACTIC:")]
                groups[key] = {
                    "id": key,
                    "technique_id": None if key.startswith("TACTIC:") or key == "UNMAPPED" else key,
                    "name": _technique_name(key),
                    "tactics": label_tactics,
                    "platforms": set(),
                    "products": set(),
                    "categories": set(),
                    "sources": set(),
                    "severities": defaultdict(int),
                    "rule_count": 0,
                    "best_rule_id": None,
                    "best_rule_title": None,
                    "best_quality_score": -1,
                    "target_support": ["splunk", "sentinel", "elastic", "opensearch", "qradar", "chronicle", "logscale"],
                }
            group = groups[key]
            group["rule_count"] += 1
            if normalized.platform:
                group["platforms"].add(normalized.platform)
            if normalized.product:
                group["products"].add(normalized.product)
            if normalized.category:
                group["categories"].add(normalized.category)
            group["sources"].add(public_source(repo.name))
            group["severities"][normalized.severity or "unknown"] += 1
            if normalized.quality_score > group["best_quality_score"]:
                group["best_quality_score"] = normalized.quality_score
                group["best_rule_id"] = normalized.id
                group["best_rule_title"] = normalized.title
    output = []
    for item in groups.values():
        item["platforms"] = sorted(item["platforms"])
        item["products"] = sorted(item["products"])
        item["categories"] = sorted(item["categories"])
        item["sources"] = sorted(item["sources"])
        item["severities"] = dict(sorted(item["severities"].items()))
        if item["id"].startswith("TACTIC:"):
            item["name"] = item["id"].removeprefix("TACTIC:")
        if item["id"] == "UNMAPPED":
            item["name"] = "Unmapped Rules"
        output.append(item)
    output.sort(key=lambda item: (-item["rule_count"], item["id"]))
    return output[:limit]


def rules_for_use_case(db: Session, use_case_id: str, limit: int = 200):
    query = db.query(NormalizedRule, RawRule, Repository).join(RawRule, NormalizedRule.raw_rule_id == RawRule.id).join(Repository, RawRule.repository_id == Repository.id)
    if use_case_id == "UNMAPPED":
        rows = [row for row in query.all() if not _json_list(row[0].mitre_techniques) and not _json_list(row[0].mitre_tactics)]
    elif use_case_id.startswith("TACTIC:"):
        tactic = use_case_id.removeprefix("TACTIC:")
        rows = [row for row in query.all() if tactic in _json_list(row[0].mitre_tactics)]
    else:
        rows = [row for row in query.all() if use_case_id.upper() in _json_list(row[0].mitre_techniques)]
    rows.sort(key=lambda row: row[0].quality_score, reverse=True)
    return [to_rule_item(row) for row in rows[:limit]]


def filter_options(db: Session):
    rows = db.query(NormalizedRule, RawRule, Repository).join(RawRule, NormalizedRule.raw_rule_id == RawRule.id).join(Repository, RawRule.repository_id == Repository.id).all()
    options = {
        "tactics": set(),
        "techniques": set(),
        "products": set(),
        "services": set(),
        "categories": set(),
        "severities": set(),
        "sources": set(),
    }
    for normalized, raw, repo in rows:
        options["tactics"].update(_json_list(normalized.mitre_tactics))
        options["techniques"].update(_json_list(normalized.mitre_techniques))
        if normalized.product:
            options["products"].add(normalized.product)
        if normalized.service:
            options["services"].add(normalized.service)
        if normalized.category:
            options["categories"].add(normalized.category)
        if normalized.severity:
            options["severities"].add(normalized.severity)
        options["sources"].add(public_source(repo.name))
    return {key: sorted(value) for key, value in options.items()}

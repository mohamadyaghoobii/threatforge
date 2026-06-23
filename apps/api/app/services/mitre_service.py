import json
from collections import Counter
from sqlalchemy.orm import Session
from app.models.rule import NormalizedRule


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def tactic_counts(db: Session) -> list[dict]:
    counter: Counter[str] = Counter()
    for row in db.query(NormalizedRule.mitre_tactics).all():
        for tactic in _json_list(row[0]):
            counter[tactic] += 1
    return [{"tactic": key, "rule_count": value} for key, value in sorted(counter.items())]


def technique_counts(db: Session) -> list[dict]:
    counter: Counter[str] = Counter()
    for row in db.query(NormalizedRule.mitre_techniques).all():
        for technique in _json_list(row[0]):
            counter[technique] += 1
    return [{"technique_id": key, "rule_count": value} for key, value in sorted(counter.items())]

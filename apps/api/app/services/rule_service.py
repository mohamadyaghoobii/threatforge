import json
from sqlalchemy.orm import Session
from app.models.rule import NormalizedRule, RawRule, Repository


def _json_list(value: str | None) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def public_source(repo_name: str | None) -> str:
    """Anonymize the upstream repository name for any client-facing output.

    We use external rules as raw material but do not expose which GitHub
    repository each rule came from. The local pack stays distinguishable.
    """
    if repo_name == "local_custom_detection_pack":
        return "MetaSec Custom"
    return "MetaSec Library"


def list_rules(
    db: Session,
    technique: str | None = None,
    tactic: str | None = None,
    severity: str | None = None,
    product: str | None = None,
    service: str | None = None,
    category: str | None = None,
    source: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
):
    query = db.query(NormalizedRule, RawRule, Repository).join(RawRule, NormalizedRule.raw_rule_id == RawRule.id).join(Repository, RawRule.repository_id == Repository.id)
    if technique:
        query = query.filter(NormalizedRule.mitre_techniques.contains(technique.upper()))
    if tactic:
        query = query.filter(NormalizedRule.mitre_tactics.contains(tactic))
    if severity:
        query = query.filter(NormalizedRule.severity == severity)
    if product:
        query = query.filter(NormalizedRule.product == product)
    if service:
        query = query.filter(NormalizedRule.service == service)
    if category:
        query = query.filter(NormalizedRule.category == category)
    if source:
        query = query.filter(Repository.name == source)
    if q:
        like = f"%{q}%"
        query = query.filter(NormalizedRule.title.ilike(like) | NormalizedRule.description.ilike(like) | NormalizedRule.mitre_techniques.ilike(like))
    return query.order_by(NormalizedRule.quality_score.desc(), NormalizedRule.id.desc()).offset(offset).limit(limit).all()


def get_rule_detail(db: Session, rule_id: int):
    return db.query(NormalizedRule, RawRule, Repository).join(RawRule, NormalizedRule.raw_rule_id == RawRule.id).join(Repository, RawRule.repository_id == Repository.id).filter(NormalizedRule.id == rule_id).first()


def to_rule_item(row):
    normalized, raw, repo = row
    return {
        "id": normalized.id,
        "title": normalized.title,
        "severity": normalized.severity,
        "product": normalized.product,
        "service": normalized.service,
        "category": normalized.category,
        "mitre_tactics": _json_list(normalized.mitre_tactics),
        "mitre_techniques": _json_list(normalized.mitre_techniques),
        "source_repo": public_source(repo.name),
        "quality_score": normalized.quality_score,
    }


def to_rule_detail(row):
    normalized, raw, repo = row
    return {
        "id": normalized.id,
        "raw_rule_id": raw.id,
        "title": normalized.title,
        "description": normalized.description,
        "status": normalized.status,
        "severity": normalized.severity,
        "product": normalized.product,
        "service": normalized.service,
        "category": normalized.category,
        "mitre_tactics": _json_list(normalized.mitre_tactics),
        "mitre_techniques": _json_list(normalized.mitre_techniques),
        "quality_score": normalized.quality_score,
        "normalized_json": json.loads(normalized.normalized_json),
        "raw_yaml": raw.raw_yaml,
        "source_repo": public_source(repo.name),
        "source_path": "",
        "license": raw.license,
    }

from hashlib import sha256
import json
from pathlib import Path
from sqlalchemy.orm import Session
from detectionforge_rule_engine import normalize_rule, parse_rule_yaml
from app.models.rule import NormalizedRule, RawRule, Repository
from app.services.config_service import list_yaml_files


def _source_url(repo: Repository, path: Path) -> str | None:
    if not repo.local_path:
        return None
    try:
        rel = path.relative_to(Path(repo.local_path)).as_posix()
    except ValueError:
        return None
    base = repo.url.removesuffix(".git")
    return f"{base}/blob/{repo.branch}/{rel}"


def _is_sigma_like(data: object) -> bool:
    """Cheap filter: only import docs that look like a detection rule.

    SigmaHQ and friends ship many YAML files that are not rules
    (pipelines, configs, docs). Importing those just produces noise.
    """
    return isinstance(data, dict) and "detection" in data and "logsource" in data


def import_repository_rules(db: Session, repo: Repository) -> tuple[int, int, int, int]:
    if not repo.local_path:
        return 0, 0, 0, 0
    root = Path(repo.local_path)
    files_seen = 0
    raw_created = 0
    normalized_created = 0
    parse_errors = 0
    for path in list_yaml_files(root):
        files_seen += 1
        # Each file gets its own savepoint so one bad rule can't roll back
        # the whole repository's progress.
        try:
            with db.begin_nested():
                raw_yaml = path.read_text(encoding="utf-8", errors="ignore")
                parsed = parse_rule_yaml(raw_yaml)
                if not _is_sigma_like(parsed.raw):
                    continue
                raw_hash = sha256(raw_yaml.encode("utf-8")).hexdigest()
                source_path = str(path.relative_to(root).as_posix())
                existing = db.query(RawRule).filter(
                    RawRule.repository_id == repo.id,
                    RawRule.source_path == source_path,
                    RawRule.raw_hash == raw_hash,
                ).first()
                if existing:
                    continue
                raw = RawRule(
                    repository_id=repo.id,
                    source_path=source_path,
                    source_url=_source_url(repo, path),
                    commit_hash=repo.last_commit_hash,
                    raw_yaml=raw_yaml,
                    raw_hash=raw_hash,
                    license=repo.license,
                )
                db.add(raw)
                db.flush()
                raw_created += 1
                normalized = normalize_rule(parsed)
                normalized_row = NormalizedRule(
                    raw_rule_id=raw.id,
                    external_rule_id=normalized.external_rule_id,
                    title=normalized.title,
                    description=normalized.description,
                    status=normalized.status,
                    severity=normalized.severity,
                    platform=normalized.platform,
                    product=normalized.product,
                    service=normalized.service,
                    category=normalized.category,
                    normalized_json=normalized.model_dump_json(),
                    mitre_tactics=json.dumps(normalized.mitre.tactics),
                    mitre_techniques=json.dumps(normalized.mitre.techniques),
                    quality_score=normalized.quality_score,
                )
                db.add(normalized_row)
                normalized_created += 1
        except Exception:
            parse_errors += 1
            continue
    db.commit()
    return files_seen, raw_created, normalized_created, parse_errors


def import_all_rules(db: Session) -> dict[str, int]:
    repos = db.query(Repository).filter(Repository.enabled == 1).all()
    totals = {
        "repositories": len(repos),
        "files_seen": 0,
        "raw_rules_created": 0,
        "normalized_created": 0,
        "parse_errors": 0,
    }
    for repo in repos:
        try:
            files_seen, raw_created, normalized_created, parse_errors = import_repository_rules(db, repo)
            totals["files_seen"] += files_seen
            totals["raw_rules_created"] += raw_created
            totals["normalized_created"] += normalized_created
            totals["parse_errors"] += parse_errors
        except Exception:
            totals["parse_errors"] += 1
            db.rollback()
    return totals

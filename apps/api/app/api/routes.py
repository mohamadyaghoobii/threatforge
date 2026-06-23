from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app.db.session import get_db
from app.schemas.rule import ConvertRequest, ConvertResponse, FilterOptionsOut, ImportResult, MitreTacticOut, MitreTechniqueOut, RepositoryOut, RuleDetail, RuleListItem, SyncResult, TargetOut, UseCaseOut
from app.services.catalog_service import targets_catalog
from app.services.conversion_service import convert_rule
from app.services.import_service import import_all_rules
from app.services.mitre_service import tactic_counts, technique_counts
from app.services.repository_service import ensure_repositories_from_config, sync_enabled_repositories
from app.services.rule_service import get_rule_detail, list_rules, to_rule_detail, to_rule_item
from app.services.use_case_service import filter_options, list_use_cases, rules_for_use_case

router = APIRouter(prefix="/api")


@router.get("/repositories", response_model=list[RepositoryOut])
def repositories(db: Session = Depends(get_db)):
    return ensure_repositories_from_config(db)


@router.post("/repositories/sync", response_model=list[SyncResult])
def sync_repositories(db: Session = Depends(get_db)):
    results = sync_enabled_repositories(db)
    return [
        SyncResult(repository=repo.name, status=status, commit_hash=commit, error=error)
        for repo, status, commit, error in results
    ]


@router.post("/rules/import", response_model=ImportResult)
def import_rules(db: Session = Depends(get_db)):
    return import_all_rules(db)


@router.get("/rules", response_model=list[RuleListItem])
def rules(
    technique: str | None = None,
    tactic: str | None = None,
    severity: str | None = None,
    product: str | None = None,
    service: str | None = None,
    category: str | None = None,
    source: str | None = None,
    q: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    rows = list_rules(db, technique=technique, tactic=tactic, severity=severity, product=product, service=service, category=category, source=source, q=q, limit=limit, offset=offset)
    return [to_rule_item(row) for row in rows]


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def rule_detail(rule_id: int, db: Session = Depends(get_db)):
    row = get_rule_detail(db, rule_id)
    if not row:
        raise HTTPException(status_code=404, detail="Rule not found")
    return to_rule_detail(row)


@router.post("/convert", response_model=ConvertResponse)
def convert(request: ConvertRequest, db: Session = Depends(get_db)):
    try:
        return convert_rule(db, request.rule_id, request.target, request.profile, request.output_format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/catalog/targets", response_model=list[TargetOut])
def targets():
    return targets_catalog()


@router.get("/filters", response_model=FilterOptionsOut)
def filters(db: Session = Depends(get_db)):
    return filter_options(db)


@router.get("/use-cases", response_model=list[UseCaseOut])
def use_cases(
    tactic: str | None = None,
    technique: str | None = None,
    product: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    q: str | None = None,
    limit: int = Query(250, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    return list_use_cases(db, tactic=tactic, technique=technique, product=product, category=category, severity=severity, source=source, q=q, limit=limit)


@router.get("/use-cases/{use_case_id}/rules", response_model=list[RuleListItem])
def use_case_rules(use_case_id: str, limit: int = Query(200, ge=1, le=1000), db: Session = Depends(get_db)):
    return rules_for_use_case(db, use_case_id, limit=limit)


@router.get("/mitre/tactics", response_model=list[MitreTacticOut])
def mitre_tactics(db: Session = Depends(get_db)):
    return tactic_counts(db)


@router.get("/mitre/techniques", response_model=list[MitreTechniqueOut])
def mitre_techniques(db: Session = Depends(get_db)):
    return technique_counts(db)


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    from app.models.rule import NormalizedRule, Repository

    return {
        "rules": db.query(NormalizedRule).count(),
        "repositories": db.query(Repository).filter(Repository.enabled == 1).count(),
        "techniques": len(technique_counts(db)),
        "tactics": len(tactic_counts(db)),
    }

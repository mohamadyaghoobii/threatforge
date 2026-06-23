"""Generator V2 REST endpoints.

These are the new ``/api/generator/*`` endpoints. The legacy
``POST /api/convert`` endpoint still works and delegates here under the
hood.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.generation import GenerationJob
from app.models.rule import NormalizedRule, RawRule
from app.schemas.generator import (
    BulkConvertRequest,
    BulkConvertResponse,
    CacheStatsOut,
    ConvertRequestV2,
    ConvertResponseV2,
    ExplainRequest,
    ExplainResponse,
    JobResultOut,
    JobStatusOut,
    JobSubmitResponse,
    OptimizeRequest,
    OptimizeResponse,
    PipelineOut,
    ProfileDetailOut,
    ProfileSummaryOut,
    RoundTripRequest,
    RoundTripResponse,
    TargetCatalogOut,
    ValidateRequest,
    ValidateResponse,
    WarningCodeOut,
)
from app.services.generator import (
    bulk,
    cache,
    engine,
    explain as explain_mod,
    optimize as optimize_mod,
    profiles,
    roundtrip as roundtrip_mod,
    targets,
    validators,
    warnings as warnings_module,
)

router = APIRouter(prefix="/api/generator", tags=["generator"])


@router.get("/targets", response_model=list[TargetCatalogOut])
def get_targets():
    return targets.list_targets()


@router.get("/profiles", response_model=list[ProfileSummaryOut])
def get_profiles(target: str | None = Query(None)):
    items = profiles.list_profiles(target=target)
    return [
        ProfileSummaryOut(
            id=p.id,
            name=p.name,
            description=p.description,
            audience=p.audience,
            field_mapping_pack=p.field_mapping_pack,
            pysigma_pipeline=p.pysigma_pipeline,
            output_formats=p.output_formats,
        )
        for p in items
    ]


@router.get("/profiles/{profile_id}", response_model=ProfileDetailOut)
def get_profile_detail(profile_id: str):
    profile = profiles.get_profile(profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail=f"Profile {profile_id!r} not found")
    return ProfileDetailOut(
        id=profile.id,
        target=profile.target,
        name=profile.name,
        description=profile.description,
        audience=profile.audience,
        base=profile.base.model_dump(exclude_none=True),
        default_event_code_by_category=profile.default_event_code_by_category,
        field_mapping_pack=profile.field_mapping_pack,
        pysigma_pipeline=profile.pysigma_pipeline,
        processing=profile.processing,
        output_formats=profile.output_formats,
        output_defaults={k: v.model_dump(exclude_none=True) for k, v in profile.output_defaults.items()},
        severity_map=profile.severity_map,
        entity_inference=profile.entity_inference,
        mitre_metadata_strategy=profile.mitre_metadata_strategy,
    )


@router.get("/pipelines", response_model=list[PipelineOut])
def get_pipelines():
    return []


@router.get("/warning-codes", response_model=list[WarningCodeOut])
def get_warning_codes():
    return warnings_module.warning_code_catalog()


@router.post("/convert", response_model=ConvertResponseV2)
def convert(request: ConvertRequestV2, db: Session = Depends(get_db)):
    try:
        result = engine.convert(
            db,
            request.rule_id,
            target=request.target,
            profile=request.profile,
            output_format=request.output_format,
            persist=request.persist,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.to_dict()


@router.post("/preview", response_model=ConvertResponseV2)
def preview(request: ConvertRequestV2, db: Session = Depends(get_db)):
    try:
        result = engine.convert(
            db,
            request.rule_id,
            target=request.target,
            profile=request.profile,
            output_format=request.output_format,
            persist=False,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result.to_dict()


@router.post("/convert-bulk", response_model=BulkConvertResponse)
def convert_bulk(request: BulkConvertRequest, db: Session = Depends(get_db)):
    results = []
    succeeded = 0
    failed = 0
    for item in request.items:
        try:
            result = engine.convert(
                db,
                item.rule_id,
                target=item.target,
                profile=item.profile,
                output_format=item.output_format,
                persist=request.persist,
            )
            if result.status == "success":
                succeeded += 1
            else:
                failed += 1
            results.append(result.to_dict())
        except ValueError as exc:
            failed += 1
            results.append(
                ConvertResponseV2(
                    rule_id=item.rule_id,
                    target=item.target,
                    profile=item.profile,
                    output_format=item.output_format,
                    query="",
                    status="error",
                    warnings=[],
                    error=str(exc),
                ).model_dump()
            )
    return BulkConvertResponse(
        total=len(request.items),
        succeeded=succeeded,
        failed=failed,
        results=results,
    )


@router.post("/validate", response_model=ValidateResponse)
def validate(request: ValidateRequest):
    if request.mode not in {"offline", "live"}:
        raise HTTPException(status_code=400, detail="mode must be 'offline' or 'live'")
    result = validators.validate(request.target, request.query, request.mode)
    return ValidateResponse(
        ok=result.ok,
        mode=result.mode,
        target=result.target,
        errors=result.errors,
        warnings=[],
        elapsed_ms=result.elapsed_ms,
        note=result.note,
    )


@router.post("/explain", response_model=ExplainResponse)
def explain(request: ExplainRequest):
    target_id = targets.normalize_target(request.target)
    text = explain_mod.explain(request.query, target_id)
    return ExplainResponse(target=target_id, profile=request.profile, explanation=text)


@router.post("/optimize", response_model=OptimizeResponse)
def optimize(request: OptimizeRequest):
    target_id = targets.normalize_target(request.target)
    optimized, changed, notes = optimize_mod.optimize(request.query, target_id)
    return OptimizeResponse(
        target=target_id,
        original=request.query,
        optimized=optimized,
        changed=changed,
        notes=notes,
    )


@router.post("/round-trip", response_model=RoundTripResponse)
def round_trip(request: RoundTripRequest, db: Session = Depends(get_db)):
    import yaml

    target_id = targets.normalize_target(request.target)
    detection: dict = {}
    if request.rule_id is not None:
        normalized = db.query(NormalizedRule).filter(NormalizedRule.id == request.rule_id).first()
        if normalized:
            raw = db.query(RawRule).filter(RawRule.id == normalized.raw_rule_id).first()
            if raw:
                try:
                    data = yaml.safe_load(raw.raw_yaml) or {}
                    detection = data.get("detection", {}) if isinstance(data, dict) else {}
                except yaml.YAMLError:
                    detection = {}
    result = roundtrip_mod.round_trip(request.query, detection)
    return RoundTripResponse(
        target=target_id,
        parsed=result["parsed"],
        semantic_match=result["semantic_match"],
        coverage=result.get("coverage"),
        missing_literals=result.get("missing_literals", []),
        note=result.get("note"),
    )


@router.get("/cache-stats", response_model=CacheStatsOut)
def get_cache_stats(db: Session = Depends(get_db)):
    s = cache.stats(db)
    return CacheStatsOut(enabled=s["enabled"], entries=s["entries"], hits=s["hits"], bytes=s["bytes"])


@router.delete("/cache")
def invalidate_cache(target: str | None = Query(None), db: Session = Depends(get_db)):
    cleared = cache.clear(db, target=target)
    return {"invalidated": cleared}


@router.post("/jobs", response_model=JobSubmitResponse)
def submit_job(request: BulkConvertRequest):
    items = [item.model_dump() for item in request.items]
    job_id = bulk.submit(items, persist=request.persist)
    return JobSubmitResponse(job_id=job_id, status="pending", total=len(items))


@router.get("/jobs", response_model=list[JobStatusOut])
def list_jobs(limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db)):
    rows = db.query(GenerationJob).order_by(GenerationJob.id.desc()).limit(limit).all()
    return [_job_status(j) for j in rows]


@router.get("/jobs/{job_id}", response_model=JobResultOut)
def get_job(job_id: int, db: Session = Depends(get_db)):
    job = db.get(GenerationJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    base = _job_status(job).model_dump()
    results = json.loads(job.result_json) if job.result_json else []
    return JobResultOut(**base, results=results)


def _job_status(job: GenerationJob) -> JobStatusOut:
    return JobStatusOut(
        id=job.id,
        kind=job.kind,
        status=job.status,
        total=job.total,
        completed=job.completed,
        succeeded=job.succeeded,
        failed=job.failed,
        error=job.error,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
    )

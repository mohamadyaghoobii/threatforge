"""Dashboard generator REST endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.dashboard import Dashboard
from app.schemas.dashboard import (
    DashboardCatalogOut,
    DashboardDetailOut,
    DashboardGenerateRequest,
    DashboardGenerateResponse,
    DashboardSummaryOut,
)
from app.services.dashboard import service

router = APIRouter(prefix="/api/dashboards", tags=["dashboards"])


@router.get("/catalog", response_model=DashboardCatalogOut)
def catalog():
    return DashboardCatalogOut(targets=sorted(service.SUPPORTED_TARGETS), layouts=service.supported_layouts())


@router.post("/generate", response_model=DashboardGenerateResponse)
def generate(request: DashboardGenerateRequest, db: Session = Depends(get_db)):
    try:
        result = service.generate(
            db,
            name=request.name,
            target=request.target,
            layout=request.layout,
            profile=request.profile,
            scope=request.scope.model_dump(),
            earliest=request.earliest,
            latest=request.latest,
            save=request.save,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return result


@router.get("", response_model=list[DashboardSummaryOut])
def list_dashboards(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    rows = db.query(Dashboard).order_by(Dashboard.id.desc()).limit(limit).all()
    return [
        DashboardSummaryOut(
            id=d.id, name=d.name, target=d.target, layout=d.layout,
            output_format=d.output_format, panel_count=d.panel_count, created_at=d.created_at,
        )
        for d in rows
    ]


@router.get("/{dashboard_id}", response_model=DashboardDetailOut)
def get_dashboard(dashboard_id: int, db: Session = Depends(get_db)):
    d = db.get(Dashboard, dashboard_id)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")
    scope = json.loads(d.scope_json) if d.scope_json else {}
    return DashboardDetailOut(
        id=d.id, name=d.name, target=d.target, layout=d.layout, output_format=d.output_format,
        panel_count=d.panel_count, created_at=d.created_at, profile=d.profile, scope=scope, artifact=d.artifact_text,
    )


@router.delete("/{dashboard_id}")
def delete_dashboard(dashboard_id: int, db: Session = Depends(get_db)):
    d = db.get(Dashboard, dashboard_id)
    if d is None:
        raise HTTPException(status_code=404, detail=f"Dashboard {dashboard_id} not found")
    db.delete(d)
    db.commit()
    return {"deleted": dashboard_id}

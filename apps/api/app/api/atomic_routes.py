"""Atomic Bible REST endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.atomic import service

router = APIRouter(prefix="/api/atomic", tags=["atomic"])


@router.get("/stats")
def atomic_stats(db: Session = Depends(get_db)):
    return service.stats(db)


@router.get("/techniques")
def atomic_techniques(q: str | None = None, platform: str | None = None,
                      limit: int = Query(500, ge=1, le=2000), db: Session = Depends(get_db)):
    return service.techniques(db, q=q, platform=platform, limit=limit)


@router.get("/techniques/{technique_id}/tests")
def atomic_tests_for(technique_id: str, db: Session = Depends(get_db)):
    return service.tests_for(db, technique_id)


@router.get("/tests")
def atomic_search(q: str | None = None, platform: str | None = None, executor: str | None = None,
                  limit: int = Query(300, ge=1, le=2000), db: Session = Depends(get_db)):
    return service.search_tests(db, q=q, platform=platform, executor=executor, limit=limit)

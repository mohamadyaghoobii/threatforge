"""Threat Intelligence REST endpoints."""

from __future__ import annotations

import csv
import io
import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.intel import scheduler, seed, service, stix

router = APIRouter(prefix="/api/intel", tags=["intel"])


@router.get("/stats")
def intel_stats(db: Session = Depends(get_db)):
    return service.stats(db)


@router.get("/status")
def intel_status():
    """Auto-update scheduler state: enabled, interval, last/next run."""
    return scheduler.status()


@router.get("/lookup")
def lookup(value: str, type: str | None = None, db: Session = Depends(get_db)):
    return service.lookup(db, value, ioc_type=type)


@router.post("/age")
def age(db: Session = Depends(get_db)):
    return {"aged_out": service.age_indicators(db)}


@router.get("/iocs")
def iocs(
    type: str | None = None,
    severity: str | None = None,
    category: str | None = None,
    source: str | None = None,
    min_score: int = 0,
    active: bool | None = None,
    q: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return service.list_indicators(
        db, ioc_type=type, severity=severity, category=category, source=source,
        min_score=min_score, active=active, q=q, limit=limit, offset=offset,
    )


@router.get("/useragents")
def user_agents(
    severity: str | None = None,
    tool: str | None = None,
    q: str | None = None,
    limit: int = Query(500, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    return service.list_user_agents(db, severity=severity, tool=tool, q=q, limit=limit, offset=offset)


@router.get("/sources")
def sources(db: Session = Depends(get_db)):
    return service.source_health(db)


@router.post("/refresh")
def refresh(iocs: bool = True, useragents: bool = True, db: Session = Depends(get_db)):
    return service.refresh(db, iocs=iocs, user_agents=useragents)


@router.post("/seed")
def reseed(force: bool = False, db: Session = Depends(get_db)):
    return seed.load_seed(db, force=force)


@router.get("/iocs/export.csv")
def export_iocs(type: str | None = None, severity: str | None = None, db: Session = Depends(get_db)):
    rows = service.list_indicators(db, ioc_type=type, severity=severity, limit=5000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["ioc", "type", "score", "severity", "confidence", "category", "tags", "sources", "first_seen", "last_seen", "active"])
    for r in rows:
        w.writerow([r["ioc"], r["ioc_type"], r["threat_score"], r["severity"], r["confidence"], r["category"],
                    ";".join(r["tags"]), ";".join(r["sources"]), r["first_seen"] or "", r["last_seen"] or "", r["is_active"]])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=metasec_iocs.csv"})


@router.get("/iocs/export.stix")
def export_stix(type: str | None = None, severity: str | None = None, min_score: int = 0,
                limit: int = Query(2000, ge=1, le=10000), db: Session = Depends(get_db)):
    rows = service.list_indicators(db, ioc_type=type, severity=severity, min_score=min_score, limit=limit)
    payload = stix.bundle(rows)
    return StreamingResponse(
        iter([json.dumps(payload, indent=2)]),
        media_type="application/stix+json",
        headers={"Content-Disposition": "attachment; filename=metasec_indicators.stix.json"},
    )


@router.get("/useragents/export.csv")
def export_uas(severity: str | None = None, db: Session = Depends(get_db)):
    rows = service.list_user_agents(db, severity=severity, limit=8000)
    buf = io.StringIO()
    w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["http_useragent", "tool_name", "category", "severity", "sources"])
    for r in rows:
        w.writerow([r["user_agent"], r["tool_name"], r["category"], r["severity"], ";".join(r["sources"])])
    buf.seek(0)
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=metasec_useragents.csv"})

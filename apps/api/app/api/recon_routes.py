"""OSINT / Web Recon REST endpoints."""

from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.services.recon import service

router = APIRouter(prefix="/api/recon", tags=["recon"])


class ScanRequest(BaseModel):
    target: str
    render: bool = False
    subdomains: bool = True
    probe: bool = True
    passive_intel: bool = True


@router.get("/stats")
def recon_stats(db: Session = Depends(get_db)):
    return service.stats(db)


@router.post("/scan")
def scan(request: ScanRequest, db: Session = Depends(get_db)):
    if not request.target.strip():
        raise HTTPException(status_code=400, detail="target is required")
    report = service.run_and_store(db, request.target, render=request.render, subdomains=request.subdomains,
                                   probe=request.probe, passive_intel=request.passive_intel)
    if report.get("status") == "error":
        raise HTTPException(status_code=400, detail=report.get("error", "scan failed"))
    return report


@router.get("/scans")
def list_scans(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    return service.list_scans(db, limit=limit)


@router.get("/scans/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    report = service.get_scan(db, scan_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
    return report


@router.get("/scans/{scan_id}/screenshot.png")
def screenshot(scan_id: int, db: Session = Depends(get_db)):
    b64 = service.get_screenshot(db, scan_id)
    if not b64:
        raise HTTPException(status_code=404, detail="No screenshot for this scan")
    return Response(content=base64.b64decode(b64), media_type="image/png")

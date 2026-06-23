"""Persist + query recon scans."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.recon import ReconScan
from app.services.recon import browser, engine


def run_and_store(db: Session, target: str, *, render: bool = False, subdomains: bool = True,
                  probe: bool = True, passive_intel: bool = True) -> dict[str, Any]:
    report = engine.run_scan(target, render=render, subdomains=subdomains, probe=probe, passive_intel=passive_intel)
    if report.get("status") == "error":
        return report
    row = ReconScan(
        target=report["target"], host=report.get("host", ""), status=report["status"],
        http_status=report.get("http_status"), final_url=report.get("final_url"),
        title=report.get("title"), server=report.get("server"),
        score=report.get("score", 0), grade=report.get("grade", "F"),
        technologies=json.dumps(report.get("technologies", [])),
        cms=json.dumps(report.get("cms", [])), cdn=json.dumps(report.get("cdn", [])),
        secrets_count=len(report.get("secrets", [])), subdomains_count=len(report.get("subdomains", [])),
        rendered=1 if report.get("rendered") else 0,
        report_json=json.dumps({k: v for k, v in report.items() if k != "screenshot_b64"}),
        screenshot_b64=report.get("screenshot_b64"),
        created_at=datetime.utcnow(),
    )
    db.add(row)
    db.commit()
    report["id"] = row.id
    return report


def get_scan(db: Session, scan_id: int) -> dict[str, Any] | None:
    row = db.get(ReconScan, scan_id)
    if not row:
        return None
    report = json.loads(row.report_json)
    report["id"] = row.id
    report["has_screenshot"] = bool(row.screenshot_b64)
    report["created_at"] = row.created_at.isoformat() if row.created_at else None
    return report


def get_screenshot(db: Session, scan_id: int) -> str | None:
    row = db.get(ReconScan, scan_id)
    return row.screenshot_b64 if row else None


def list_scans(db: Session, limit: int = 50) -> list[dict[str, Any]]:
    rows = db.query(ReconScan).order_by(ReconScan.id.desc()).limit(limit).all()
    return [
        {"id": r.id, "target": r.target, "host": r.host, "status": r.status,
         "http_status": r.http_status, "score": r.score, "grade": r.grade,
         "technologies": json.loads(r.technologies or "[]"), "secrets_count": r.secrets_count,
         "subdomains_count": r.subdomains_count, "rendered": bool(r.rendered),
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in rows
    ]


def stats(db: Session) -> dict[str, Any]:
    rows = db.query(ReconScan).all()
    grades: Counter = Counter()
    for r in rows:
        grades[r.grade] += 1
    avg = round(sum(r.score for r in rows) / len(rows), 1) if rows else 0
    return {
        "scans": len(rows),
        "avg_score": avg,
        "by_grade": dict(grades),
        "selenium_available": browser.is_available(),
        "with_secrets": sum(1 for r in rows if r.secrets_count > 0),
    }

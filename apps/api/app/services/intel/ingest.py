"""Ingest normalized indicators / user-agents into the database.

Upserts with cross-source merge: re-seeing an indicator unions its
sources/tags, keeps the strongest score, and refreshes last_seen.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.models.intel import Indicator, IntelRun, UserAgentIntel
from app.services.intel import scoring


def _merge_list(existing: str | None, incoming: list[str]) -> str:
    cur = set(json.loads(existing) if existing else [])
    cur.update(incoming or [])
    return json.dumps(sorted(c for c in cur if c))


def upsert_indicator(db: Session, raw: dict[str, Any]) -> bool:
    """Upsert one raw indicator dict. Returns True if newly created."""
    ioc_type = raw.get("ioc_type") or scoring.guess_type(raw.get("ioc", ""))
    if ioc_type == "unknown":
        return False
    value = raw.get("ioc") or raw.get("value") or ""
    normalized = raw.get("normalized_ioc") or scoring.normalize(ioc_type, value)
    if not normalized:
        return False

    sources = raw.get("sources") or ([raw["source"]] if raw.get("source") else ["seed"])
    confidence = (raw.get("confidence") or "medium").lower()
    active = bool(raw.get("is_active", True))
    src_weight = max((scoring.SOURCE_WEIGHT.get(s, 60) for s in sources), default=60)
    provided = raw.get("threat_score")
    sc = int(provided) if isinstance(provided, (int, float)) and provided else scoring.score(src_weight, confidence, active)
    sev = raw.get("severity") or scoring.severity_for(sc)
    tags = raw.get("tags") or []

    row = db.query(Indicator).filter(Indicator.ioc_type == ioc_type, Indicator.normalized == normalized).first()
    if row is None:
        db.add(
            Indicator(
                ioc_type=ioc_type, value=value, normalized=normalized,
                threat_score=sc, severity=sev, confidence=confidence,
                category=(raw.get("category") or "unknown").lower(),
                tags_json=json.dumps(tags), sources_json=json.dumps(sorted(set(sources))),
                first_seen=raw.get("first_seen"), last_seen=raw.get("last_seen"),
                is_active=1 if active else 0, updated_at=datetime.utcnow(),
            )
        )
        return True
    row.threat_score = max(row.threat_score, sc)
    row.severity = scoring.severity_for(row.threat_score)
    row.tags_json = _merge_list(row.tags_json, tags)
    row.sources_json = _merge_list(row.sources_json, sources)
    if raw.get("last_seen"):
        row.last_seen = max(row.last_seen or "", raw["last_seen"])
    if active:
        row.is_active = 1
    row.updated_at = datetime.utcnow()
    return False


def upsert_user_agent(db: Session, raw: dict[str, Any]) -> bool:
    ua = (raw.get("http_useragent") or raw.get("user_agent") or "").strip()
    if not ua:
        return False
    ua_hash = hashlib.sha256(ua.lower().encode("utf-8")).hexdigest()
    sources = raw.get("sources") or []
    row = db.query(UserAgentIntel).filter(UserAgentIntel.ua_hash == ua_hash).first()
    if row is None:
        db.add(
            UserAgentIntel(
                ua_hash=ua_hash, user_agent=ua,
                tool_name=raw.get("tool_name") or "unknown",
                category=raw.get("threat_category") or raw.get("category") or "Suspicious",
                severity=(raw.get("severity_level") or raw.get("severity") or "medium").lower(),
                sources_json=json.dumps(sorted(set(sources))),
                updated_at=datetime.utcnow(),
            )
        )
        return True
    row.sources_json = _merge_list(row.sources_json, sources)
    if (row.tool_name or "unknown") == "unknown" and raw.get("tool_name"):
        row.tool_name = raw["tool_name"]
    row.updated_at = datetime.utcnow()
    return False


def ingest_indicators(db: Session, items: Iterable[dict[str, Any]], source: str) -> dict[str, int]:
    created = seen = 0
    for raw in items:
        seen += 1
        if upsert_indicator(db, raw):
            created += 1
        if seen % 500 == 0:
            db.commit()
    db.commit()
    _record_run(db, "ioc", source, "success", seen)
    return {"seen": seen, "created": created}


def ingest_user_agents(db: Session, items: Iterable[dict[str, Any]], source: str) -> dict[str, int]:
    created = seen = 0
    for raw in items:
        seen += 1
        if upsert_user_agent(db, raw):
            created += 1
        if seen % 500 == 0:
            db.commit()
    db.commit()
    _record_run(db, "useragent", source, "success", seen)
    return {"seen": seen, "created": created}


def _record_run(db: Session, kind: str, source: str, status: str, items: int, error: str | None = None) -> None:
    db.add(IntelRun(kind=kind, source=source, status=status, items=items, error=error, finished_at=datetime.utcnow()))
    db.commit()

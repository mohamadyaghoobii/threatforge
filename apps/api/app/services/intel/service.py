"""Query + orchestration layer for the Threat Intel module."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.models.intel import Indicator, IntelRun, UserAgentIntel
from app.services.intel import ingest
from app.services.intel.collectors import feeds, useragents


def _ioc_sources() -> list[dict]:
    path: Path = get_settings().config_path / "intel" / "ioc_sources.yml"
    if not path.exists():
        return []
    try:
        cfg = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:
        return []
    return [s for s in cfg.get("sources", []) if s.get("enabled", True)]


def _jl(value: str | None) -> list[str]:
    try:
        return json.loads(value) if value else []
    except (ValueError, TypeError):
        return []


def _indicator_dict(row: Indicator) -> dict[str, Any]:
    return {
        "id": row.id, "ioc": row.value, "normalized": row.normalized, "ioc_type": row.ioc_type,
        "threat_score": row.threat_score, "severity": row.severity, "confidence": row.confidence,
        "category": row.category, "tags": _jl(row.tags_json), "sources": _jl(row.sources_json),
        "first_seen": row.first_seen, "last_seen": row.last_seen, "is_active": bool(row.is_active),
    }


def list_indicators(db: Session, *, ioc_type=None, severity=None, category=None, source=None,
                    min_score=0, active=None, q=None, limit=500, offset=0) -> list[dict]:
    query = db.query(Indicator)
    if ioc_type:
        query = query.filter(Indicator.ioc_type == ioc_type)
    if severity:
        query = query.filter(Indicator.severity == severity)
    if category:
        query = query.filter(Indicator.category == category)
    if active is not None:
        query = query.filter(Indicator.is_active == (1 if active else 0))
    if min_score:
        query = query.filter(Indicator.threat_score >= min_score)
    if q:
        like = f"%{q}%"
        query = query.filter(Indicator.value.ilike(like) | Indicator.category.ilike(like) | Indicator.tags_json.ilike(like))
    rows = query.order_by(Indicator.threat_score.desc(), Indicator.id.desc()).offset(offset).limit(limit).all()
    out = [_indicator_dict(r) for r in rows]
    if source:
        out = [r for r in out if source in r["sources"]]
    return out


def list_user_agents(db: Session, *, severity=None, tool=None, q=None, limit=500, offset=0) -> list[dict]:
    query = db.query(UserAgentIntel)
    if severity:
        query = query.filter(UserAgentIntel.severity == severity)
    if tool:
        query = query.filter(UserAgentIntel.tool_name == tool)
    if q:
        like = f"%{q}%"
        query = query.filter(UserAgentIntel.user_agent.ilike(like) | UserAgentIntel.tool_name.ilike(like))
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    rows = query.limit(8000).all()
    rows.sort(key=lambda r: (order.get(r.severity, 0), r.tool_name), reverse=True)
    sliced = rows[offset: offset + limit]
    return [
        {"id": r.id, "user_agent": r.user_agent, "tool_name": r.tool_name, "category": r.category,
         "severity": r.severity, "sources": _jl(r.sources_json)}
        for r in sliced
    ]


def stats(db: Session) -> dict[str, Any]:
    by_type: Counter = Counter()
    by_sev: Counter = Counter()
    by_cat: Counter = Counter()
    by_source: Counter = Counter()
    active = 0
    total = 0
    for row in db.query(Indicator).all():
        total += 1
        by_type[row.ioc_type] += 1
        by_sev[row.severity] += 1
        by_cat[row.category] += 1
        for s in _jl(row.sources_json) or ["unknown"]:
            by_source[s] += 1
        if row.is_active:
            active += 1
    ua_total = db.query(UserAgentIntel).count()
    ua_sev: Counter = Counter()
    for row in db.query(UserAgentIntel.severity).all():
        ua_sev[row[0]] += 1
    return {
        "indicators": total,
        "indicators_active": active,
        "user_agents": ua_total,
        "by_type": dict(by_type),
        "by_severity": dict(by_sev),
        "by_category": dict(by_cat.most_common(12)),
        "by_source": dict(by_source),
        "ua_by_severity": dict(ua_sev),
    }


def source_health(db: Session) -> list[dict]:
    """Latest run per (kind, source). Hides empty successful pulls — a feed
    that returned 0 items adds noise, not signal."""
    out = []
    rows = db.query(IntelRun).order_by(IntelRun.id.desc()).limit(80).all()
    seen = set()
    for r in rows:
        key = (r.kind, r.source)
        if key in seen:
            continue
        seen.add(key)
        if r.status == "success" and r.items == 0:
            continue  # skip empty feeds
        out.append({"kind": r.kind, "source": r.source, "status": r.status,
                    "items": r.items, "error": r.error,
                    "finished_at": r.finished_at.isoformat() if r.finished_at else None})
    return out


def refresh(db: Session, *, iocs: bool = True, user_agents: bool = True) -> dict[str, Any]:
    """Pull live feeds (best-effort) and ingest. Never raises."""
    settings = get_settings()
    timeout = 30
    result: dict[str, Any] = {"sources": []}
    if iocs:
        for src in _ioc_sources():
            name = src["id"]
            try:
                items = feeds.collect(src, timeout=timeout)
                res = ingest.ingest_indicators(db, items, source=name)
                result["sources"].append({"source": name, "kind": "ioc", "fetched": res["seen"], "created": res["created"]})
            except Exception as exc:
                ingest._record_run(db, "ioc", name, "failed", 0, str(exc)[:300])
                result["sources"].append({"source": name, "kind": "ioc", "error": str(exc)[:200]})
    if user_agents:
        try:
            items = useragents.collect()
            res = ingest.ingest_user_agents(db, items, source="ua_aggregator")
            result["sources"].append({"source": "ua_aggregator", "kind": "useragent", "fetched": res["seen"], "created": res["created"]})
        except Exception as exc:
            ingest._record_run(db, "useragent", "ua_aggregator", "failed", 0, str(exc)[:300])
            result["sources"].append({"source": "ua_aggregator", "kind": "useragent", "error": str(exc)[:200]})
    # Age out stale indicators after a refresh so freshness is maintained.
    result["aged_out"] = age_indicators(db, settings.intel_ttl_days)
    return result


def age_indicators(db: Session, ttl_days: int | None = None) -> int:
    """Mark indicators inactive once their last_seen passes the TTL."""
    from app.services.intel import scoring

    ttl = ttl_days if ttl_days is not None else get_settings().intel_ttl_days
    aged = 0
    for row in db.query(Indicator).filter(Indicator.is_active == 1).all():
        if row.last_seen and not scoring.is_active(row.last_seen, ttl):
            row.is_active = 0
            aged += 1
    if aged:
        db.commit()
    return aged


def lookup(db: Session, value: str, ioc_type: str | None = None) -> dict[str, Any]:
    """SOC lookup: is this value a known indicator? Returns a verdict."""
    from app.services.intel import scoring

    value = (value or "").strip()
    if not value:
        return {"value": value, "known": False, "indicators": []}
    candidates: list[str] = []
    if ioc_type:
        candidates = [ioc_type]
    else:
        guessed = scoring.guess_type(value)
        candidates = [guessed] if guessed != "unknown" else ["domain", "ip", "url", "hash"]
    matches: list[dict] = []
    for t in candidates:
        norm = scoring.normalize(t, value)
        row = db.query(Indicator).filter(Indicator.ioc_type == t, Indicator.normalized == norm).first()
        if row:
            matches.append(_indicator_dict(row))
    verdict = "malicious" if matches else "unknown"
    max_score = max((m["threat_score"] for m in matches), default=0)
    return {"value": value, "known": bool(matches), "verdict": verdict, "max_score": max_score, "indicators": matches}

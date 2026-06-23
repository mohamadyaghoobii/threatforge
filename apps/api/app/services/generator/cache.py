"""Conversion cache (G9).

Keyed by a hash of the rule's raw content + target + profile +
output_format + generator version, so any change to the rule or the
generator invalidates the entry. Stores the final formatted query and
its structured warnings.
"""

from __future__ import annotations

import hashlib
import json

from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.models.generation import ConversionCache

# Bump when generator output semantics change so stale entries are bypassed.
GENERATOR_VERSION = "2.0.0-g9"


def enabled() -> bool:
    return get_settings().generator_cache_enabled


def make_key(raw_hash: str, target: str, profile: str | None, output_format: str) -> str:
    payload = "|".join([raw_hash or "", target, profile or "", output_format, GENERATOR_VERSION])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def lookup(db: Session, cache_key: str) -> ConversionCache | None:
    if not enabled():
        return None
    row = db.query(ConversionCache).filter(ConversionCache.cache_key == cache_key).first()
    if row:
        from datetime import datetime

        row.hit_count += 1
        row.last_used_at = datetime.utcnow()
        db.commit()
    return row


def store(
    db: Session,
    *,
    cache_key: str,
    rule_id: int,
    target: str,
    profile: str | None,
    output_format: str,
    backend: str | None,
    query_text: str,
    warnings: list,
) -> None:
    if not enabled():
        return
    existing = db.query(ConversionCache).filter(ConversionCache.cache_key == cache_key).first()
    if existing:
        return
    row = ConversionCache(
        cache_key=cache_key,
        rule_id=rule_id,
        target=target,
        profile=profile,
        output_format=output_format,
        generator_version=GENERATOR_VERSION,
        backend=backend,
        query_text=query_text,
        warnings_json=json.dumps([w.to_dict() for w in warnings], default=str),
        body_size_bytes=len(query_text.encode("utf-8")),
    )
    db.add(row)
    db.commit()


def stats(db: Session) -> dict:
    rows = db.query(ConversionCache).all()
    total_hits = sum(r.hit_count for r in rows)
    total_bytes = sum(r.body_size_bytes for r in rows)
    return {
        "enabled": enabled(),
        "entries": len(rows),
        "hits": total_hits,
        "bytes": total_bytes,
    }


def clear(db: Session, target: str | None = None) -> int:
    q = db.query(ConversionCache)
    if target:
        q = q.filter(ConversionCache.target == target)
    count = q.count()
    q.delete(synchronize_session=False)
    db.commit()
    return count

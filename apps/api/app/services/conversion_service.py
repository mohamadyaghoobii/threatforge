"""Legacy convert entry point.

Kept for backward compatibility with the existing ``POST /api/convert``
endpoint. New code should call ``app.services.generator.engine.convert``
directly and consume the structured ``ConvertResult``.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from app.services.generator.engine import convert as generator_convert


def convert_rule(
    db: Session,
    rule_id: int,
    target: str,
    profile: str | None,
    output_format: str,
) -> dict:
    result = generator_convert(
        db,
        rule_id,
        target=target,
        profile=profile,
        output_format=output_format,
        persist=True,
    )
    return {
        "rule_id": result.rule_id,
        "target": result.target,
        "profile": result.profile,
        "output_format": result.output_format,
        "query": result.query,
        "status": result.status,
        "warnings": [w.message for w in result.warnings],
        "error": result.error,
        "created_at": result.created_at,
    }

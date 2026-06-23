"""Query validators.

Two modes:
  - offline : structural lint of a generated query (no network). Catches
              unbalanced parens/quotes/brackets and obvious per-target
              syntax problems. Always available.
  - live    : send the query to the real SIEM's parse/validate API. Only
              runs when the relevant credentials are configured via env;
              otherwise reports ok=None with a note (skipped).

``validate(target, query, mode)`` returns a ValidationResult.
"""

from __future__ import annotations

from app.services.generator import targets as targets_module
from app.services.generator.validators import live as _live
from app.services.generator.validators import offline as _offline
from app.services.generator.validators.base import ValidationResult

__all__ = ["ValidationResult", "validate"]


def validate(target: str, query: str, mode: str = "offline") -> ValidationResult:
    canonical = targets_module.normalize_target(target)
    if mode == "live":
        return _live.validate(canonical, query)
    return _offline.validate(canonical, query)

"""Shared validation result type (kept separate to avoid import cycles)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ValidationResult:
    ok: bool | None
    mode: str
    target: str
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    elapsed_ms: int = 0
    note: str | None = None

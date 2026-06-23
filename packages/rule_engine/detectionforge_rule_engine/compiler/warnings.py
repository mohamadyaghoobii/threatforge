"""Lightweight compiler warnings.

The rule_engine package stays free of any API/web dependency, so it
defines its own minimal warning record. The generator service translates
these into its richer ``GeneratorWarning`` using the shared ``code``.

Codes intentionally match the API warning catalog in
``apps/api/app/services/generator/warnings.py``.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field as dataclass_field
from typing import Any


@dataclass
class CompilerWarning:
    code: str
    message: str
    field: str | None = None
    context: dict[str, Any] = dataclass_field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "field": self.field,
            "context": self.context,
        }


def warn(
    code: str,
    *,
    message: str,
    field: str | None = None,
    context: dict[str, Any] | None = None,
) -> CompilerWarning:
    return CompilerWarning(code=code, message=message, field=field, context=context or {})

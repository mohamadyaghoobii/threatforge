"""Offline structural linting of generated queries.

Target-agnostic checks (balanced delimiters, non-empty) plus light
per-target heuristics. The goal is high recall on broken output without
needing a live SIEM — enough to gate generation in CI.
"""

from __future__ import annotations

import time
from typing import Callable

from app.services.generator.validators.base import ValidationResult


def _balanced(query: str, errors: list[str]) -> None:
    pairs = {")": "(", "]": "[", "}": "{"}
    openers = set(pairs.values())
    stack: list[str] = []
    in_string = False
    string_char = ""
    prev = ""
    for ch in query:
        if in_string:
            if ch == string_char and prev != "\\":
                in_string = False
            prev = ch
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            prev = ch
            continue
        if ch in openers:
            stack.append(ch)
        elif ch in pairs:
            if not stack or stack[-1] != pairs[ch]:
                errors.append(f"Unbalanced '{ch}'")
                return
            stack.pop()
        prev = ch
    if in_string:
        errors.append("Unterminated string literal")
    if stack:
        errors.append(f"Unclosed '{stack[-1]}'")


def _lint_splunk(query: str, errors: list[str], warnings: list[str]) -> None:
    # A bare leading pipe with no base search is suspicious unless it's a
    # generating command (tstats, makeresults, inputlookup).
    stripped = query.lstrip()
    if stripped.startswith("|"):
        first = stripped[1:].strip().split()[:1]
        gen = {"tstats", "makeresults", "inputlookup", "from", "datamodel"}
        if not first or first[0] not in gen:
            warnings.append("SPL begins with a pipe but no generating command follows.")


def _lint_kql(query: str, errors: list[str], warnings: list[str]) -> None:
    # KQL where-clauses should follow a table or a pipe.
    if "| where" in query and query.strip().startswith("| where"):
        warnings.append("KQL starts with '| where' but no source table precedes it.")


def _lint_aql(query: str, errors: list[str], warnings: list[str]) -> None:
    upper = query.upper()
    if "SELECT" in upper and "FROM" not in upper:
        errors.append("AQL SELECT without FROM.")


_PER_TARGET: dict[str, Callable[[str, list[str], list[str]], None]] = {
    "splunk": _lint_splunk,
    "sentinel": _lint_kql,
    "elastic": _lint_kql,
    "opensearch": _lint_kql,
    "qradar": _lint_aql,
}


def validate(target: str, query: str):
    start = time.perf_counter()
    errors: list[str] = []
    warnings: list[str] = []

    if not query or not query.strip():
        errors.append("Empty query.")
    else:
        _balanced(query, errors)
        linter = _PER_TARGET.get(target)
        if linter:
            linter(query, errors, warnings)

    elapsed = int((time.perf_counter() - start) * 1000)
    return ValidationResult(
        ok=len(errors) == 0,
        mode="offline",
        target=target,
        errors=errors,
        warnings=warnings,
        elapsed_ms=elapsed,
        note=None,
    )

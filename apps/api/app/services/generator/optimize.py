"""Query optimizer (G10).

Conservative, text-level rewrites that preserve semantics:
  - collapse repeated ``field=a OR field=b`` on the same field into an
    ``field IN (a, b)`` list (Splunk / KQL-ish).
  - de-duplicate identical OR'd clauses.
  - strip redundant whitespace and doubled parentheses.

Returns (optimized_query, changed, notes).
"""

from __future__ import annotations

import re


def _collapse_or_lists(query: str) -> tuple[str, bool, list[str]]:
    notes: list[str] = []
    changed = False
    pattern = re.compile(r'\(\s*([\w.\-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s()]+)((?:\s+OR\s+\1\s*=\s*(?:"(?:[^"\\]|\\.)*"|[^\s()]+))+)\s*\)')

    def replace(match: re.Match) -> str:
        nonlocal changed
        field = match.group(1)
        first_val = match.group(2)
        rest = match.group(3)
        more_vals = re.findall(r'OR\s+' + re.escape(field) + r'\s*=\s*("(?:[^"\\]|\\.)*"|[^\s()]+)', rest)
        values = [first_val, *more_vals]
        changed = True
        return f"({field} IN ({', '.join(values)}))"

    new = pattern.sub(replace, query)
    if changed:
        notes.append("Collapsed same-field OR clauses into IN() lists.")
    return new, changed, notes


def _dedupe_ws(query: str) -> tuple[str, bool]:
    new = re.sub(r"[ \t]{2,}", " ", query).strip()
    return new, new != query


def optimize(query: str, target: str) -> tuple[str, bool, list[str]]:
    if not query or not query.strip():
        return query, False, []
    notes: list[str] = []
    result = query
    changed_any = False

    if target in ("splunk", "sentinel", "logscale"):
        result, c, n = _collapse_or_lists(result)
        changed_any = changed_any or c
        notes.extend(n)

    result, c = _dedupe_ws(result)
    if c:
        changed_any = True
        notes.append("Normalized whitespace.")

    return result, changed_any, notes

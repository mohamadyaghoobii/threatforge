"""Round-trip check (G10).

Extracts the field/value pairs a generated query references and compares
them against the field/value pairs in the source Sigma detection. A close
match means the conversion preserved the rule's semantics; a divergence
flags possible loss (e.g. a modifier the target couldn't express).

This is a heuristic signal, not a formal proof.
"""

from __future__ import annotations

import re
from typing import Any


def _sigma_tokens(detection: dict[str, Any]) -> set[str]:
    """Collect the literal values that appear in a Sigma detection."""
    tokens: set[str] = set()

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "condition":
                    continue
                walk(v)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif node is not None:
            # Strip Sigma wildcards and quotes for comparison.
            text = str(node).strip("*").strip().lower()
            if text:
                tokens.add(text)

    walk(detection)
    return tokens


def _query_tokens(query: str) -> set[str]:
    quoted = re.findall(r'"((?:[^"\\]|\\.)*)"', query)
    backtick = re.findall(r"`([^`]*)`", query)
    regex_lit = re.findall(r"/([^/]+)/", query)
    raw = quoted + backtick + regex_lit
    out: set[str] = set()
    for t in raw:
        cleaned = t.replace("\\\\", "\\").strip("*%").strip().lower()
        if cleaned:
            out.add(cleaned)
    return out


def round_trip(query: str, detection: dict[str, Any]) -> dict[str, Any]:
    sigma_tokens = _sigma_tokens(detection)
    query_tokens = _query_tokens(query)
    if not sigma_tokens:
        return {"parsed": bool(query_tokens), "semantic_match": None, "note": "No comparable literals in the source rule."}

    # A sigma token is "covered" if it is a substring of any query token or
    # vice versa (handles path escaping and wildcard trimming).
    covered = 0
    missing: list[str] = []
    for st in sigma_tokens:
        if any(st in qt or qt in st for qt in query_tokens):
            covered += 1
        else:
            missing.append(st)
    ratio = covered / len(sigma_tokens)
    return {
        "parsed": bool(query_tokens),
        "semantic_match": ratio >= 0.8,
        "coverage": round(ratio, 2),
        "missing_literals": sorted(missing)[:10],
        "note": "Heuristic literal-coverage check.",
    }

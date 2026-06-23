"""Live validation against a real SIEM's parse API.

Each target reads its own env vars. When they are absent (the common
case), validation is *skipped* — ok=None with an explanatory note —
rather than failing. Network calls use a short timeout and never raise.

Configured env (all optional):
  Splunk   : SPLUNK_URL, SPLUNK_TOKEN
  Elastic  : ELASTIC_URL, ELASTIC_API_KEY
  (others scaffolded; return skipped until wired)
"""

from __future__ import annotations

import os
import time

from app.services.generator.validators.base import ValidationResult


def _skipped(target: str, note: str, elapsed: int) -> ValidationResult:
    return ValidationResult(ok=None, mode="live", target=target, note=note, elapsed_ms=elapsed)


def _validate_splunk(query: str, start: float) -> ValidationResult:
    url = os.getenv("SPLUNK_URL")
    token = os.getenv("SPLUNK_TOKEN")
    elapsed = lambda: int((time.perf_counter() - start) * 1000)  # noqa: E731
    if not url or not token:
        return _skipped("splunk", "SPLUNK_URL/SPLUNK_TOKEN not set; live validation skipped.", elapsed())
    try:
        import httpx

        search = query if query.lstrip().startswith(("|", "search")) else f"search {query}"
        resp = httpx.post(
            f"{url.rstrip('/')}/services/search/parser",
            params={"q": search, "output_mode": "json", "parse_only": "t"},
            headers={"Authorization": f"Bearer {token}"},
            timeout=10.0,
            verify=False,
        )
        ok = resp.status_code == 200
        errors = [] if ok else [f"HTTP {resp.status_code}: {resp.text[:300]}"]
        return ValidationResult(ok=ok, mode="live", target="splunk", errors=errors, elapsed_ms=elapsed())
    except Exception as exc:  # network/SSL/etc — report, don't raise
        return ValidationResult(
            ok=None, mode="live", target="splunk", note=f"Live check failed: {type(exc).__name__}: {exc}", elapsed_ms=elapsed()
        )


def _validate_elastic(query: str, start: float) -> ValidationResult:
    url = os.getenv("ELASTIC_URL")
    key = os.getenv("ELASTIC_API_KEY")
    elapsed = lambda: int((time.perf_counter() - start) * 1000)  # noqa: E731
    if not url or not key:
        return _skipped("elastic", "ELASTIC_URL/ELASTIC_API_KEY not set; live validation skipped.", elapsed())
    try:
        import httpx

        resp = httpx.post(
            f"{url.rstrip('/')}/_validate/query",
            params={"rewrite": "true"},
            json={"query": {"query_string": {"query": query}}},
            headers={"Authorization": f"ApiKey {key}", "Content-Type": "application/json"},
            timeout=10.0,
            verify=False,
        )
        data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {}
        ok = bool(data.get("valid", resp.status_code == 200))
        errors = [] if ok else [str(data.get("error", f"HTTP {resp.status_code}"))]
        return ValidationResult(ok=ok, mode="live", target="elastic", errors=errors, elapsed_ms=elapsed())
    except Exception as exc:
        return ValidationResult(
            ok=None, mode="live", target="elastic", note=f"Live check failed: {type(exc).__name__}: {exc}", elapsed_ms=elapsed()
        )


_LIVE = {
    "splunk": _validate_splunk,
    "elastic": _validate_elastic,
}


def validate(target: str, query: str) -> ValidationResult:
    start = time.perf_counter()
    fn = _LIVE.get(target)
    if not fn:
        return _skipped(target, f"No live validator wired for target {target!r}.", 0)
    return fn(query, start)

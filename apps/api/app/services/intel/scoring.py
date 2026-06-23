"""Normalization, scoring, severity, and aging for threat indicators.

Pure functions — no I/O — so they are trivially testable and reused by
both the seed loader and the live collectors.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta, timezone

_CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.75, "low": 0.5, "none": 0.4}
# Per-source trust weight (0-100). Unknown sources get a neutral default.
SOURCE_WEIGHT = {
    "urlhaus": 90,
    "threatfox": 85,
    "malwarebazaar": 85,
    "abuseipdb": 80,
    "otx": 70,
    "manual": 95,
    "seed": 75,
}
DEFAULT_TTL_DAYS = 30


def normalize(ioc_type: str, value: str) -> str:
    v = (value or "").strip()
    if ioc_type == "domain":
        v = v.lower().replace("[.]", ".")
        v = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
        return v
    if ioc_type == "ip":
        return v.replace("[.]", ".").strip()
    if ioc_type == "url":
        return v.replace("[.]", ".").strip()
    if ioc_type == "hash":
        return v.lower().strip()
    return v.lower().strip()


def guess_type(value: str) -> str:
    v = (value or "").strip().replace("[.]", ".")
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", v):
        return "hash"
    host = re.sub(r"^https?://", "", v).split("/")[0].split(":")[0]
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^https?://", v, re.I) or ("/" in v and "." in v):
        return "url"
    if "." in v:
        return "domain"
    return "unknown"


def score(source_weight: int, confidence: str, active: bool) -> int:
    base = max(0, min(100, source_weight))
    conf = _CONFIDENCE_WEIGHT.get((confidence or "medium").lower(), 0.75)
    s = base * conf
    if not active:
        s *= 0.8
    return int(round(max(0, min(100, s))))


def severity_for(score_value: int) -> str:
    if score_value >= 85:
        return "critical"
    if score_value >= 65:
        return "high"
    if score_value >= 40:
        return "medium"
    return "low"


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    txt = value.strip().replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            if fmt is None:
                return datetime.fromisoformat(txt)
            return datetime.strptime(value.strip(), fmt).replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    return None


def is_active(last_seen: str | None, ttl_days: int = DEFAULT_TTL_DAYS) -> bool:
    dt = _parse_dt(last_seen)
    if dt is None:
        return True
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - dt <= timedelta(days=ttl_days)

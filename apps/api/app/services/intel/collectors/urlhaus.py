"""URLhaus collector — public recent URL CSV (no auth required)."""

from __future__ import annotations

import csv
import io
import ipaddress
import re
import urllib.request

RECENT_CSV = "https://urlhaus.abuse.ch/downloads/csv_recent/"


def _host(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]


def collect(limit: int = 2000, timeout: int = 30) -> list[dict]:
    try:
        req = urllib.request.Request(RECENT_CSV, headers={"User-Agent": "MetaSecSecurityCenter/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "ignore")
    except Exception:
        return []

    rows = [ln for ln in body.splitlines() if ln.strip() and not ln.startswith("#")]
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for rec in csv.reader(rows):
        if len(rec) < 9:
            continue
        _id, dateadded, url, status, last_online, threat, tags, link, reporter = rec[:9]
        url = url.strip()
        if not url:
            continue
        active = status.strip().lower() == "online"
        taglist = [t.strip() for t in (tags or "").split(",") if t.strip()]
        category = (threat or "malware").strip()
        last = last_online or dateadded

        key = ("url", url.lower())
        if key not in seen:
            seen.add(key)
            out.append({"ioc": url, "ioc_type": "url", "category": category, "confidence": "high",
                        "source": "urlhaus", "tags": taglist, "first_seen": dateadded,
                        "last_seen": last, "is_active": active})
        host = _host(url)
        if host:
            try:
                ipaddress.ip_address(host)
                htype = "ip"
            except ValueError:
                htype = "domain"
            hkey = (htype, host.lower())
            if hkey not in seen:
                seen.add(hkey)
                out.append({"ioc": host, "ioc_type": htype, "category": category, "confidence": "medium",
                            "source": "urlhaus", "tags": taglist, "first_seen": dateadded,
                            "last_seen": last, "is_active": active})
        if len(out) >= limit:
            break
    return out

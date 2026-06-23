"""ThreatFox collector — abuse.ch API (auth token via env)."""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

API = "https://threatfox-api.abuse.ch/api/v1/"


def collect(limit: int = 2000, days: int = 3, timeout: int = 30) -> list[dict]:
    token = os.getenv("THREATFOX_AUTH_TOKEN") or os.getenv("ABUSECH_AUTH_TOKEN")
    if not token:
        return []
    try:
        data = urllib.parse.urlencode({"query": "get_iocs", "days": days}).encode()
        req = urllib.request.Request(API, data=data, method="POST")
        req.add_header("User-Agent", "MetaSecSecurityCenter/1.0")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Auth-Key", token)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "ignore")
        payload = json.loads(body)
    except Exception:
        return []

    type_map = {"ip:port": "ip", "domain": "domain", "url": "url",
                "md5_hash": "hash", "sha256_hash": "hash", "sha1_hash": "hash"}
    out: list[dict] = []
    for it in (payload.get("data") or [])[:limit]:
        raw_type = (it.get("ioc_type") or "").lower()
        ioc_type = type_map.get(raw_type, "")
        ioc = (it.get("ioc") or "").strip()
        if not ioc or not ioc_type:
            continue
        if ioc_type == "ip":
            ioc = ioc.split(":")[0]
        tags = []
        for k in ("malware", "malware_alias", "tags"):
            v = it.get(k)
            if isinstance(v, str) and v:
                tags += [t.strip() for t in v.split(",") if t.strip()]
        out.append({
            "ioc": ioc, "ioc_type": ioc_type, "category": "malware",
            "confidence": (it.get("confidence_level") or "medium"),
            "source": "threatfox", "tags": sorted(set(tags)),
            "first_seen": it.get("first_seen"), "last_seen": it.get("last_seen"), "is_active": True,
        })
    return out

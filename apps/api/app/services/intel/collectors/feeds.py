"""Generic, config-driven IOC feed collectors.

A single ``collect(source)`` dispatches on the source's ``format`` to a
parser. Every parser is fail-soft (returns [] on any error) so one bad
feed never breaks a refresh. Adding a feed is a config change in
configs/intel/ioc_sources.yml, not new code.
"""

from __future__ import annotations

import csv
import ipaddress
import re
import urllib.request

from app.services.intel.collectors import threatfox


def _http_get(url: str, timeout: int) -> bytes | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "MetaSecSecurityCenter/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception:
        return None


def _host(url: str) -> str:
    return re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _rows(body: str) -> list[list[str]]:
    lines = [ln for ln in body.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return list(csv.reader(lines))


def parse_urlhaus_csv(body: str, src: dict) -> list[dict]:
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    limit = int(src.get("limit", 2500))
    for rec in _rows(body):
        if len(rec) < 9:
            continue
        _id, dateadded, url, status, last_online, threat, tags, link, reporter = rec[:9]
        url = url.strip()
        if not url:
            continue
        active = status.strip().lower() == "online"
        taglist = [t.strip() for t in (tags or "").split(",") if t.strip()]
        category = (threat or src.get("category", "malware")).strip()
        last = last_online or dateadded
        k = ("url", url.lower())
        if k not in seen:
            seen.add(k)
            out.append({"ioc": url, "ioc_type": "url", "category": category, "confidence": "high",
                        "source": src["id"], "tags": taglist, "first_seen": dateadded, "last_seen": last, "is_active": active})
        host = _host(url)
        if host:
            htype = "ip" if _is_ip(host) else "domain"
            hk = (htype, host.lower())
            if hk not in seen:
                seen.add(hk)
                out.append({"ioc": host, "ioc_type": htype, "category": category, "confidence": "medium",
                            "source": src["id"], "tags": taglist, "first_seen": dateadded, "last_seen": last, "is_active": active})
        if len(out) >= limit:
            break
    return out


def parse_abuse_ip_csv(body: str, src: dict) -> list[dict]:
    """abuse.ch IP CSVs (Feodo, SSLBL): find the IP column per row."""
    out: list[dict] = []
    seen: set[str] = set()
    for rec in _rows(body):
        ip = next((c.strip() for c in rec if _is_ip(c.strip())), None)
        if not ip or ip in seen:
            continue
        seen.add(ip)
        malware = ""
        for c in rec:
            cc = c.strip()
            if cc and not _is_ip(cc) and not cc.isdigit() and "-" not in cc[:4] and len(cc) < 40:
                malware = cc
        out.append({"ioc": ip, "ioc_type": "ip", "category": src.get("category", "c2"),
                    "confidence": src.get("confidence", "high"), "source": src["id"],
                    "tags": [t for t in [malware] if t], "is_active": True})
    return out


def parse_threatfox_csv(body: str, src: dict) -> list[dict]:
    """ThreatFox public CSV export (no auth). Columns:
    first_seen, id, ioc_value, ioc_type, threat_type, malware, alias,
    printable, last_seen, confidence, reference, tags, anonymous, reporter.
    """
    type_map = {"ip:port": "ip", "domain": "domain", "url": "url",
                "md5_hash": "hash", "sha1_hash": "hash", "sha256_hash": "hash"}
    out: list[dict] = []
    seen: set[tuple[str, str]] = set()
    limit = int(src.get("limit", 4000))
    for rec in _rows(body):
        rec = [c.strip().strip('"').strip() for c in rec]
        if len(rec) < 10:
            continue
        first_seen, _id, value, raw_type, threat, malware, alias, printable, last_seen, conf = rec[:10]
        ioc_type = type_map.get(raw_type.lower(), "")
        if not value or not ioc_type:
            continue
        if ioc_type == "ip":
            value = value.split(":")[0]
        tags = [t for t in [printable, alias] if t and t.lower() != "none"]
        if len(rec) > 11 and rec[11] and rec[11].lower() != "none":
            tags += [t.strip() for t in rec[11].split(",") if t.strip()]
        confidence = "high" if conf.isdigit() and int(conf) >= 75 else ("medium" if conf.isdigit() and int(conf) >= 50 else "low")
        k = (ioc_type, value.lower())
        if k in seen:
            continue
        seen.add(k)
        out.append({"ioc": value, "ioc_type": ioc_type, "category": (threat or src.get("category", "malware")),
                    "confidence": confidence, "source": src["id"], "tags": sorted(set(tags)),
                    "first_seen": first_seen or None, "last_seen": last_seen or None, "is_active": True})
        if len(out) >= limit:
            break
    return out


def parse_ip_txt(body: str, src: dict) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    limit = int(src.get("limit", 6000))
    for line in body.splitlines():
        ip = line.strip()
        if not _is_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        out.append({"ioc": ip, "ioc_type": "ip", "category": src.get("category", "attacker"),
                    "confidence": src.get("confidence", "medium"), "source": src["id"], "is_active": True})
        if len(out) >= limit:
            break
    return out


def parse_hash_txt(body: str, src: dict) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for line in body.splitlines():
        h = line.strip().strip('"')
        if not re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", h):
            continue
        hl = h.lower()
        if hl in seen:
            continue
        seen.add(hl)
        out.append({"ioc": h, "ioc_type": "hash", "category": src.get("category", "malware"),
                    "confidence": src.get("confidence", "high"), "source": src["id"], "is_active": True})
    return out


_PARSERS = {
    "urlhaus_csv": parse_urlhaus_csv,
    "abuse_ip_csv": parse_abuse_ip_csv,
    "threatfox_csv": parse_threatfox_csv,
    "ip_txt": parse_ip_txt,
    "hash_txt": parse_hash_txt,
}


def collect(source: dict, timeout: int = 30) -> list[dict]:
    fmt = source.get("format")
    if fmt == "threatfox_api":
        return threatfox.collect(limit=int(source.get("limit", 2000)), timeout=timeout)
    parser = _PARSERS.get(fmt)
    if not parser or not source.get("url"):
        return []
    body = _http_get(source["url"], timeout)
    if body is None:
        return []
    try:
        return parser(body.decode("utf-8", "ignore"), source)
    except Exception:
        return []

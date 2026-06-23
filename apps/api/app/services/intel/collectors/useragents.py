"""User-Agent aggregator — pulls suspicious UA lists from public sources.

Sources are config-driven (configs/intel/useragent_sources.json). Each
source has a parser format; failures are isolated per source.
"""

from __future__ import annotations

import csv
import json
import re
import urllib.request
from pathlib import Path

from app.core.settings import get_settings

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_TOOL_PATTERNS = [
    ("sqlmap", re.compile(r"sqlmap", re.I), "critical"),
    ("metasploit", re.compile(r"metasploit|msf", re.I), "critical"),
    ("hydra", re.compile(r"\bhydra\b", re.I), "critical"),
    ("nmap", re.compile(r"\bnmap\b", re.I), "high"),
    ("masscan", re.compile(r"\bmasscan\b", re.I), "high"),
    ("nikto", re.compile(r"\bnikto\b", re.I), "high"),
    ("nuclei", re.compile(r"\bnuclei\b", re.I), "high"),
    ("wpscan", re.compile(r"\bwpscan\b", re.I), "high"),
    ("nessus", re.compile(r"\bnessus\b", re.I), "high"),
    ("acunetix", re.compile(r"\bacunetix\b", re.I), "high"),
    ("gobuster", re.compile(r"\bgobuster\b", re.I), "high"),
    ("ffuf", re.compile(r"\bffuf\b", re.I), "high"),
    ("curl", re.compile(r"\bcurl\b", re.I), "medium"),
    ("wget", re.compile(r"\bwget\b", re.I), "medium"),
]


def _worse(a: str, b: str) -> str:
    return a if SEVERITY_RANK.get(a, 2) >= SEVERITY_RANK.get(b, 2) else b


def _detect(ua: str, default_sev: str) -> tuple[str, str]:
    for name, rx, implied in _TOOL_PATTERNS:
        if rx.search(ua):
            return name, _worse(default_sev, implied)
    return "unknown", default_sev


def _normalize(s: str) -> str:
    s = (s or "").replace("\r", " ").replace("\n", " ").strip()
    s = re.sub(r"\s+", " ", s)
    if len(s) > 1 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1].strip()
    return s


def _parse(fmt: str, data: bytes) -> list[str]:
    text = data.decode("utf-8", "replace")
    if fmt == "txt_lines":
        return [s.strip() for s in text.splitlines() if s.strip() and not s.lstrip().startswith(("#", ";", "//"))]
    if fmt == "json_list":
        obj = json.loads(text)
        if isinstance(obj, list):
            return [str(x).strip() for x in obj if str(x).strip()]
        if isinstance(obj, dict):
            for k in ("list", "user_agents", "useragents", "agents"):
                if isinstance(obj.get(k), list):
                    return [str(x).strip() for x in obj[k] if str(x).strip()]
        return []
    if fmt == "csv_first_column":
        out = []
        for i, row in enumerate(csv.reader(text.splitlines())):
            if not row:
                continue
            if i == 0 and any("user" in (c or "").lower() for c in row):
                continue
            if row[0].strip():
                out.append(row[0].strip())
        return out
    return []


def _config_path() -> Path:
    return get_settings().config_path / "intel" / "useragent_sources.json"


def collect(timeout: int = 20) -> list[dict]:
    cfg_path = _config_path()
    if not cfg_path.exists():
        return []
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    store: dict[str, dict] = {}
    for src in cfg.get("sources", []):
        try:
            req = urllib.request.Request(src["url"], headers={"User-Agent": "MetaSecSecurityCenter/1.0"})
            with urllib.request.urlopen(req, timeout=cfg.get("timeout_seconds", timeout)) as r:
                data = r.read()
            items = _parse(src["format"], data)
        except Exception:
            continue
        default_cat = src.get("default_category", "Suspicious")
        default_sev = src.get("default_severity", "medium")
        for raw in items:
            ua = _normalize(raw)
            if not ua:
                continue
            key = ua.lower()
            tool, sev = _detect(ua, default_sev)
            rec = store.get(key)
            if rec is None:
                store[key] = {"http_useragent": ua, "threat_category": default_cat,
                              "tool_name": tool, "severity_level": sev, "sources": [src["id"]]}
            else:
                if src["id"] not in rec["sources"]:
                    rec["sources"].append(src["id"])
                rec["severity_level"] = _worse(rec["severity_level"], sev)
                if rec["tool_name"] == "unknown" and tool != "unknown":
                    rec["tool_name"] = tool
    return list(store.values())

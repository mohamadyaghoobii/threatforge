"""Active-light + passive recon over the network — all fail-soft.

Everything here may touch the network and must never raise: DNS over
HTTPS (full record set, no dnspython dependency), robots.txt / sitemap,
sensitive-path probing (.git/.env/swagger/openapi/graphql), Wayback
Machine URLs, urlscan.io passive search, JavaScript fetch + endpoint /
secret extraction, and key-gated enrichment (Shodan, Hunter.io,
SecurityTrails) when the matching env var is present.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from typing import Any

from app.services.recon import analyzers

_UA = {"User-Agent": "Mozilla/5.0 (compatible; MetaSecSecurityCenter/1.0)"}


def _get(url: str, timeout: int = 15, headers: dict | None = None) -> tuple[int | None, bytes | None]:
    try:
        req = urllib.request.Request(url, headers={**_UA, **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return getattr(r, "status", 200), r.read()
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception:
        return None, None


def _get_json(url: str, timeout: int = 15, headers: dict | None = None) -> Any:
    status, body = _get(url, timeout, headers)
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8", "ignore"))
    except Exception:
        return None


# --- DNS over HTTPS ---------------------------------------------------------

def dns_records(host: str, timeout: int = 12) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if not host:
        return out
    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
        data = _get_json(f"https://dns.google/resolve?name={urllib.parse.quote(host)}&type={rtype}", timeout)
        vals = []
        for ans in (data or {}).get("Answer", []) if isinstance(data, dict) else []:
            v = str(ans.get("data", "")).strip().strip('"')
            if v:
                vals.append(v)
        if vals:
            out[rtype] = sorted(set(vals))[:25]
    return out


# --- robots / sitemap -------------------------------------------------------

def robots_and_sitemap(base: str, timeout: int = 12) -> dict[str, Any]:
    result: dict[str, Any] = {"robots": False, "sitemaps": [], "disallow": []}
    status, body = _get(urllib.parse.urljoin(base, "/robots.txt"), timeout)
    if status == 200 and body:
        result["robots"] = True
        for line in body.decode("utf-8", "ignore").splitlines():
            line = line.strip()
            if line.lower().startswith("sitemap:"):
                result["sitemaps"].append(line.split(":", 1)[1].strip())
            elif line.lower().startswith("disallow:"):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    result["disallow"].append(p)
    result["disallow"] = result["disallow"][:40]
    return result


# --- sensitive path probing -------------------------------------------------

# Each path carries a content signature: a 200 only counts as a real hit
# when the body actually matches, defeating SPA / catch-all 200 pages.
_SENSITIVE_PATHS = [
    ("/.git/config", "high", "Exposed Git repository", ["[core]", "repositoryformatversion"]),
    ("/.env", "critical", "Exposed environment file (secrets)", ["__ENV_KV__"]),
    ("/.svn/entries", "high", "Exposed SVN repository", ["dir", "svn:"]),
    ("/.DS_Store", "low", "Exposed macOS directory index", ["Bud1", "\x00\x00\x00"]),
    ("/swagger.json", "medium", "Swagger/OpenAPI spec exposed", ["\"swagger\"", "\"openapi\""]),
    ("/openapi.json", "medium", "OpenAPI spec exposed", ["\"openapi\"", "\"paths\""]),
    ("/v2/api-docs", "medium", "Springfox API docs exposed", ["\"swagger\"", "\"paths\""]),
    ("/api/swagger.json", "medium", "Swagger spec exposed", ["\"swagger\"", "\"openapi\""]),
    ("/.well-known/security.txt", "info", "security.txt present", ["contact:"]),
    ("/server-status", "medium", "Apache server-status exposed", ["apache server status", "server uptime", "server version:"]),
    ("/actuator/health", "low", "Spring Boot actuator reachable", ["\"status\":\"up\"", "\"status\": \"up\""]),
    ("/phpinfo.php", "high", "phpinfo() exposed", ["phpinfo()", "php version", "<title>phpinfo"]),
]


def _looks_html(body: bytes) -> bool:
    head = body[:600].lower()
    return b"<!doctype html" in head or b"<html" in head


def _matches(path: str, body: bytes) -> bool:
    text_full = body.decode("utf-8", "ignore")
    text = text_full.lower()
    sig = next((s for p, _, _, s in _SENSITIVE_PATHS if p == path), [])
    # .env: require at least one KEY=VALUE line and not an HTML page.
    if "__ENV_KV__" in sig:
        if _looks_html(body):
            return False
        import re as _re
        return bool(_re.search(r"^[A-Z][A-Z0-9_]{2,}=\S", text_full, _re.M))
    # config/binary/spec paths must not be an HTML catch-all unless the sig is HTML.
    if _looks_html(body) and not any("<title>" in s or "html" in s for s in sig):
        return False
    return any(s.lower() in text for s in sig)


def probe_paths(base: str, timeout: int = 8) -> list[dict]:
    found: list[dict] = []
    for path, sev, detail, _sig in _SENSITIVE_PATHS:
        status, body = _get(urllib.parse.urljoin(base, path), timeout)
        if status == 200 and body and _matches(path, body):
            found.append({"path": path, "severity": sev, "detail": detail, "status": status})
    return found


# --- Wayback ----------------------------------------------------------------

def wayback_urls(host: str, timeout: int = 20, cap: int = 80) -> list[str]:
    if not host:
        return []
    url = (f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(host)}/*"
           f"&output=json&fl=original&collapse=urlkey&limit={cap}")
    data = _get_json(url, timeout)
    if not isinstance(data, list) or len(data) < 2:
        return []
    return sorted({row[0] for row in data[1:] if row})[:cap]


# --- urlscan.io (passive search, no key) -----------------------------------

def urlscan_search(host: str, timeout: int = 15, cap: int = 20) -> list[dict]:
    if not host:
        return []
    data = _get_json(f"https://urlscan.io/api/v1/search/?q=domain:{urllib.parse.quote(host)}&size={cap}", timeout)
    out = []
    for r in (data or {}).get("results", [])[:cap] if isinstance(data, dict) else []:
        page = r.get("page", {})
        out.append({"url": page.get("url"), "ip": page.get("ip"), "server": page.get("server"),
                    "country": page.get("country"), "time": r.get("task", {}).get("time")})
    return out


# --- JavaScript fetch + intel ----------------------------------------------

def analyze_js(script_urls: list[str], timeout: int = 12, max_files: int = 6) -> dict[str, Any]:
    endpoints: set[str] = set()
    secrets: list[dict] = []
    analyzed = 0
    for url in script_urls[:max_files]:
        status, body = _get(url, timeout)
        if not body:
            continue
        analyzed += 1
        text = body.decode("utf-8", "ignore")
        endpoints.update(analyzers.extract_js_endpoints(text))
        secrets.extend(analyzers.scan_secrets(text, max_findings=10))
    # de-dup secrets by match
    uniq, seen = [], set()
    for s in secrets:
        if s["match"] not in seen:
            seen.add(s["match"])
            uniq.append(s)
    return {"files_analyzed": analyzed, "endpoints": sorted(endpoints)[:120], "secrets": uniq[:30]}


# --- key-gated enrichment ---------------------------------------------------

def enrich(host: str, ips: list[str], timeout: int = 15) -> dict[str, Any]:
    out: dict[str, Any] = {}

    sh_key = os.getenv("SHODAN_API_KEY")
    if sh_key and ips:
        data = _get_json(f"https://api.shodan.io/shodan/host/{ips[0]}?key={sh_key}", timeout)
        if isinstance(data, dict) and not data.get("error"):
            out["shodan"] = {"ip": ips[0], "org": data.get("org"), "os": data.get("os"),
                             "ports": data.get("ports", []), "hostnames": data.get("hostnames", []),
                             "vulns": list(data.get("vulns", []))[:20]}

    hunter_key = os.getenv("HUNTER_API_KEY")
    if hunter_key and host:
        data = _get_json(f"https://api.hunter.io/v2/domain-search?domain={host}&api_key={hunter_key}&limit=20", timeout)
        emails = [(e.get("value")) for e in (data or {}).get("data", {}).get("emails", [])] if isinstance(data, dict) else []
        if emails:
            out["hunter_emails"] = [e for e in emails if e][:25]

    st_key = os.getenv("SECURITYTRAILS_API_KEY")
    if st_key and host:
        data = _get_json(f"https://api.securitytrails.com/v1/domain/{host}/subdomains?apikey={st_key}", timeout)
        subs = (data or {}).get("subdomains", []) if isinstance(data, dict) else []
        if subs:
            out["securitytrails_subdomains"] = sorted(f"{s}.{host}" for s in subs)[:200]

    return out

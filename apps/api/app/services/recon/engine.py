"""Recon engine — orchestrates a full web recon scan.

Pipeline: normalize -> HTTP fetch -> analyzers (metadata, security +
cookie audit, CMS/CDN/tech/GraphQL, confidence-rated secrets, assets) ->
DNS (DoH) + crt.sh subdomains -> robots/sitemap -> sensitive-path probe ->
JS fetch+intel -> Wayback + urlscan -> key-gated enrichment -> optional
Selenium render -> posture score. Fail-soft throughout.
"""

from __future__ import annotations

import json
import socket
import urllib.request
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from app.services.recon import analyzers, browser, passive, scoring


def normalize_target(target: str) -> tuple[str, str]:
    t = (target or "").strip()
    if not t:
        return "", ""
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    host = urlparse(t).netloc.split("@")[-1].split(":")[0]
    return t, host


def _fetch(url: str, timeout: int = 15) -> dict[str, Any]:
    import requests

    for verify in (True, False):
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True, verify=verify,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; MetaSecSecurityCenter/1.0)"})
            return {"ok": True, "status": resp.status_code, "final_url": str(resp.url),
                    "headers": dict(resp.headers), "raw_headers": resp.raw.headers if hasattr(resp.raw, "headers") else None,
                    "html": resp.text[:600000], "error": None if verify else "tls-unverified"}
        except Exception as exc:
            last = f"{type(exc).__name__}: {str(exc)[:200]}"
    return {"ok": False, "status": None, "final_url": url, "headers": {}, "html": "", "error": last}


def _resolve_ips(host: str) -> list[str]:
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def _crtsh_subdomains(host: str, timeout: int = 20, cap: int = 200) -> list[str]:
    if not host:
        return []
    try:
        req = urllib.request.Request(f"https://crt.sh/?q=%25.{host}&output=json",
                                     headers={"User-Agent": "MetaSecSecurityCenter/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8", "ignore") or "[]")
    except Exception:
        return []
    subs: set[str] = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(host) and name != host:
                subs.add(name)
    return sorted(subs)[:cap]


def run_scan(target: str, *, render: bool = False, subdomains: bool = True,
             probe: bool = True, passive_intel: bool = True, timeout: int = 15) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    url, host = normalize_target(target)
    if not url:
        return {"status": "error", "error": "empty target"}

    fetched = _fetch(url, timeout)
    headers, html, final_url = fetched["headers"], fetched["html"], fetched["final_url"]
    https = urlparse(final_url).scheme == "https"
    base = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}"

    metadata = analyzers.extract_metadata(html) if html else {}
    sec = analyzers.audit_security_headers(headers)
    cookies = analyzers.audit_cookies(headers)
    cms = analyzers.detect_cms(html, headers) if html else []
    cdn = analyzers.detect_cdn(headers)
    tech = analyzers.detect_tech(html, headers) if html else []
    secrets = analyzers.scan_secrets(html) if html else []
    assets = analyzers.extract_assets(html, final_url) if html else {}
    graphql = analyzers.detect_graphql(html, (assets.get("internal_links", []) + assets.get("external_links", []))) if html else {"detected": False, "markers": []}

    # --- network passive/active-light ---
    dns = passive.dns_records(host) if host else {}
    ips = dns.get("A", []) or _resolve_ips(host)
    subs = _crtsh_subdomains(host) if subdomains else []
    robots = passive.robots_and_sitemap(base) if fetched["ok"] else {}
    exposed = passive.probe_paths(base) if (probe and fetched["ok"]) else []
    js_intel = passive.analyze_js(assets.get("scripts", [])) if (probe and assets.get("scripts")) else {"files_analyzed": 0, "endpoints": [], "secrets": []}
    wayback = passive.wayback_urls(host) if passive_intel else []
    urlscan = passive.urlscan_search(host) if passive_intel else []
    enrichment = passive.enrich(host, ips) if passive_intel else {}

    # merge JS-discovered secrets (tagged) + securitytrails subdomains
    for s in js_intel.get("secrets", []):
        s = {**s, "source": "javascript"}
        if s["match"] not in {x["match"] for x in secrets}:
            secrets.append(s)
    if enrichment.get("securitytrails_subdomains"):
        subs = sorted(set(subs) | set(enrichment["securitytrails_subdomains"]))[:400]

    rendered = {"rendered": False}
    if render:
        rendered = browser.render(final_url, timeout=timeout + 10)
        if rendered.get("rendered") and rendered.get("dom"):
            tech = sorted(set(tech) | set(analyzers.detect_tech(rendered["dom"], headers)))

    posture = scoring.score_scan(https=https, security_headers=sec, cookies=cookies, secrets=secrets,
                                 forms=assets.get("forms", []), exposed_paths=exposed, graphql=graphql)

    finished = datetime.now(timezone.utc)
    return {
        "status": "success" if fetched["ok"] else "unreachable",
        "target": target, "url": url, "host": host,
        "http_status": fetched["status"], "final_url": final_url, "https": https,
        "server": headers.get("Server") or headers.get("server"),
        "title": metadata.get("title") or rendered.get("rendered_title", ""),
        "metadata": metadata, "ips": ips, "dns": dns,
        "score": posture["score"], "grade": posture["grade"], "findings": posture["findings"],
        "security_headers": sec, "cookies": cookies,
        "technologies": tech, "cms": cms, "cdn": cdn, "graphql": graphql,
        "secrets": secrets, "assets": assets,
        "subdomains": subs, "robots": robots, "exposed_paths": exposed,
        "js_intel": js_intel, "wayback": wayback, "urlscan": urlscan, "enrichment": enrichment,
        "rendered": rendered.get("rendered", False), "screenshot_b64": rendered.get("screenshot_b64"),
        "render_error": rendered.get("error"), "fetch_error": fetched["error"],
        "elapsed_ms": int((finished - started).total_seconds() * 1000),
    }

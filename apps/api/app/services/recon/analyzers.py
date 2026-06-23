"""Recon analyzers — pure HTML/header inspectors.

Ported and hardened from the MetaSec Recon Engine toolkit (metadata, security-header
audit, cookie audit, CMS/CDN/tech/GraphQL fingerprinting, confidence-rated
secret scanning, JS endpoint intel, link/form/comment extraction). No
network here — these run on already-fetched content so they are fast and
unit-testable.
"""

from __future__ import annotations

import math
import re
from urllib.parse import urljoin, urlparse

# --- security headers -------------------------------------------------------

SECURITY_HEADERS = {
    "content-security-policy": ("Content-Security-Policy", "Mitigates XSS and data injection", "medium"),
    "strict-transport-security": ("Strict-Transport-Security", "Enforces HTTPS (HSTS)", "medium"),
    "x-content-type-options": ("X-Content-Type-Options", "Stops MIME sniffing", "low"),
    "x-frame-options": ("X-Frame-Options", "Prevents clickjacking", "low"),
    "referrer-policy": ("Referrer-Policy", "Controls referrer leakage", "low"),
    "permissions-policy": ("Permissions-Policy", "Restricts browser features", "low"),
    "cross-origin-opener-policy": ("Cross-Origin-Opener-Policy", "Isolates browsing context", "low"),
}
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
# Only flag a leaky header when it actually discloses a version.
_VERSION_RE = re.compile(r"\d+\.\d+")


def audit_security_headers(headers: dict) -> dict:
    lower = {k.lower(): str(v) for k, v in headers.items()}
    present, missing, leaks = [], [], []
    for key, (name, desc, weight) in SECURITY_HEADERS.items():
        (present if key in lower else missing).append({"header": name, "description": desc, "weight": weight})
    for key in LEAKY_HEADERS:
        if key in lower:
            val = lower[key]
            discloses = key in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator") or bool(_VERSION_RE.search(val))
            leaks.append({"header": key, "value": val[:120], "discloses_version": discloses})
    return {"present": present, "missing": missing, "leaks": leaks}


# --- cookies ----------------------------------------------------------------


def audit_cookies(headers: dict) -> list[dict]:
    """Parse Set-Cookie header(s) and flag missing Secure/HttpOnly/SameSite."""
    raw = []
    for k, v in headers.items():
        if k.lower() == "set-cookie":
            raw.append(str(v))
    # requests collapses multiple Set-Cookie into one comma-joined string;
    # split conservatively on ", <name>=" boundaries.
    cookies = []
    for blob in raw:
        for part in re.split(r",(?=[^;]+?=)", blob):
            part = part.strip()
            if not part or "=" not in part:
                continue
            name = part.split("=", 1)[0].strip()
            low = part.lower()
            session_like = any(s in name.lower() for s in ("sess", "auth", "token", "sid", "jwt", "csrf"))
            cookies.append({
                "name": name[:60],
                "secure": "secure" in low,
                "httponly": "httponly" in low,
                "samesite": next((v.split("=", 1)[1].strip() for seg in low.split(";")
                                  for v in [seg.strip()] if v.startswith("samesite=")), None),
                "session_like": session_like,
            })
    return cookies


# --- fingerprinting ---------------------------------------------------------

_CMS = {
    "WordPress": [r"wp-content/", r"wp-includes/", r"/wp-json/"],
    "Joomla": [r"/components/com_", r"/modules/mod_", r"Joomla!"],
    "Drupal": [r"/sites/all/", r"/misc/drupal\.js", r"Drupal\.settings"],
    "Magento": [r"/skin/frontend/", r"Mage\.Cookies"],
    "Ghost": [r"ghost/api/", r"content/images"],
    "Shopify": [r"cdn\.shopify\.com", r"Shopify\."],
    "Wix": [r"static\.wixstatic\.com"],
}
_CDN = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
    "Akamai": ["akamai", "x-akamai"],
    "Fastly": ["fastly", "x-served-by"],
    "Amazon CloudFront": ["cloudfront", "x-amz-cf-id"],
    "Sucuri": ["x-sucuri-id"],
    "Google": ["x-goog", "gws"],
}
_TECH = {
    "jQuery": r"jquery(?:[-.]\d|\.min)?\.js",
    "Bootstrap": r"bootstrap(?:\.min)?\.(?:css|js)",
    "React": r"react(?:\.min|\.production)?\.js|__REACT",
    "Vue.js": r"vue(?:\.min|\.runtime)?\.js",
    "Angular": r"angular(?:\.min)?\.js|ng-version",
    "Next.js": r"/_next/|__NEXT_DATA__",
    "Nuxt": r"/_nuxt/",
    "Google Analytics": r"google-analytics\.com|gtag\(|googletagmanager",
    "Font Awesome": r"font-?awesome",
    "PHP": r"\.php(?:\?|\"|$)",
    "ASP.NET": r"\.aspx|__VIEWSTATE",
}


def detect_cms(html: str, headers: dict) -> list[str]:
    found = {cms for cms, pats in _CMS.items() if any(re.search(p, html, re.I) for p in pats)}
    powered = (headers.get("X-Powered-By") or headers.get("x-powered-by") or "").lower()
    for cms in ("WordPress", "Drupal"):
        if cms.lower() in powered:
            found.add(cms)
    return sorted(found)


def detect_cdn(headers: dict) -> list[str]:
    blob = " ".join(f"{k.lower()}:{str(v).lower()}" for k, v in headers.items())
    return sorted({cdn for cdn, inds in _CDN.items() if any(i in blob for i in inds)})


def detect_tech(html: str, headers: dict) -> list[str]:
    found = {tech for tech, pat in _TECH.items() if re.search(pat, html, re.I)}
    server = (headers.get("Server") or headers.get("server") or "").lower()
    powered = (headers.get("X-Powered-By") or headers.get("x-powered-by") or "").lower()
    for needle, label in [("nginx", "Nginx"), ("apache", "Apache"), ("iis", "IIS"),
                          ("litespeed", "LiteSpeed"), ("openresty", "OpenResty")]:
        if needle in server:
            found.add(label)
    if "php" in powered:
        found.add("PHP")
    if "asp.net" in powered or "asp.net" in server:
        found.add("ASP.NET")
    return sorted(found)


def detect_graphql(html: str, links: list[str]) -> dict:
    markers = ["/graphql", "/graphiql", "__schema", "graphql-playground", "apollo"]
    hits = [m for m in markers if m in html.lower() or any(m in l.lower() for l in links)]
    return {"detected": bool(hits), "markers": hits}


# --- secrets (confidence-rated) --------------------------------------------

# Confirmed: format is specific enough to be a real credential.
_CONFIRMED = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Google API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Token": r"gh[pousr]_[0-9A-Za-z]{36,}",
    "Stripe Live Key": r"sk_live_[0-9a-zA-Z]{24,}",
    "SendGrid Key": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Private Key Block": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    "JWT": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Google OAuth": r"ya29\.[0-9A-Za-z\-_]+",
}
# Potential: generic assignment; only kept when the value has high entropy.
_POTENTIAL = re.compile(r"""(?i)(api[_-]?key|secret|access[_-]?token|client[_-]?secret)["'\s:=]{1,4}["']?([A-Za-z0-9\-_./+]{20,60})""")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    return -sum((s.count(c) / len(s)) * math.log2(s.count(c) / len(s)) for c in set(s))


def scan_secrets(text: str, max_findings: int = 40) -> list[dict]:
    """Return findings with a confidence level so scoring can weight them."""
    findings: list[dict] = []
    seen: set[str] = set()
    for name, pat in _CONFIRMED.items():
        for m in re.finditer(pat, text):
            val = m.group(0)
            if val in seen:
                continue
            seen.add(val)
            findings.append({"type": name, "confidence": "confirmed",
                             "match": val[:40] + ("…" if len(val) > 40 else "")})
            if len(findings) >= max_findings:
                return findings
    for m in _POTENTIAL.finditer(text):
        val = m.group(2)
        if val in seen or _entropy(val) < 3.5:
            continue
        # Skip obvious non-secrets (urls, common words).
        if val.lower() in ("undefined", "null", "function", "your_api_key") or "/" in val and "." in val:
            continue
        seen.add(val)
        findings.append({"type": f"Possible {m.group(1)}", "confidence": "potential",
                         "match": val[:40] + ("…" if len(val) > 40 else ""), "entropy": round(_entropy(val), 1)})
        if len(findings) >= max_findings:
            break
    return findings


# --- links / forms / comments / JS -----------------------------------------


def extract_assets(html: str, base_url: str) -> dict:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    host = urlparse(base_url).netloc
    links, ext_links, forms, scripts, comments, emails = set(), set(), [], set(), [], set()

    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        (links if urlparse(href).netloc == host else ext_links).add(href)
    for f in soup.find_all("form"):
        inputs = f.find_all("input")
        forms.append({
            "action": urljoin(base_url, f.get("action", "")),
            "method": (f.get("method") or "get").upper(),
            "inputs": len(inputs),
            "has_password": any((i.get("type") or "").lower() == "password" for i in inputs),
        })
    for s in soup.find_all("script", src=True):
        scripts.add(urljoin(base_url, s["src"]))
    from bs4 import Comment

    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(c).strip()
        if text:
            comments.append(text[:160])
    for em in re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", html):
        emails.add(em)

    return {
        "internal_links": sorted(links)[:150],
        "external_links": sorted(ext_links)[:100],
        "forms": forms[:30],
        "scripts": sorted(scripts)[:80],
        "comments": comments[:30],
        "emails": sorted(emails)[:40],
    }


_JS_ENDPOINT_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{2,}|https?://[A-Za-z0-9_\-./?=&%]{6,})["'`]""")


def extract_js_endpoints(js_text: str, cap: int = 60) -> list[str]:
    out: set[str] = set()
    for m in _JS_ENDPOINT_RE.finditer(js_text):
        v = m.group(1)
        if any(v.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2", ".ico")):
            continue
        out.add(v)
        if len(out) >= cap:
            break
    return sorted(out)


def extract_metadata(html: str) -> dict:
    from bs4 import BeautifulSoup

    soup = BeautifulSoup(html, "html.parser")
    md = {"title": "", "description": "", "keywords": "", "generator": ""}
    if soup.title and soup.title.string:
        md["title"] = soup.title.string.strip()[:200]
    for tag in soup.find_all("meta"):
        name = (tag.get("name") or "").lower()
        if name == "description":
            md["description"] = (tag.get("content") or "").strip()[:300]
        elif name == "keywords":
            md["keywords"] = (tag.get("content") or "").strip()[:200]
        elif name == "generator":
            md["generator"] = (tag.get("content") or "").strip()[:120]
    return md

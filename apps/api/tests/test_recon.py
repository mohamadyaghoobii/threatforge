"""OSINT Recon tests — analyzers + scoring (offline, no network)."""

from __future__ import annotations

from app.services.recon import analyzers, engine, scoring

HTML = """<html><head><title>Demo Corp</title>
<meta name="description" content="A demo site">
<meta name="generator" content="WordPress 6.4">
<script src="/wp-content/themes/x/jquery.min.js"></script>
</head><body>
<!-- TODO remove debug key -->
<a href="/about">About</a><a href="https://twitter.com/x">tw</a>
<form action="http://demo.test/login" method="post"><input name="u"></form>
<script>var k="AKIAIOSFODNN7EXAMPLE"; var api_key="abcdef0123456789abcdef";</script>
contact: admin@demo.test
</body></html>"""

HEADERS = {"Server": "nginx/1.25", "X-Powered-By": "PHP/8.2", "cf-ray": "abc", "Content-Type": "text/html"}


def test_metadata():
    md = analyzers.extract_metadata(HTML)
    assert md["title"] == "Demo Corp"
    assert "demo" in md["description"].lower()
    assert "WordPress" in md["generator"]


def test_security_headers_audit():
    a = analyzers.audit_security_headers(HEADERS)
    missing = {m["header"] for m in a["missing"]}
    assert "Content-Security-Policy" in missing
    assert any(l["header"] == "server" for l in a["leaks"])


def test_cms_cdn_tech():
    assert "WordPress" in analyzers.detect_cms(HTML, HEADERS)
    assert "Cloudflare" in analyzers.detect_cdn(HEADERS)
    tech = analyzers.detect_tech(HTML, HEADERS)
    assert "Nginx" in tech and "PHP" in tech and "jQuery" in tech


def test_secret_scan_confidence():
    secrets = analyzers.scan_secrets(HTML)
    confirmed = [s for s in secrets if s["confidence"] == "confirmed"]
    assert any(s["type"] == "AWS Access Key" for s in confirmed)


def test_cookie_audit():
    headers = {"Set-Cookie": "sessionid=abc; Path=/, theme=dark; Path=/; Secure"}
    cookies = analyzers.audit_cookies(headers)
    names = {c["name"] for c in cookies}
    assert "sessionid" in names
    sess = next(c for c in cookies if c["name"] == "sessionid")
    assert sess["session_like"] and not sess["secure"]  # insecure session cookie


def test_graphql_detect():
    g = analyzers.detect_graphql("<a href='/graphql'>api</a>", ["/graphql"])
    assert g["detected"] and "/graphql" in g["markers"]


def test_js_endpoint_extraction():
    js = 'fetch("/api/v1/users"); const u="https://api.demo.test/data";'
    eps = analyzers.extract_js_endpoints(js)
    assert "/api/v1/users" in eps


def test_extract_assets():
    a = analyzers.extract_assets(HTML, "http://demo.test/")
    assert any("/about" in x for x in a["internal_links"])
    assert a["forms"] and a["forms"][0]["has_password"] is False
    assert "admin@demo.test" in a["emails"]


def test_scoring_missing_headers_is_not_high():
    # HTTPS site that merely lacks headers should NOT be graded F nor flagged high.
    sec = analyzers.audit_security_headers({"Content-Type": "text/html"})
    result = scoring.score_scan(https=True, security_headers=sec, cookies=[], secrets=[], forms=[])
    assert result["grade"] in ("B", "C")  # not D/F
    assert all(f["severity"] in ("medium", "low", "info") for f in result["findings"])


def test_scoring_confirmed_secret_is_critical():
    secrets = analyzers.scan_secrets(HTML)
    result = scoring.score_scan(https=False, security_headers=analyzers.audit_security_headers(HEADERS),
                                cookies=[], secrets=secrets, forms=[])
    assert any(f["severity"] == "critical" for f in result["findings"])
    assert result["score"] < 60


def test_scoring_exposed_path_high():
    sec = analyzers.audit_security_headers({})
    result = scoring.score_scan(https=True, security_headers=sec, cookies=[], secrets=[], forms=[],
                                exposed_paths=[{"path": "/.git/config", "severity": "high", "detail": "x"}])
    assert any(f["severity"] == "high" and ".git" in f["title"] for f in result["findings"])


def test_probe_path_matching_avoids_spa_false_positives():
    from app.services.recon import passive

    spa = b"<!doctype html><html><head><title>App</title></head><body>SPA</body></html>"
    # An SPA catch-all 200 must NOT count as an exposed git/server-status.
    assert passive._matches("/.git/config", spa) is False
    assert passive._matches("/server-status", spa) is False
    assert passive._matches("/.env", spa) is False
    # Real signatures DO match.
    assert passive._matches("/.git/config", b"[core]\n\trepositoryformatversion = 0") is True
    assert passive._matches("/.env", b"SECRET_KEY=abcd1234\nDB_HOST=localhost") is True
    assert passive._matches("/server-status", b"<h1>Apache Server Status for x</h1>Server uptime: 1 day") is True


def test_normalize_target():
    assert engine.normalize_target("example.com") == ("https://example.com", "example.com")
    url, host = engine.normalize_target("http://sub.example.com:8080/path")
    assert host == "sub.example.com"

"""Security-posture scoring for a recon scan.

Recalibrated to be realistic: a *missing* hardening header is a low/medium
gap, not "high". High/critical are reserved for genuine exposures —
confirmed secrets, exposed VCS/dotenv, password forms over HTTP, missing
HTTPS. Score starts at 100; deductions are weighted and capped so a
well-run site that merely lacks a few headers still grades well.
"""

from __future__ import annotations

from typing import Any

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def score_scan(*, https: bool, security_headers: dict, cookies: list[dict], secrets: list[dict],
               forms: list[dict], exposed_paths: list[dict] | None = None,
               graphql: dict | None = None) -> dict[str, Any]:
    score = 100
    findings: list[dict] = []
    exposed_paths = exposed_paths or []

    def add(sev, title, detail, penalty):
        nonlocal score
        score -= penalty
        findings.append({"severity": sev, "title": title, "detail": detail})

    # --- transport ---
    if not https:
        add("high", "No HTTPS", "Target is served over plain HTTP.", 25)

    present = {h["header"] for h in security_headers.get("present", [])}
    has_hsts = "Strict-Transport-Security" in present

    # --- confirmed secrets (the real high-severity signal) ---
    confirmed = [s for s in secrets if s.get("confidence") == "confirmed"]
    potential = [s for s in secrets if s.get("confidence") != "confirmed"]
    if confirmed:
        add("critical", f"{len(confirmed)} confirmed secret(s) exposed",
            ", ".join(sorted({s['type'] for s in confirmed})), min(50, 25 * len(confirmed)))
    if potential:
        add("low", f"{len(potential)} possible secret-like string(s)",
            "High-entropy values in source; verify (often false positives).", min(5, len(potential)))

    # --- exposed sensitive paths (.git/.env/swagger/etc.) ---
    for p in exposed_paths:
        sev = p.get("severity", "medium")
        pen = {"critical": 25, "high": 18, "medium": 8, "low": 3}.get(sev, 8)
        add(sev, f"Exposed: {p['path']}", p.get("detail", "Reachable sensitive path."), pen)

    # --- forms ---
    http_pw_forms = [f for f in forms if str(f.get("action", "")).startswith("http://") and f.get("has_password")]
    http_forms = [f for f in forms if str(f.get("action", "")).startswith("http://") and not f.get("has_password")]
    if http_pw_forms:
        add("high", "Password form over HTTP", f"{len(http_pw_forms)} login form(s) submit credentials insecurely.", 14)
    elif http_forms:
        add("medium", "Form posts over HTTP", f"{len(http_forms)} form(s) submit over HTTP.", 6)

    # --- cookies ---
    insecure_session = [c for c in cookies if c.get("session_like") and (not c.get("secure") or not c.get("httponly"))]
    if insecure_session:
        add("medium", "Insecure session cookie",
            f"{len(insecure_session)} session-like cookie(s) missing Secure/HttpOnly.", 6)

    # --- headers (gentle, capped) ---
    if "Content-Security-Policy" not in present:
        add("medium", "Missing Content-Security-Policy", "No CSP — weaker XSS/clickjacking defense.", 8)
    if https and not has_hsts:
        add("medium", "HSTS not enforced", "HTTPS without Strict-Transport-Security.", 6)
    other_missing = [h for h in security_headers.get("missing", [])
                     if h["header"] not in ("Content-Security-Policy", "Strict-Transport-Security")]
    if other_missing:
        add("low", f"{len(other_missing)} hardening header(s) missing",
            ", ".join(h["header"] for h in other_missing[:6]), min(10, 2 * len(other_missing)))

    # --- info-leak version headers ---
    version_leaks = [l for l in security_headers.get("leaks", []) if l.get("discloses_version")]
    if version_leaks:
        add("low", "Version-disclosing headers", ", ".join(l["header"] for l in version_leaks), min(6, 2 * len(version_leaks)))

    # --- graphql introspection hint ---
    if graphql and graphql.get("detected"):
        add("info", "GraphQL endpoint detected", "Review introspection exposure.", 0)

    score = max(0, min(100, score))
    grade = "A" if score >= 90 else "B" if score >= 78 else "C" if score >= 62 else "D" if score >= 45 else "F"
    findings.sort(key=lambda f: _SEV_ORDER.get(f["severity"], 5))
    return {"score": score, "grade": grade, "findings": findings}

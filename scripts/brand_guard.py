#!/usr/bin/env python3
"""Brand guard: fail if forbidden legacy/personal branding appears in any
user-facing surface (frontend, public API routes, recon engine, generated
SIEM artifacts, dashboards). Internal-only identifiers — the
`detectionforge_rule_engine` import path, package names, database names, and
UUID namespace seeds — are deliberately out of scope and are NOT scanned.

Usage:
    python scripts/brand_guard.py        # exit 1 if any forbidden hit

Public product name is "MetaSec Security Center".
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# User-facing surfaces only.
SCAN_DIRS = [
    "apps/web/app",
    "apps/web/components",
    "apps/web/lib",
    "apps/api/app/api",
    "apps/api/app/services/recon",
    "apps/api/app/services/generator/formats",
    "apps/api/app/services/dashboard/generators",
]
SCAN_FILES = [
    "apps/api/app/services/rule_service.py",
    "apps/api/app/core/settings.py",
]
EXTS = {".py", ".ts", ".tsx", ".js", ".jsx", ".css"}
SKIP_DIRS = {"node_modules", ".next", "__pycache__", ".venv", ".git"}

# (compiled pattern, human label). Brand names matched case-sensitively so the
# internal lowercase package path is not flagged; identities case-insensitively.
FORBIDDEN = [
    (re.compile(r"ThreatForge"), "legacy brand 'ThreatForge'"),
    (re.compile(r"DetectionForge"), "legacy brand 'DetectionForge'"),
    (re.compile(r"[Ii]ka[Rr]econ"), "legacy brand 'IkaRecon'"),
    (re.compile(r"\b[Ii]karus\b"), "legacy brand 'Ikarus'"),
    (re.compile(r"(?i)yaghoob|mohamad"), "personal name"),
    (re.compile(r"(?i)linkedin\.com|instagram\.com"), "personal social link"),
    (re.compile(r"(?i)github\.com/mohamadyaghoob"), "personal GitHub link"),
    (re.compile(r"[A-Za-z0-9._%+-]+@(?:gmail|yahoo|outlook|hotmail|proton)\.[a-z]+"), "personal email"),
]


def iter_files():
    for d in SCAN_DIRS:
        base = ROOT / d
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_dir() or any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.suffix in EXTS:
                yield p
    for f in SCAN_FILES:
        p = ROOT / f
        if p.exists():
            yield p


def main() -> int:
    hits = []
    for path in iter_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for pattern, label in FORBIDDEN:
                if pattern.search(line):
                    rel = path.relative_to(ROOT).as_posix()
                    hits.append((rel, i, label, line.strip()[:100]))

    if hits:
        print(f"BRAND GUARD: FAIL - {len(hits)} forbidden reference(s) in user-facing surfaces:\n")
        for rel, line_no, label, snippet in hits:
            print(f"  {rel}:{line_no}  [{label}]")
            print(f"      {snippet}")
        print("\nPublic product name must be 'MetaSec Security Center'. See scripts/brand_guard.py.")
        return 1

    print("BRAND GUARD: PASS - no forbidden branding in user-facing surfaces.")
    print(f"Scanned {len(SCAN_DIRS)} directories + {len(SCAN_FILES)} files under {ROOT.name}/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

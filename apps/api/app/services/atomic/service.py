"""Atomic Bible loader + queries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.settings import get_settings
from app.models.atomic import AtomicTest


def _seed_path() -> Path:
    configured = get_settings().data_path / "atomic" / "atomic_bible.json"
    here = Path(__file__).resolve()
    candidates = [configured]

    for base in [Path.cwd(), *here.parents]:
        candidates.append(base / "data" / "atomic" / "atomic_bible.json")
        candidates.append(base / "apps" / "api" / "data" / "atomic" / "atomic_bible.json")

    seen = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        if path.exists():
            print(f"Atomic Bible path: {path}", flush=True)
            return path

    raise FileNotFoundError("atomic_bible.json not found. Checked: " + " | ".join(str(p) for p in candidates))


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _executor_name(value: Any) -> str:
    if isinstance(value, dict):
        return value.get("name", "") or value.get("executor", "") or ""
    if isinstance(value, str):
        return value
    return ""


def _executor_command(value: Any, item: dict[str, Any]) -> str:
    if isinstance(value, dict):
        return value.get("command", "") or ""
    return item.get("command", "") or ""


def _executor_elevation(value: Any, item: dict[str, Any]) -> bool:
    if isinstance(value, dict):
        return bool(value.get("elevation_required", False))
    return bool(item.get("elevation_required", False))


def _flatten_seed_tests(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        source = data
    elif isinstance(data, dict) and isinstance(data.get("tests"), list):
        source = data.get("tests", [])
    elif isinstance(data, dict) and isinstance(data.get("techniques"), list):
        source = data.get("techniques", [])
    else:
        source = []

    output = []

    for item in source:
        if not isinstance(item, dict):
            continue

        nested = item.get("atomic_tests")
        if not isinstance(nested, list):
            nested = item.get("tests") if isinstance(item.get("tests"), list) else None

        if isinstance(nested, list):
            technique_id = item.get("technique_id") or item.get("attack_technique") or item.get("id") or ""
            technique_name = item.get("technique_name") or item.get("display_name") or item.get("name") or ""
            tactics = item.get("tactics") or item.get("tactic") or []
            platforms = item.get("platforms") or item.get("supported_platforms") or []

            for test in nested:
                if not isinstance(test, dict):
                    continue

                executor = test.get("executor", {})
                output.append({
                    "technique_id": test.get("technique_id") or technique_id,
                    "technique_name": test.get("technique_name") or technique_name,
                    "tactics": _as_list(test.get("tactics") or tactics),
                    "test_name": test.get("test_name") or test.get("name") or "",
                    "description": test.get("description") or "",
                    "platforms": _as_list(test.get("platforms") or test.get("supported_platforms") or platforms),
                    "executor": _executor_name(executor),
                    "elevation_required": _executor_elevation(executor, test),
                    "command": test.get("command") or _executor_command(executor, test),
                })
        else:
            executor = item.get("executor", {})
            output.append({
                "technique_id": item.get("technique_id") or item.get("attack_technique") or item.get("id") or "",
                "technique_name": item.get("technique_name") or item.get("display_name") or "",
                "tactics": _as_list(item.get("tactics") or item.get("tactic") or []),
                "test_name": item.get("test_name") or item.get("name") or "",
                "description": item.get("description") or "",
                "platforms": _as_list(item.get("platforms") or item.get("supported_platforms") or []),
                "executor": _executor_name(executor),
                "elevation_required": _executor_elevation(executor, item),
                "command": item.get("command") or _executor_command(executor, item),
            })

    return output


def load_seed(db: Session, force: bool = False) -> int:
    path = _seed_path()

    if not force and db.query(AtomicTest).count() > 0:
        return 0

    data = json.loads(path.read_text(encoding="utf-8"))
    tests = _flatten_seed_tests(data)
    print(f"Atomic seed parsed tests: {len(tests)}", flush=True)

    created = 0
    for t in tests:
        db.add(AtomicTest(
            technique_id=t.get("technique_id", ""),
            technique_name=t.get("technique_name", ""),
            tactics=json.dumps(t.get("tactics", [])),
            test_name=t.get("test_name", ""),
            description=t.get("description", ""),
            platforms=json.dumps(t.get("platforms", [])),
            executor=t.get("executor", ""),
            elevation_required=1 if t.get("elevation_required") else 0,
            command=t.get("command", ""),
        ))
        created += 1

    db.commit()
    return created

def _jl(v: str | None) -> list[str]:
    try:
        return json.loads(v) if v else []
    except (ValueError, TypeError):
        return []


def _row(t: AtomicTest) -> dict[str, Any]:
    return {
        "id": t.id, "technique_id": t.technique_id, "technique_name": t.technique_name,
        "test_name": t.test_name, "description": t.description,
        "platforms": _jl(t.platforms), "executor": t.executor,
        "elevation_required": bool(t.elevation_required), "command": t.command, "guid": t.guid,
    }


def stats(db: Session) -> dict[str, Any]:
    total = db.query(AtomicTest).count()
    techniques = db.query(AtomicTest.technique_id).distinct().count()
    from collections import Counter

    by_exec: Counter = Counter()
    by_platform: Counter = Counter()
    for t in db.query(AtomicTest).all():
        if t.executor:
            by_exec[t.executor] += 1
        for p in _jl(t.platforms):
            by_platform[p] += 1
    return {"tests": total, "techniques": techniques,
            "by_executor": dict(by_exec.most_common(10)),
            "by_platform": dict(by_platform.most_common(10))}


def techniques(db: Session, q: str | None = None, platform: str | None = None, limit: int = 500) -> list[dict]:
    rows = db.query(AtomicTest).all()
    groups: dict[str, dict] = {}
    for t in rows:
        if platform and platform not in _jl(t.platforms):
            continue
        if q:
            ql = q.lower()
            if ql not in (t.technique_id or "").lower() and ql not in (t.technique_name or "").lower() \
               and ql not in (t.test_name or "").lower() and ql not in (t.description or "").lower():
                continue
        g = groups.setdefault(t.technique_id, {"technique_id": t.technique_id, "technique_name": t.technique_name,
                                               "test_count": 0, "platforms": set()})
        g["test_count"] += 1
        g["platforms"].update(_jl(t.platforms))
    out = [{**g, "platforms": sorted(g["platforms"])} for g in groups.values()]
    out.sort(key=lambda x: x["technique_id"])
    return out[:limit]


def tests_for(db: Session, technique_id: str) -> list[dict]:
    rows = db.query(AtomicTest).filter(AtomicTest.technique_id == technique_id.upper()).all()
    return [_row(t) for t in rows]


def search_tests(db: Session, q: str | None = None, platform: str | None = None,
                 executor: str | None = None, limit: int = 300) -> list[dict]:
    query = db.query(AtomicTest)
    if executor:
        query = query.filter(AtomicTest.executor == executor)
    rows = query.limit(8000).all()
    out = []
    ql = (q or "").lower()
    for t in rows:
        if platform and platform not in _jl(t.platforms):
            continue
        if ql and ql not in " ".join([t.technique_id or "", t.technique_name or "", t.test_name or "", t.description or "", t.command or ""]).lower():
            continue
        out.append(_row(t))
        if len(out) >= limit:
            break
    return out


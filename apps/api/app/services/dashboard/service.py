"""Dashboard generation orchestrator.

scope + target + layout -> DashboardPlan (builder) -> rows (layouts) ->
artifact (per-target generator). Optionally persists the generated
dashboard.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.dashboard import Dashboard
from app.services.dashboard import builder, layouts
from app.services.dashboard.generators import elastic_ndjson, sentinel_workbook, splunk_xml

# target -> (generator fn, format id, content_type, file_extension)
_GENERATORS = {
    "splunk": (splunk_xml.generate, "simple_xml", "application/xml", ".xml"),
    "sentinel": (sentinel_workbook.generate, "workbook_json", "application/json", ".json"),
    "elastic": (elastic_ndjson.generate, "saved_objects_ndjson", "application/x-ndjson", ".ndjson"),
}

SUPPORTED_TARGETS = set(_GENERATORS)


def supported_layouts() -> list[str]:
    return sorted(layouts.LAYOUTS)


def generate(
    db: Session,
    *,
    name: str,
    target: str,
    layout: str,
    profile: str | None,
    scope: dict[str, Any],
    earliest: str = "-24h",
    latest: str = "now",
    save: bool = False,
) -> dict[str, Any]:
    if target not in _GENERATORS:
        raise ValueError(f"Dashboard generation not supported for target {target!r}. Supported: {sorted(_GENERATORS)}")
    if layout not in layouts.LAYOUTS:
        layout = "grid"

    plan = builder.build_plan(db, name=name, target=target, layout=layout, profile=profile, scope=scope)
    rows = layouts.arrange(plan.panels, layout)

    gen_fn, fmt_id, content_type, ext = _GENERATORS[target]
    if target == "splunk":
        artifact = gen_fn(plan, rows, earliest=earliest, latest=latest)
    else:
        artifact = gen_fn(plan, rows)

    filename = f"{_slug(name)}{ext}"
    result = {
        "name": name,
        "target": target,
        "layout": layout,
        "format": fmt_id,
        "content_type": content_type,
        "filename": filename,
        "panel_count": len(plan.panels),
        "artifact": artifact,
        "panels": [
            {
                "title": p.title,
                "technique": p.technique,
                "tactic": p.tactic,
                "severity": p.severity,
                "viz": p.viz,
                "backend": p.backend,
            }
            for p in plan.panels
        ],
    }

    if save:
        row = Dashboard(
            name=name,
            target=target,
            layout=layout,
            profile=profile,
            output_format=fmt_id,
            scope_json=json.dumps(scope),
            panel_count=len(plan.panels),
            artifact_text=artifact,
            created_at=datetime.utcnow(),
        )
        db.add(row)
        db.commit()
        result["id"] = row.id

    return result


def _slug(text: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in text.lower()).strip("-")[:80] or "dashboard"

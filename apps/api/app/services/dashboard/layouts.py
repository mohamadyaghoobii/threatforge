"""Arrange a flat panel list into rows according to a layout preset."""

from __future__ import annotations

from app.services.dashboard.builder import PanelSpec

TACTIC_ORDER = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact",
]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

LAYOUTS = {"kill_chain", "by_severity", "by_data_source", "single_technique", "grid"}


def _chunk(panels: list[PanelSpec], size: int = 2) -> list[list[PanelSpec]]:
    return [panels[i : i + size] for i in range(0, len(panels), size)]


def arrange(panels: list[PanelSpec], layout: str) -> list[list[PanelSpec]]:
    if not panels:
        return []
    if layout == "kill_chain":
        rows: list[list[PanelSpec]] = []
        for tactic in TACTIC_ORDER:
            group = [p for p in panels if p.tactic == tactic]
            rows.extend(_chunk(group, 2))
        leftover = [p for p in panels if p.tactic not in TACTIC_ORDER]
        rows.extend(_chunk(leftover, 2))
        return [r for r in rows if r]
    if layout == "by_severity":
        rows = []
        for sev in SEVERITY_ORDER:
            group = [p for p in panels if (p.severity or "").lower() == sev]
            rows.extend(_chunk(group, 2))
        leftover = [p for p in panels if (p.severity or "").lower() not in SEVERITY_ORDER]
        rows.extend(_chunk(leftover, 2))
        return [r for r in rows if r]
    if layout == "by_data_source":
        # Group by the technique prefix as a cheap proxy for data source.
        buckets: dict[str, list[PanelSpec]] = {}
        for p in panels:
            buckets.setdefault(p.technique or "other", []).append(p)
        rows = []
        for key in sorted(buckets):
            rows.extend(_chunk(buckets[key], 2))
        return [r for r in rows if r]
    if layout == "single_technique":
        # One panel per row, full width.
        return [[p] for p in panels]
    # grid (default)
    return _chunk(panels, 2)

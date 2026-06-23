# Design: Dashboard Generator (Phase 1C — flagship feature)

## Goal
Given a set of use cases (or a tactic / actor / campaign) and a target SIEM,
generate a ready-to-import dashboard artifact (Splunk XML, Sentinel
Workbook, Kibana NDJSON) that surfaces detections, drill-downs, and
coverage gaps.

This is the "dashboard generation" feature requested for V2.

## High-level UX
A 3-step wizard at `/dashboards/new`:

1. **Scope**
   - Pick by: MITRE matrix selection, tactic, threat actor, campaign, or
     manual use case selection.
   - Result: a list of use case ids + auto-derived "rule clusters".
2. **Target + layout**
   - SIEM target (splunk / sentinel / elastic).
   - Layout preset:
     - `kill_chain`     — one row per ATT&CK tactic, panels per technique
     - `by_data_source` — one row per log source (sysmon, security, network)
     - `by_severity`    — critical / high / medium / low rows
     - `actor_overview` — actor TTP heatmap + recent matches + top hosts
   - Time range default, refresh interval.
3. **Preview + export**
   - Render thumbnails of each panel.
   - Download artifact (.xml / .json / .ndjson) and / or save to DB.

## Backend design

### Domain model
```
dashboards (
  id, name, owner, target, layout, scope_json, status,
  created_at, updated_at
)
dashboard_panels (
  id, dashboard_id, position, panel_type, title,
  use_case_id, rule_cluster_id, viz_kind, viz_config_json,
  source_query, query_status
)
```

`panel_type` ∈ {`single_stat`, `time_chart`, `top_n_table`, `event_table`,
`heatmap`, `geo_map`, `coverage_matrix`, `markdown`}.

### Service layout (new module)
```
apps/api/app/services/dashboard/
  __init__.py
  builder.py          # scope → list[Panel]
  layout.py           # arrange Panels into rows/columns
  generator_splunk.py
  generator_sentinel.py
  generator_elastic.py
  templates/
    splunk/
      kill_chain.xml.j2
      panel_time_chart.xml.j2
      panel_top_table.xml.j2
    sentinel/
      workbook.json.j2
    elastic/
      kibana_dashboard.ndjson.j2
```

`builder.py` workflow:
```
scope = {use_case_ids: [], tactics: [], actor_id: ...}
1. Resolve scope -> list[UseCase]
2. For each use case:
   - pick "preferred rule" (highest quality_score, status=stable)
   - convert to target SIEM via existing convert_rule()
   - decide viz_kind:
       * single rule + high frequency event -> time_chart
       * group by suspect entity (user, host, process) -> top_n_table
       * any selection on EventID range -> event_table
       * tactic-level summary panel -> single_stat (count of distinct techniques)
3. Group panels by layout preset
4. Return list[PanelSpec]
```

### Per-target generators

| Target   | Format                              | Library / approach                          |
|----------|--------------------------------------|---------------------------------------------|
| Splunk   | Simple XML (.xml)                    | Jinja2 templates, validated against Splunk Simple XML schema |
| Sentinel | Workbook ARM template (.json)       | Jinja2 → ARM JSON with `azureResourceType:` workbook         |
| Elastic  | Kibana saved-objects export (.ndjson) | Build saved_objects: dashboard + visualizations + lens       |

Generators take `list[PanelSpec]` + `LayoutSpec` → return `{filename, content_type, body}`.

### New endpoints
```
POST   /api/dashboards/generate          # one-shot: spec -> file
POST   /api/dashboards                   # save spec
GET    /api/dashboards                   # list saved
GET    /api/dashboards/{id}              # detail
POST   /api/dashboards/{id}/export       # regenerate from saved spec
DELETE /api/dashboards/{id}
GET    /api/dashboards/{id}/preview      # JSON preview for UI rendering
```

Request body for `POST /api/dashboards/generate`:
```json
{
  "name": "Initial Access Coverage — Sysmon",
  "target": "splunk",
  "layout": "kill_chain",
  "time_range": "-24h",
  "scope": {
    "tactics": ["Initial Access"],
    "use_case_ids": ["T1566", "T1190"],
    "actor_id": null
  },
  "options": {
    "include_coverage_matrix": true,
    "include_markdown_headers": true
  }
}
```

Response:
```json
{
  "filename": "dashboard_initial_access.xml",
  "content_type": "application/xml",
  "size_bytes": 13422,
  "panels": 12,
  "body_base64": "..."
}
```

## Panel synthesis examples

### Splunk single_stat panel
Source SPL produced from a use case (e.g. T1059.001 PowerShell):
```spl
index=sysmon EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| stats count
```
Rendered XML:
```xml
<panel>
  <single>
    <title>T1059.001 — PowerShell (last 24h)</title>
    <search>
      <query>index=sysmon EventCode=1 ...</query>
      <earliest>-24h</earliest>
      <latest>now</latest>
    </search>
  </single>
</panel>
```

### Splunk top_n panel
```spl
... | top limit=10 Computer
```
Rendered as `<table>` panel.

### Sentinel coverage matrix
Workbook tile = `grid` with KQL:
```kql
union withsource=TableName *
| where ... whatever the rule predicates are ...
| summarize Count = count() by Technique = "T1059.001"
```

### Elastic Lens
Use Lens config JSON; emit one Lens viz per panel, embed in dashboard
saved object.

## Frontend wizard

`/dashboards/new`:
- Step 1 — `ScopePicker` (matrix multiselect / dropdown chips)
- Step 2 — `LayoutPicker` + `TargetPicker`
- Step 3 — `Preview` (live render via `GET /api/dashboards/.../preview`)
  + `Save` + `Download` buttons.

Saved list at `/dashboards` shows table with name, target, panels,
last generated.

## Validation
- Splunk artifact: parse with `xmllint` / lxml, ensure all required tags.
- Sentinel: `az workbook show` not required; do JSON schema check.
- Elastic: must be valid NDJSON, one object per line, includes `type`.

## Effort estimate
- Backend domain + builder skeleton: 1 day
- Splunk generator + 2 layouts: 1.5 days
- Sentinel workbook generator: 1.5 days
- Elastic NDJSON generator: 1 day
- Wizard UI: 2 days
- Tests + sample dashboards committed under `docs/examples/`: 1 day

Total: ~7 days.

## Acceptance
- For each target (splunk, sentinel, elastic), generating a `kill_chain`
  layout from the 14 tactics produces an artifact that **imports cleanly**
  in that SIEM.
- At least 3 panel types render correctly per target.
- Saving a spec and regenerating produces a byte-stable artifact for the
  same data snapshot.
- Wizard preview renders within 2s for a 20-panel dashboard.

## Future
- Custom panel editor (manual SPL/KQL).
- Per-panel ownership + signoff.
- "Dashboard suggestions" — given a new threat actor in the catalog, suggest
  which panels to add to an existing dashboard.

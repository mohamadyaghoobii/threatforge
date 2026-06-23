# Design: Use Case & Dashboard Taxonomy (Phase 1D)

## Goal
Define the **classification system** that lets ThreatForge scale to **hundreds of dashboards and thousands of use cases** across multiple SIEMs (Splunk, Sentinel, Elastic, OpenSearch, QRadar, Chronicle, LogScale).

Without a taxonomy, the dashboard generator can produce one-offs but cannot
do bulk generation, navigation, search, or coverage analytics. With the
taxonomy below, every use case and every dashboard has a deterministic
identity, a parent category, and a set of facets — so the same template can
spawn 1, 14, or 600+ artifacts driven by data.

---

## Part A — Use Case classification

A **use case** in ThreatForge is one "thing we want to detect", independent
of which rule variants implement it.

### A.1 Primary classification (the hierarchy)

Use cases are arranged in a strict hierarchy. Every use case lives at exactly
one node:

```
Domain
└── Kill chain phase  (Reconnaissance, Weaponization, ... Actions on Objectives)
    └── MITRE Tactic  (14 ATT&CK Enterprise tactics)
        └── MITRE Technique  (~200 techniques)
            └── MITRE Sub-technique  (~450 sub-techniques)
                └── Procedure  (concrete attacker behavior)
```

| Level | Count (Enterprise) | Example | Use-case id format |
|---|---|---|---|
| Domain | 3 | `enterprise`, `mobile`, `ics` | `UC.<domain>` |
| Kill chain phase | 7 | `actions-on-objectives` | derived |
| Tactic | 14 | `Initial Access` | `UC.TA0001` |
| Technique | ~200 | `T1059 Command and Scripting Interpreter` | `UC.T1059` |
| Sub-technique | ~450 | `T1059.001 PowerShell` | `UC.T1059.001` |
| Procedure | unbounded | "PowerShell -enc base64 cradle" | `UC.T1059.001.P<n>` |

### A.2 Facets (orthogonal tags applied to every use case)

Facets let the same use case be searched/filtered/dashboarded from many
angles. A use case can carry many values per facet.

| Facet | Purpose | Example values |
|---|---|---|
| `platform` | Where the attack runs | `windows`, `linux`, `macos`, `containers`, `cloud-aws`, `cloud-azure`, `cloud-gcp`, `m365`, `gws`, `network`, `ot-ics`, `mobile-android`, `mobile-ios` |
| `data_source` | Telemetry needed to detect | `sysmon`, `wineventlog-security`, `wineventlog-powershell`, `edr`, `auditd`, `osquery`, `firewall`, `proxy`, `dns`, `email-gateway`, `idp`, `cloudtrail`, `azure-activity`, `gcp-audit`, `kubernetes-audit`, `network-pcap`, `netflow` |
| `log_category` | Sigma logsource category | `process_creation`, `network_connection`, `file_event`, `registry_event`, `image_load`, `dns_query`, `authentication`, `web` |
| `severity` | Detection-time risk | `critical`, `high`, `medium`, `low`, `informational` |
| `confidence` | False-positive likelihood | `high`, `medium`, `low` |
| `detection_logic` | Algorithmic shape | `signature`, `behavior`, `anomaly`, `threshold`, `statistical`, `ml`, `correlation`, `lookup-enrichment` |
| `attack_lifecycle` | High-level phase | `pre-attack`, `intrusion`, `lateral`, `objective`, `post-objective` |
| `intent` | Why an attacker does it | `discovery`, `persistence`, `evasion`, `theft`, `destruction`, `ransom`, `espionage` |
| `actor_attribution` | Known to be used by | `apt28`, `apt29`, `lazarus`, `fin7`, `lockbit`, ... (MITRE Groups ids) |
| `malware_family` | Implemented by | `cobaltstrike`, `mimikatz`, `emotet`, `qakbot`, ... (MITRE Software ids) |
| `industry` | Most relevant verticals | `finance`, `healthcare`, `government`, `manufacturing`, `energy-utilities`, `retail`, `tech`, `education`, `telecom`, `defense` |
| `compliance` | Mapped controls | `pci-dss-10`, `hipaa-164.312`, `soc2-cc7`, `iso27001-a12`, `nist-csf-de.cm`, `nist-800-53-au`, `cmmc-l2-au` |
| `mitre_data_components` | ATT&CK data components | `process-creation`, `command-execution`, `network-traffic-flow`, `os-api-execution` |
| `mitre_mitigations` | Mapped mitigations | `m1040`, `m1042`, `m1026`, ... |
| `lifecycle_status` | Internal maturity | `draft`, `validated`, `production`, `deprecated` |
| `tuning_difficulty` | Operational cost | `plug-and-play`, `light-tuning`, `environment-specific`, `requires-baseline` |
| `enrichment_required` | External feeds needed | `none`, `threat-intel`, `asset-inventory`, `identity-graph`, `vulnerability-data` |
| `response_playbook` | Linked SOAR runbook | playbook-id |

### A.3 Use case naming convention
```
UC.<technique_or_subtechnique>.<short-slug>
```
Examples:
- `UC.T1059.001.powershell-encoded-cradle`
- `UC.T1078.004.cloud-account-impossible-travel`
- `UC.T1486.ransomware-mass-rename`

Slugs are lowercase, hyphenated, ASCII-only. The technique id is the
canonical join key — slug is only for human readability.

### A.4 Coverage rollups
Because of the hierarchy + facets, the platform can answer rollup questions:

- How many use cases do we have for **Initial Access × cloud-aws × critical**?
- Which **techniques** have zero use cases for **macos**?
- Which **APT29-attributed** techniques lack any production-grade use case?

These rollups are what feed the matrix heatmap and coverage dashboards.

---

## Part B — Dashboard classification

A **dashboard** is a deliverable artifact (XML / JSON / NDJSON) for a target SIEM.

### B.1 Dashboard families (the "shapes")

A family is the *intent* of the dashboard. Family + scope + layout fully
determine the artifact.

| Family | Audience | Purpose |
|---|---|---|
| **Executive Overview** | CISO / SOC manager | Top-level KPIs: detections fired, MTTR, coverage %, top tactics, top hosts |
| **SOC Operations** | Tier 1 / 2 analyst | Triage queue, today's alerts grouped by tactic + severity, oldest open |
| **Tactic Deep-Dive** | Tier 2 / 3 analyst | One dashboard per tactic; technique-level panels for that tactic |
| **Technique Hunt** | Threat hunter | One dashboard per technique or sub-technique; raw event search, pivot panels |
| **Threat Actor Profile** | CTI analyst | TTP heatmap for one actor, matched detections, campaigns, IoCs |
| **Campaign Investigation** | IR | Timeline, indicators, affected hosts/users, attribution |
| **Malware Family Profile** | Malware analyst | C2 patterns, persistence sites, network beacons, file artifacts |
| **Use Case Operations** | Detection engineer | Per-use-case fire rate, FP rate, suppression, tuning state |
| **Coverage Gap** | Detection eng + CTI | Matrix of `coverage × ATT&CK`; "what we cannot see" |
| **Data Source Health** | Eng / SOC ops | Sysmon EID volumes, gaps, host coverage %, lag |
| **Compliance** | GRC | Mapped controls × detection coverage × evidence |
| **Industry / Vertical Threat** | CISO / SOC manager | Curated TTPs known to target an industry |
| **Insider Threat** | DLP / HR-linked | UEBA-style: anomalous user behavior, exfil, privileged abuse |
| **Cloud Posture + Detection** | Cloud security | CloudTrail / Azure-Activity detections + drift |
| **Identity Threats** | IAM / SOC | Auth anomalies, MFA bypass, golden ticket, impossible travel |
| **Endpoint Threats** | Endpoint team | Sysmon / EDR-centric detections |
| **Network Threats** | NetOps / SOC | Lateral movement, beaconing, exfil channels |
| **Email / Phishing** | SOC + email admin | Suspicious senders, attachments, URL clicks |
| **Vulnerability + Exploitation** | VM team | CVE-linked detections vs. asset exposure |
| **Detection Health / QA** | Detection eng | Rules fired / not fired in N days, parser errors |

### B.2 Layouts (the "skeletons")

A layout describes the visual structure independent of content.

| Layout id | Structure | Best for families |
|---|---|---|
| `kill_chain` | 14 rows of tactics, each row = panels for techniques | Tactic Deep-Dive, Coverage Gap, Executive Overview |
| `by_data_source` | One row per data source group | Data Source Health, SOC Operations |
| `by_severity` | Rows = critical → informational | SOC Operations, Triage |
| `by_platform` | Rows = windows / linux / mac / cloud | Endpoint, Cloud Posture |
| `actor_profile` | Header (actor metadata) → TTP heatmap → matched detections → IoCs → campaigns | Threat Actor Profile |
| `campaign_timeline` | Time-axis swimlane + entity table | Campaign Investigation |
| `top_n` | Single column of Top-N panels | Quick wins |
| `single_technique_deep` | Header → query → time-chart → top entities → raw events → MITRE context | Technique Hunt |
| `coverage_matrix` | 14×N grid colored by detection presence | Coverage Gap |
| `kpi_grid` | Single-stats grid + 2–3 trend panels | Executive Overview |
| `entity_pivot` | Pick a user/host/process → enriched panels | IR, Insider Threat |
| `correlation_storyboard` | Sequence of related rules ordered by likely attack order | Campaign Investigation |

### B.3 Per-SIEM artifact formats

| Target | Format | File extension | Generator backend |
|---|---|---|---|
| **Splunk** | Simple XML | `.xml` | Jinja2 → SimpleXML schema |
| **Splunk** | Dashboard Studio JSON | `.json` | Jinja2 → DS schema |
| **Splunk** | Saved searches conf | `.conf` | Jinja2 → `savedsearches.conf` |
| **Microsoft Sentinel** | Workbook ARM template | `.json` | Jinja2 → ARM workbook |
| **Microsoft Sentinel** | Analytics rule | `.json` | Jinja2 → ARM Microsoft.SecurityInsights/alertRules |
| **Microsoft Sentinel** | Hunting query | `.yaml` | Jinja2 |
| **Elastic / Kibana** | Saved-objects NDJSON | `.ndjson` | Jinja2 → saved_object lines |
| **Elastic Security** | Detection rule | `.ndjson` / API | Jinja2 |
| **OpenSearch Dashboards** | Saved-objects NDJSON | `.ndjson` | Jinja2 |
| **QRadar** | AQL + dashboard XML | `.xml` | Jinja2 |
| **QRadar** | Custom rule (offense) | XML | Jinja2 |
| **Google Chronicle** | YARA-L rule | `.yaral` | Jinja2 (best-effort) |
| **Google Chronicle** | Dashboard JSON (Looker-backed) | `.json` | Jinja2 (limited) |
| **CrowdStrike LogScale** | Dashboard JSON | `.json` | Jinja2 |
| **CrowdStrike LogScale** | Saved query | `.yaml` | Jinja2 |
| **Devo** | Activeboard JSON | `.json` | Jinja2 |
| **Sumo Logic** | Dashboard JSON | `.json` | Jinja2 |

The same `PanelSpec` model produced by the dashboard builder feeds every
generator. The generator only knows how to render that spec in its own
serialization.

### B.4 Panel kinds (the "tiles")

A panel is a single tile inside a dashboard. Panel kind + a converted
query + viz config = renderable tile.

| Panel kind | Description |
|---|---|
| `single_stat` | One number with delta vs. previous period |
| `time_series_line` | Line chart over time |
| `time_series_area` | Stacked area chart |
| `time_series_bar` | Bar chart over time |
| `top_n_table` | Top-N grouping by a field |
| `event_table` | Raw event rows |
| `heatmap` | 2-D grid colored by count |
| `geo_map` | Latitude/longitude map |
| `chord_or_sankey` | Source → destination flow |
| `mitre_coverage_matrix` | Custom ATT&CK matrix grid |
| `host_user_pivot` | Entity-centric grid with quick filters |
| `markdown_header` | Section title + narrative |
| `link_card` | Card linking to another dashboard / runbook |
| `gauge` | Threshold gauge |
| `single_value_trend` | KPI + sparkline |
| `pie_or_donut` | Categorical share |
| `treemap` | Hierarchical share |
| `multi_metric_table` | Multi-column metric grid |
| `lookup_enrichment_table` | Joined with CTI / asset / identity data |

### B.5 Dashboard naming convention
```
DB.<family>.<scope_kind>.<scope_value>.<target>
```
Examples:
- `DB.tactic-deepdive.tactic.initial-access.splunk`
- `DB.technique-hunt.technique.T1059-001.elastic`
- `DB.actor-profile.actor.apt29.sentinel`
- `DB.coverage-gap.global.all.splunk`
- `DB.exec-overview.org.acme.splunk`

The id is deterministic. Regenerating the same id with the same data
snapshot produces a byte-identical artifact.

---

## Part C — How this enables "hundreds of dashboards"

### C.1 Bulk generation modes

| Mode | Input | Output count | Example |
|---|---|---|---|
| **Single** | one spec | 1 | "Initial Access for Splunk" |
| **Per-tactic** | one family + one target | 14 | 14 tactic deep-dive dashboards |
| **Per-technique** | family + target + scope=`all-techniques` | ~200 | one per technique |
| **Per-actor** | family + target | 100+ (MITRE Groups) | one per APT group |
| **Per-data-source** | family + target | ~20 | one per telemetry feed |
| **Matrix sweep** | `[families] × [targets]` | hundreds | full multi-SIEM rollout |
| **Curated pack** | named profile + target | variable | "Financial sector starter pack — Splunk" |

The generator exposes:
```
POST /api/dashboards/generate-bulk
{
  "family": "technique_hunt",
  "scope": { "kind": "per-technique", "filter": { "tactic": "Initial Access" } },
  "target": "splunk",
  "layout": "single_technique_deep",
  "options": { "save": true, "tag": "starter-pack-v1" }
}
```

### C.2 Curated dashboard packs

Pre-defined sets ThreatForge ships with. Each is a recipe: family + scope
filter + target list.

| Pack id | Contents |
|---|---|
| `pack.starter-windows` | Sysmon-centric Endpoint Threats + Tactic Deep-Dive (4 tactics) for each target |
| `pack.starter-linux` | auditd + osquery-centric Endpoint Threats |
| `pack.starter-cloud-aws` | CloudTrail-centric Cloud Posture + Identity Threats |
| `pack.starter-cloud-azure` | Sentinel-native pack |
| `pack.starter-m365` | Email / phishing + Identity Threats + Insider Threat |
| `pack.coverage-baseline` | Coverage Gap + Data Source Health for all 14 tactics |
| `pack.apt29-overview` | Actor Profile (APT29) + Technique Hunt for each APT29 TTP |
| `pack.ransomware-readiness` | Technique Hunt for `T1486`, `T1490`, `T1489`, `T1543`, `T1003`, ... |
| `pack.pci-dss` | Compliance + Coverage Gap mapped to PCI-DSS 10.x |
| `pack.industry-finance` | curated TTPs known to target finance |
| `pack.industry-healthcare` | curated TTPs known to target healthcare |

Packs are versioned YAML files under `configs/dashboard_packs/`:
```yaml
id: pack.starter-windows
name: Windows starter pack
version: 1.0.0
targets: [splunk, sentinel, elastic]
items:
  - family: endpoint-threats
    layout: by_data_source
    scope: { platform: windows, data_source: [sysmon, wineventlog-security] }
  - family: tactic-deepdive
    layout: kill_chain
    scope: { tactic: [Execution, Persistence, Defense Evasion, Credential Access] }
```

Generating a pack expands to N dashboards × M targets in one call.

### C.3 Inheritance and overrides

Every dashboard inherits from a chain:

```
SIEM-target defaults
  ← Family defaults
    ← Layout defaults
      ← Pack overrides
        ← User overrides (per-instance)
```

This means a panel's `time_range`, color palette, refresh interval, or
field-mapping override can be set once at the top and changed only where
needed. Without inheritance, hundreds of dashboards become hundreds of
divergent configs.

### C.4 Versioning

Every dashboard artifact carries:
- `threatforge_version`
- `pack_version` (if from a pack)
- `mitre_attack_version`
- `rule_snapshot_hash`
- `generated_at`
- `generator_signature`

So you can answer: "Which dashboards were generated against ATT&CK v15 vs.
v16? Which need regeneration after the latest rule sync?"

---

## Part D — Data model additions

These join the existing `repositories / raw_rules / normalized_rules /
converted_queries` model.

```
use_cases (
  id, technique_id, name, slug, description, status,
  parent_use_case_id, created_at, updated_at
)
use_case_facets (
  use_case_id, facet, value
)
use_case_rules (
  use_case_id, normalized_rule_id, role  -- 'primary' | 'variant' | 'reference'
)

dashboard_families (id, name, description, default_layout, audience)
dashboard_layouts (id, name, description, panel_template_set)
panel_kinds      (id, name, default_viz_config_json)

dashboards (
  id, name, slug, family_id, layout_id, target,
  scope_json, options_json, pack_id, pack_version,
  status, generated_at, generator_signature
)
dashboard_panels (
  id, dashboard_id, position, panel_kind, title,
  use_case_id, normalized_rule_id, viz_config_json,
  query_text, query_status
)

dashboard_packs (id, name, version, definition_yaml, applies_to_targets)
generation_jobs (
  id, kind, request_json, status, total, completed,
  artifact_dir, started_at, finished_at, error
)
```

`generation_jobs` is critical for bulk runs — generating 200 technique-hunt
dashboards across 7 targets is 1400 artifacts and must be tracked as one
job with progress reporting.

---

## Part E — Sample matrix of what "hundreds of dashboards" looks like

Assuming you adopt all five starter packs across three targets:

| Target | Tactic deep-dives | Technique hunts (top 60) | Actor profiles (top 20) | Coverage / health | **Total** |
|---|---|---|---|---|---|
| Splunk | 14 | 60 | 20 | 4 | **98** |
| Sentinel | 14 | 60 | 20 | 4 | **98** |
| Elastic | 14 | 60 | 20 | 4 | **98** |
| | | | | **Grand total** | **≈294** |

Add LogScale, OpenSearch, QRadar, Chronicle → easily 500+.

Add per-data-source health (5 per target × 7 targets) → +35.

Add 5 curated packs (≈25 dashboards each × 7 targets) → +875.

This is why bulk generation, inheritance, packs, and versioning are not
optional — they're what make the numbers stop being scary.

---

## Part F — Acceptance criteria

- A use case in the DB has exactly one position in the hierarchy and any
  number of facet values.
- Every dashboard has a deterministic id matching its naming convention.
- `POST /api/dashboards/generate-bulk` can produce ≥ 50 dashboards in one
  call, tracked under a single `generation_job`.
- At least three curated packs ship out of the box.
- The MITRE matrix page can roll up use-case counts by any facet (platform,
  data source, actor, industry, compliance).
- Coverage Gap dashboard for any target shows zero / low / medium / high
  coverage per technique against the chosen scope.
- Regenerating any dashboard with no upstream changes produces a
  byte-identical artifact.

---

## Part G — Sequencing

1. **Add the `use_cases` and `use_case_facets` tables** and backfill from
   existing `normalized_rules` (tactic + technique only, other facets later).
2. **Ship dashboard families + layouts + panel-kinds catalogs** as static
   YAML under `configs/dashboards/`.
3. **Implement Splunk Simple XML generator first** — most templates,
   fastest feedback.
4. **Add Sentinel Workbook generator**.
5. **Add Elastic NDJSON generator**.
6. **Add `POST /api/dashboards/generate-bulk` + `generation_jobs`**.
7. **Ship `pack.starter-windows` and `pack.coverage-baseline`** as proof.
8. **UI wizard surfaces packs first, custom builds second.**
9. **Add per-target generators** (LogScale, OpenSearch, QRadar, Chronicle).
10. **Add inheritance + override layer** once two generators exist.

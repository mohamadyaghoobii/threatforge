# Design: Generator V2 — Comprehensive Query Generator (Phase 1 — foundation)

## Strategic role
The query generator is the **load-bearing component** of ThreatForge.
Every use case ultimately resolves to a query; every dashboard panel is a
visualization wrapped around a query; every detection-rule export is a
query plus metadata. If the generator is shaky, everything built on top is
shaky.

**This document defines the V2 of the generator: production-grade,
exhaustive Sigma support, full per-SIEM profile + output-format coverage,
structured warnings, validation, bulk operation, and SIEM-native metadata
(schedules, throttles, notables, RBA, MITRE embedding).**

Use-case taxonomy (doc 04) and dashboard generator (doc 03) sit on top of
this. They consume the generator; they don't replace it.

---

## Why now (before use-cases / dashboards)

| Without Generator V2 | With Generator V2 |
|---|---|
| Each new dashboard panel finds new corner cases the converter can't handle | Panels just say "give me the query for use case X target Y profile Z format F" |
| String-based warnings can't drive UI / coverage analytics | Structured warnings let the UI show "this rule does not fit the chosen profile because field A is missing" with one-click suggested fixes |
| Field mapping only for `splunk_windows` → most rules degrade to generic syntax | Profile packs per product = real queries that work in production |
| Convert returns just a string | Convert returns query + schedule + throttle + entity mappings + MITRE metadata + risk score = ready to import |
| Bulk convert means N separate API calls and no progress | One job, progress, partial results, cache |
| `sigma-cli` subprocess for every rule = slow | pySigma in-process = ~50× faster |

---

## Current state (baseline)

- 7 targets, mostly **one** profile each.
- Field mapping: `splunk_windows.yml` only.
- Sigma modifier support: `contains`, `startswith`, `endswith`.
- Condition parsing: simple, `1 of selection*`, `all of selection*`, basic
  AND/OR with caveats (any complex condition emits a free-text warning).
- Output: **just the query string**. No schedule, no throttle, no entity
  mapping, no MITRE embedding, no notable, no RBA.
- No validation, no optimizer, no explainer.
- Conversion path: `sigma-cli` subprocess → fallback. No in-process pySigma.

---

## Coverage targets for V2

### 1. Full Sigma spec support
Implement every modifier and condition shape in the current Sigma spec.

| Sigma feature | Today | V2 |
|---|---|---|
| `contains`, `startswith`, `endswith` | ✅ | ✅ |
| `re` (regex) | ❌ | ✅ per-target syntax |
| `cased` (case-sensitive) | ❌ | ✅ |
| `base64`, `base64offset` | ❌ | ✅ (pre-encode) |
| `wide`, `utf16`, `utf16le`, `utf16be` | ❌ | ✅ |
| `windash` (`/` ↔ `-`) | ❌ | ✅ (expand variants) |
| `all` (every value in list must match) | ❌ | ✅ |
| `lt`, `lte`, `gt`, `gte` numeric | ❌ | ✅ |
| `expand` (placeholder) | ❌ | ✅ via lookup |
| `null` / `notexists` | ❌ | ✅ |
| Field-list values (mixed types) | partial | ✅ |
| Aggregation `count() by X > N` | ❌ | ✅ |
| Aggregation `sum/avg/min/max` | ❌ | ✅ |
| `near` operator (timeframe correlation) | ❌ | ✅ (per-SIEM where supported) |
| Selection wildcards: `1 of selection_*`, `all of *` | partial | ✅ |
| Negation `not selection` | ❌ | ✅ |
| Arbitrary boolean trees | weak | ✅ (real tokenizer + AST) |
| Correlation Sigma rules (type: correlation) | ❌ | ✅ |
| `timeframe` field on detection | ❌ | ✅ |
| `fields:` projection | ❌ | ✅ (where supported) |

### 2. Per-target profile + format matrix

#### Splunk
**Profiles (12):**
`splunk_sysmon`, `splunk_windows_security`, `splunk_powershell`,
`splunk_cim_endpoint`, `splunk_cim_network`, `splunk_cim_auth`,
`splunk_cim_web`, `splunk_cim_email`, `splunk_cim_change`,
`splunk_linux_syslog`, `splunk_aws_cloudtrail`, `splunk_azure_activity`,
`splunk_okta`, `splunk_o365`, `splunk_gws`, `splunk_palo_traffic`,
`splunk_zeek`.

**Output formats (6):**
- `spl` — bare SPL search
- `savedsearches_conf` — full `savedsearches.conf` stanza (schedule, suppression, notable, RBA, MITRE annotation)
- `datamodel_tstats` — `tstats` against CIM accelerated data models
- `ess_notable` — ES notable event creation parameters
- `risk_based_alert` — RBA-ready: risk object, threat object, risk score
- `dashboard_panel` — query + panel XML fragment

#### Microsoft Sentinel
**Profiles (10):**
`defender_xdr_device_process`, `defender_xdr_device_network`,
`defender_xdr_device_file`, `defender_xdr_device_registry`,
`defender_xdr_device_logon`, `defender_xdr_device_image_load`,
`defender_xdr_email`, `sentinel_security_event`, `sentinel_windows_event`,
`sentinel_syslog`, `sentinel_aad_signin`, `sentinel_audit`,
`sentinel_office_activity`, `sentinel_aws_cloudtrail`,
`sentinel_azure_activity`, `sentinel_gcp_audit`, `sentinel_okta`.

**Output formats (4):**
- `kql` — bare KQL
- `analytic_rule_arm` — `Microsoft.SecurityInsights/alertRules` ARM template (schedule, threshold, tactics, techniques, entity mappings, incident config, alert details override)
- `hunting_query_yaml` — Sentinel hunting query YAML
- `workbook_panel` — workbook tile JSON

#### Elastic
**Profiles (8):**
`ecs_windows_sysmon`, `ecs_windows_security`, `ecs_linux_auditbeat`,
`ecs_endpoint_security`, `ecs_cloud_aws`, `ecs_cloud_azure`,
`ecs_cloud_gcp`, `ecs_network_zeek`, `ecs_okta`.

**Output formats (5):**
- `kql` — Kibana Query Language
- `eql` — Event Query Language (better for sequences)
- `lucene` — Lucene query string
- `esql` — Elastic ES|QL
- `detection_rule_ndjson` — Kibana Security detection rule (one NDJSON line with risk score, severity, threat mapping, interval, indices, exceptions hooks, RBA)

#### OpenSearch
**Profiles (2):** `opensearch_ecs`, `opensearch_wazuh`.
**Output formats (3):** `kql`, `dsl`, `detection_rule_ndjson`.

#### QRadar
**Profiles (5):** `qradar_windows_dsm`, `qradar_linux_dsm`,
`qradar_palo_dsm`, `qradar_cloud_dsm`, `qradar_okta_dsm`.
**Output formats (4):**
- `aql` — Ariel Query Language
- `custom_rule_xml` — full custom rule with tests + dispatch_offense action
- `building_block_xml` — reusable building block
- `ariel_search_json` — saved search payload

#### Google Chronicle
**Profiles (5):** `udm_windows`, `udm_linux`, `udm_cloud_gcp`,
`udm_cloud_aws`, `udm_okta`.
**Output formats (3):**
- `udm_search` — UDM Search query
- `yara_l_rule` — YARA-L 2.0 detection rule with `meta`, `events`,
  `condition`, severity, MITRE technique meta
- `retrohunt_payload` — Retrohunt JSON

#### CrowdStrike LogScale (Humio)
**Profiles (6):** `falcon_insight`, `sysmon_ecs`, `linux_syslog`,
`aws_cloudtrail`, `azure_activity`, `okta`.
**Output formats (3):**
- `query` — search query
- `alert_yaml` — alert with throttle and notifiers
- `dashboard_widget` — widget JSON

#### Sumo Logic
**Profiles (3):** `cse_windows`, `cse_linux`, `cse_cloud_aws`.
**Output formats (2):** `query`, `cse_rule_yaml`.

#### Devo
**Profiles (2):** `devo_windows`, `devo_linux`.
**Output formats (2):** `linq`, `alert_definition_json`.

#### Wazuh / OpenSearch SIEM
**Profiles (2):** `wazuh_rule_xml`, `opensearch_security_analytics`.
**Output formats (2):** `wazuh_rule_xml`, `detection_rule_ndjson`.

#### Grand total
- **~70 unique (target, profile) pairs**
- **~30 output formats across targets**
- Cross-product surface: hundreds of valid combinations the API must serve.

### 3. SIEM-native metadata

Every output format that supports it gets:

| Field | Source |
|---|---|
| Title | Rule title |
| Description | Rule description |
| Severity | Rule level, mapped per target (`high` → Splunk 4, Sentinel `High`, Elastic risk 73, QRadar 7, Chronicle `High`, LogScale `4`) |
| Schedule / interval | Profile default, override per format |
| Time window | Profile default, override |
| Throttling / suppression | Profile default with sensible field choice (`host`, `user`, `aid`) |
| Entity mappings | Auto-inferred from logsource (host=ComputerName, user=TargetUserName, process=Image) |
| MITRE annotations | `tactics`, `techniques`, `sub_techniques`; pulled from normalized rule |
| Risk score | Computed from severity + confidence + asset criticality (default) |
| Incident creation | Enabled by default for critical/high; configurable |
| References | Rule references + ATT&CK URLs |
| Tags / labels | Standard set: `threatforge`, technique id, tactic, source repo |
| MITRE data sources | From STIX enrichment (doc 02) |

### 4. Structured warnings (catalog)

Warnings are objects, not strings. Stable codes, machine-readable.

| Code | Severity | Meaning |
|---|---|---|
| `FIELD_NOT_IN_PROFILE` | warning | A Sigma field doesn't exist in the chosen profile's field map |
| `FIELD_FALLBACK_USED` | info | Generic field name used because no mapping was found |
| `MODIFIER_NOT_SUPPORTED` | warning | Modifier (`base64offset`, `cidr`, etc.) is not natively expressible in target; emulated |
| `MODIFIER_EMULATED_LOSSY` | warning | Emulation is best-effort; review (e.g., `base64offset` → 3 candidate strings) |
| `CONDITION_AMBIGUOUS` | warning | Boolean condition has mixed operators without parens; default precedence was applied |
| `AGGREGATION_NOT_SUPPORTED` | warning | Target doesn't support aggregation in this format (e.g., realtime KQL inline) |
| `TIMEFRAME_REQUIRED_BUT_MISSING` | warning | Rule uses correlation but no `timeframe`; default applied |
| `BASE_SELECTOR_GUESSED` | info | logsource category/service was unknown; generic base index used |
| `INDEX_FALLBACK_USED` | warning | Profile lacks index hint for category; `index=main` used |
| `LICENSE_RESTRICTION` | error | Source rule license prohibits redistribution in this output format |
| `EMPTY_DETECTION` | error | Detection has no selections; cannot produce a query |
| `UNMAPPED_TARGET` | warning | Target id was unknown; mapped to closest equivalent |
| `BACKEND_UNAVAILABLE` | info | pySigma backend not installed; built-in fallback used |
| `OPTIMIZER_REWRITE` | info | Query was rewritten for performance (e.g., predicate pushdown) |
| `ENTITY_MAPPING_INCOMPLETE` | warning | Could only infer some entities from logsource (e.g., host but not process) |
| `RBA_REQUIRES_FIELD` | warning | Risk-based alert format needs a field (`risk_object`) the rule doesn't produce |
| `MITRE_TAG_INVALID` | warning | A tag like `attack.t1059` couldn't be resolved against the STIX bundle |

The full catalog ships as JSON at `/api/generator/warning-codes` and is referenced in UI tooltips.

### 5. Validation

Two modes:

**Offline lint** (default, no network):
- Splunk: SPL tokenizer (closed parens, valid pipe commands, valid eval funcs)
- KQL: lark-based KQL grammar check
- KuQL / Lucene: similar
- AQL: tokenizer
- YARA-L: parser

**Live validate** (opt-in, env-gated):
- Splunk: `POST /services/parser?parse_only=1` against `SPLUNK_URL` + `SPLUNK_TOKEN`
- Sentinel: ARM template what-if via `AZURE_*` env
- Elastic: `POST _validate/query?rewrite=true` against `ELASTIC_URL` + key
- QRadar: dry-run AQL via API
- LogScale: `dryRun=true`
- Chronicle: best-effort regex lint
Returns: `{ ok, errors[], warnings[], elapsed_ms }`.

### 6. Bulk operation

```
POST /api/generator/convert-bulk
{
  "rule_ids": [1,2,3, ...100],
  "targets": ["splunk", "sentinel", "elastic"],
  "profiles_per_target": {"splunk": "splunk_sysmon", "sentinel": "defender_xdr_device_process", "elastic": "ecs_windows_sysmon"},
  "output_formats_per_target": {"splunk": ["savedsearches_conf"], "sentinel": ["analytic_rule_arm"], "elastic": ["detection_rule_ndjson"]},
  "options": {"cache": true, "parallel": 8}
}
```

Backed by the same `generation_jobs` table introduced in doc 04. Returns
job id, polled via `GET /api/jobs/{id}` for progress.

### 7. Cache

Key:
```
sha256(rule_raw_hash || target || profile || output_format || pysigma_pipeline_version || generator_version || mitre_attack_version)
```
Hit → instant. Miss → convert, store, return. Invalidated when any
component of the key changes.

### 8. Explainer + optimizer + round-trip

- `POST /api/generator/explain` → returns plain English: "Search for
  Sysmon process-creation events where `Image` ends with `powershell.exe`
  and `CommandLine` contains `-enc`; suppress per `host` for 1 hour.
  Maps to ATT&CK T1059.001 (PowerShell). Risk score 60. Notable created."
- `POST /api/generator/optimize` → rewrites:
  - hoist common predicate (`Image=*powershell.exe`) above OR'd selections
  - push base-selector predicates earlier
  - merge adjacent `OR` clauses on same field into `IN (...)`
  - rewrite `field=*x*` to `field=*x` if regex anchors allow
- `POST /api/generator/round-trip` → parses the generated query back to a
  pseudo-Sigma AST and diffs; flags semantic loss.

---

## Architecture

```
apps/api/app/services/generator/
  __init__.py
  engine.py                    # Orchestrator: pick backend, run pipeline, fallback, cache
  backends/
    pysigma_runtime.py         # In-process pySigma backend
    sigma_cli_runtime.py       # Subprocess
    builtin_fallback.py        # The current converters.py rewritten with full modifier support
  pipelines/                   # YAML processing pipelines (pySigma compatible)
    sysmon.yml
    splunk_sysmon.yml
    splunk_cim.yml
    splunk_windows_security.yml
    sentinel_defender_device_process.yml
    sentinel_security_event.yml
    elastic_ecs_windows.yml
    elastic_ecs_linux.yml
    elastic_ecs_cloud_aws.yml
    qradar_windows.yml
    chronicle_udm_windows.yml
    logscale_falcon.yml
    ... (one per profile)
  formats/
    splunk/
      spl.py
      savedsearches_conf.py
      datamodel_tstats.py
      ess_notable.py
      risk_based_alert.py
      dashboard_panel.py
    sentinel/
      kql.py
      analytic_rule_arm.py
      hunting_query_yaml.py
      workbook_panel.py
    elastic/
      kql.py
      eql.py
      lucene.py
      esql.py
      detection_rule_ndjson.py
    opensearch/
      kql.py
      dsl.py
      detection_rule_ndjson.py
    qradar/
      aql.py
      custom_rule_xml.py
      building_block_xml.py
      ariel_search_json.py
    chronicle/
      udm_search.py
      yara_l.py
      retrohunt.py
    logscale/
      query.py
      alert_yaml.py
      dashboard_widget.py
    sumologic/
      query.py
      cse_rule_yaml.py
    devo/
      linq.py
      alert_definition_json.py
    wazuh/
      rule_xml.py
  templates/                   # Jinja2 templates for non-query content
    splunk/
      savedsearches.conf.j2
      ess_notable.j2
      rba.j2
    sentinel/
      analytic_rule.arm.json.j2
      hunting_query.yaml.j2
    elastic/
      detection_rule.ndjson.j2
    qradar/
      custom_rule.xml.j2
      building_block.xml.j2
    chronicle/
      yara_l.yaral.j2
    logscale/
      alert.yaml.j2
  validators/
    splunk.py
    sentinel.py
    elastic.py
    qradar.py
    chronicle.py
    logscale.py
  warnings.py                  # Code catalog + builder
  bulk.py                      # Multi-rule, multi-target orchestrator
  cache.py                     # Conversion cache (Postgres-backed table + LRU memory)
  explain.py                   # Plain-English explainer
  optimize.py                  # Rewrites + simplifications
  roundtrip.py                 # Parse generated query back to AST
  metadata.py                  # Entity inference, MITRE embedding, RBA scoring, severity mapping
```

### Profile YAML spec

```yaml
# configs/generator/profiles/splunk/sysmon.yml
id: splunk_sysmon
target: splunk
name: Splunk Sysmon
audience: SOC / Endpoint
description: Sysmon shipped to index=sysmon as XmlWinEventLog
base:
  index: sysmon
  sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
default_event_code_by_category:
  process_creation: 1
  network_connection: 3
  image_load: 7
  file_event: 11
  registry_event: 12
  dns_query: 22
field_mapping_pack: splunk_sysmon_fields
pysigma_pipeline: pipelines/splunk_sysmon.yml
processing:
  - rewrite_event_id_to_eventcode
  - case_insensitive_strings
  - add_sysmon_sourcetype_filter
output_defaults:
  spl:
    leading_filter: "index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
  savedsearches_conf:
    cron_schedule: "*/15 * * * *"
    dispatch.earliest_time: "-15m"
    suppression:
      enabled: true
      fields: ["host"]
      period: "1h"
    notable:
      enabled: true
      security_domain: endpoint
    rba:
      enabled: true
      risk_object_field: user
      risk_object_type: user
      threat_object_field: process_name
      threat_object_type: process
      base_score: 40
severity_map:
  critical: 5
  high: 4
  medium: 3
  low: 2
  informational: 1
entity_inference:
  host: ComputerName
  user: User
  process: Image
  parent_process: ParentImage
mitre_metadata_strategy: ess_correlation_annotation
```

### Field mapping YAML spec

```yaml
# configs/generator/field_mappings/splunk_sysmon_fields.yml
id: splunk_sysmon_fields
target: splunk
mappings:
  EventID: EventCode
  event_id: EventCode
  Image: Image
  CommandLine: CommandLine
  ParentImage: ParentImage
  ParentCommandLine: ParentCommandLine
  User: User
  TargetUserName: TargetUserName
  ComputerName: host
  UtcTime: _time
  ProcessGuid: ProcessGuid
  IntegrityLevel: IntegrityLevel
  Hashes: Hashes
  TargetFilename: TargetFilename
  DestinationIp: DestinationIp
  DestinationPort: DestinationPort
  SourceIp: SourceIp
  SourcePort: SourcePort
unknown_field_policy: pass_through_with_warning
```

---

## New endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/generator/targets` | Full target catalog (target × profiles × formats × support level) |
| `GET` | `/api/generator/profiles?target=splunk` | Profile list for a target |
| `GET` | `/api/generator/profiles/{id}` | Profile detail (YAML resolved + inheritance applied) |
| `GET` | `/api/generator/pipelines` | Available pySigma pipelines |
| `GET` | `/api/generator/warning-codes` | Full warning catalog |
| `POST` | `/api/generator/convert` | Single rule → query (structured) |
| `POST` | `/api/generator/convert-bulk` | Many rules × many (target, profile, format) → many queries; async job |
| `POST` | `/api/generator/preview` | Same as convert but no persistence |
| `POST` | `/api/generator/validate` | Validate a query (offline lint or live) |
| `POST` | `/api/generator/explain` | Plain-English explanation |
| `POST` | `/api/generator/optimize` | Optimized rewrite |
| `POST` | `/api/generator/round-trip` | Parse generated query back; report semantic diff |
| `GET` | `/api/generator/cache-stats` | Hits, misses, size |
| `DELETE` | `/api/generator/cache` | Invalidate (with filters) |

---

## Data model additions

```
generator_profiles (
  id, target, name, version, source_yaml_hash, definition_json,
  inheritance_chain_json, created_at, updated_at
)
generator_field_mappings (
  id, target, name, version, definition_json
)
generator_pipelines (
  id, target, name, pysigma_version, definition_yaml
)
conversion_cache (
  cache_key, rule_id, target, profile, output_format,
  pipeline_version, generator_version, mitre_version,
  query_text, warnings_json, metadata_json, body_size_bytes,
  hit_count, last_used_at, created_at
)
validation_runs (
  id, conversion_id, mode (offline|live), target,
  ok, errors_json, warnings_json, elapsed_ms, created_at
)
```

Extend `converted_queries` with:
- `output_format` (already exists)
- `warnings_json` (structured, replacing `warnings`)
- `metadata_json` (schedule, throttle, entity mappings, MITRE, RBA)
- `generator_signature` (which backend + pipeline + version did this)
- `cache_key`

---

## Output examples

### Splunk savedsearches.conf (output_format: `savedsearches_conf`)

```ini
[ThreatForge - T1059.001 PowerShell Encoded Cradle]
description = Detects PowerShell processes launched with -EncodedCommand passing a base64 payload.
search = index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe") (CommandLine="*-enc *" OR CommandLine="*-EncodedCommand *")
disabled = 0
cron_schedule = */15 * * * *
dispatch.earliest_time = -15m
dispatch.latest_time = now
is_scheduled = 1
realtime_schedule = 0
alert.suppress = 1
alert.suppress.fields = host,user
alert.suppress.period = 1h
action.notable = 1
action.notable.param.security_domain = endpoint
action.notable.param.severity = high
action.notable.param.rule_title = T1059.001 PowerShell Encoded Cradle
action.notable.param.rule_description = ...
action.notable.param.drilldown_search = index=sysmon EventCode=1 host="$host$" user="$user$" earliest=-30m
action.risk = 1
action.risk.param._risk_score = 60
action.risk.param._risk_object = user
action.risk.param._risk_object_type = user
action.risk.param.threat_object_field = Image
action.risk.param.threat_object_type = process
action.correlationsearch.enabled = 1
action.correlationsearch.label = ThreatForge - T1059.001 PowerShell Encoded Cradle
action.correlationsearch.annotations = {"mitre_attack":["T1059.001"], "kill_chain_phases":["execution"]}
```

### Sentinel Analytic Rule (output_format: `analytic_rule_arm`)

```json
{
  "type": "Microsoft.SecurityInsights/alertRules",
  "apiVersion": "2023-12-01-preview",
  "kind": "Scheduled",
  "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/','threatforge-t1059-001')]",
  "properties": {
    "displayName": "ThreatForge - T1059.001 PowerShell Encoded Cradle",
    "description": "Detects PowerShell processes launched with -EncodedCommand ...",
    "severity": "High",
    "enabled": true,
    "query": "DeviceProcessEvents | where FileName in~ ('powershell.exe','pwsh.exe') | where ProcessCommandLine has_any('-enc ','-EncodedCommand ')",
    "queryFrequency": "PT15M",
    "queryPeriod": "PT15M",
    "triggerOperator": "GreaterThan",
    "triggerThreshold": 0,
    "suppressionDuration": "PT1H",
    "suppressionEnabled": true,
    "tactics": ["Execution"],
    "techniques": ["T1059"],
    "subTechniques": ["T1059.001"],
    "entityMappings": [
      {"entityType": "Account", "fieldMappings": [{"identifier": "Name", "columnName": "AccountName"}]},
      {"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "DeviceName"}]},
      {"entityType": "Process", "fieldMappings": [{"identifier": "CommandLine", "columnName": "ProcessCommandLine"}]}
    ],
    "incidentConfiguration": {
      "createIncident": true,
      "groupingConfiguration": {
        "enabled": true,
        "reopenClosedIncident": false,
        "lookbackDuration": "PT5H",
        "matchingMethod": "AllEntities"
      }
    },
    "alertDetailsOverride": {
      "alertDisplayNameFormat": "Encoded PowerShell from {{AccountName}} on {{DeviceName}}",
      "alertDescriptionFormat": "Suspicious encoded PowerShell observed on {{DeviceName}}"
    },
    "customDetails": {"Technique": "T1059.001"}
  }
}
```

### Elastic Detection Rule (output_format: `detection_rule_ndjson`)

```json
{"type":"query","language":"kuery","query":"process.name : (\"powershell.exe\" or \"pwsh.exe\") and process.command_line : (*-enc* or *-EncodedCommand*)","name":"ThreatForge - T1059.001 PowerShell Encoded Cradle","description":"...","risk_score":73,"severity":"high","interval":"5m","from":"now-9m","to":"now","index":["winlogbeat-*","logs-windows.*","logs-endpoint.events.process-*"],"enabled":true,"tags":["ThreatForge","Tactic:Execution","T1059","T1059.001"],"threat":[{"framework":"MITRE ATT&CK","tactic":{"id":"TA0002","name":"Execution","reference":"https://attack.mitre.org/tactics/TA0002/"},"technique":[{"id":"T1059","name":"Command and Scripting Interpreter","reference":"https://attack.mitre.org/techniques/T1059/","subtechnique":[{"id":"T1059.001","name":"PowerShell","reference":"https://attack.mitre.org/techniques/T1059/001/"}]}]}],"max_signals":100,"rule_id":"tf-t1059-001-encoded-cradle","license":"Elastic License v2","exceptions_list":[],"actions":[]}
```

### Chronicle YARA-L (output_format: `yara_l_rule`)

```yaral
rule t1059_001_powershell_encoded_cradle {
  meta:
    author = "ThreatForge"
    description = "Encoded PowerShell command line"
    severity = "High"
    mitre_attack_tactic = "Execution"
    mitre_attack_technique = "T1059.001"
    reference = "https://attack.mitre.org/techniques/T1059/001/"

  events:
    $e.metadata.event_type = "PROCESS_LAUNCH"
    $e.target.process.file.full_path = /.*\\(powershell|pwsh)\.exe$/ nocase
    re.regex($e.target.process.command_line, `(?i)(-enc(odedcommand)?\s+)`)

  condition:
    $e
}
```

### LogScale alert (output_format: `alert_yaml`)

```yaml
name: ThreatForge - T1059.001 PowerShell Encoded Cradle
description: Encoded PowerShell command line via -enc / -EncodedCommand
query: '#repo=falcon event_simpleName=ProcessRollup2 (FileName="powershell.exe" OR FileName="pwsh.exe") CommandLine=/-(enc|EncodedCommand)/i'
queryStart: -15m
throttleField: aid
throttleTimeMillis: 3600000
notifierIds: ['default-email']
labels:
  - ThreatForge
  - T1059.001
  - Execution
severity: HIGH
```

### QRadar custom rule (output_format: `custom_rule_xml`)

```xml
<rule>
  <name>ThreatForge - T1059.001 PowerShell Encoded Cradle</name>
  <severity>7</severity>
  <category>Anomaly</category>
  <enabled>true</enabled>
  <tests>
    <test type="EventName" op="equals">Process Create</test>
    <test type="Custom" op="ilike">"Process Path" ILIKE '%\\powershell.exe' OR "Process Path" ILIKE '%\\pwsh.exe'</test>
    <test type="Custom" op="ilike">"Command" ILIKE '%-enc%' OR "Command" ILIKE '%-EncodedCommand%'</test>
  </tests>
  <actions>
    <action type="dispatch_offense">
      <field name="offense_indexer">SourceIp</field>
      <field name="annotate">T1059.001</field>
    </action>
  </actions>
</rule>
```

---

## Sequencing (~14 working days for full V2 generator)

| Phase | Days | Deliverable |
|---|---|---|
| **G1** | 1.5 | Refactor: extract generator service, structured warnings, warning code catalog, JSON output, profile YAML loader, endpoint scaffolding |
| **G2** | 2 | Built-in fallback covers full Sigma modifier set (`re`, `cased`, `base64`, `base64offset`, `wide`, `windash`, `all`, `lt/lte/gt/gte`, `null`, `notexists`, list values, negation, complex condition AST) + tests |
| **G3** | 1.5 | In-process pySigma backend selection + per-target pipeline files; fallback chain |
| **G4** | 2 | Splunk profile pack (12 profiles) + field mapping packs + 6 output formats (spl, savedsearches.conf, datamodel_tstats, ess_notable, risk_based_alert, dashboard_panel) + Jinja2 templates |
| **G5** | 2 | Sentinel profile pack (10 profiles) + 4 output formats (kql, analytic_rule_arm, hunting_query_yaml, workbook_panel) |
| **G6** | 2 | Elastic + OpenSearch profile packs + formats (kql, eql, lucene, esql, detection_rule_ndjson, dsl) |
| **G7** | 1.5 | QRadar + Chronicle + LogScale + Sumo Logic + Devo + Wazuh formats |
| **G8** | 1 | Validators (offline lint per target; live validate behind env flags) |
| **G9** | 1 | Bulk endpoint + `generation_jobs` + cache + progress |
| **G10** | 1 | Explainer + optimizer + round-trip + entity inference + MITRE embedding + RBA |
| **G11** | 1 | Golden file tests per (target, profile, format) — at least 10 representative Sigma rules |

After G11 the generator is production-grade and the rest of the system
(use cases, dashboards, actor profiles, packs) can be built **as thin
layers on top** rather than rebuilding query plumbing per feature.

---

## Acceptance

- Every Sigma modifier in the v2 spec produces a working query in at
  least Splunk, Sentinel, and Elastic (golden tests prove it).
- `GET /api/generator/targets` returns ≥ 7 targets, ≥ 50 (target, profile)
  pairs, ≥ 25 output formats.
- A rule with no field-mapping warnings imports cleanly into Splunk
  (savedsearches.conf), Sentinel (ARM deploy), and Elastic (Kibana
  detection rules import).
- Bulk convert of 100 rules × 3 targets completes in under 30 seconds
  cold (no cache), under 5 seconds warm.
- Warnings always carry a code from the catalog; UI can render code +
  message + suggestion.
- Offline lint catches malformed SPL / KQL / KQL-EQL / AQL with > 95% recall
  on a corpus of 200 broken queries.
- Round-trip preserves semantics for ≥ 80% of selection-only rules.

---

## How this unblocks use cases + dashboards

After G11:

- **Use cases (doc 04)** become a thin facet/grouping layer over normalized
  rules + cached conversions. Per technique × target × profile = N
  pre-rendered queries.
- **Dashboards (doc 03)** become Jinja2 layouts that pull queries from
  cache and inject them into panel templates. No per-panel generator
  logic needed.
- **Curated packs** become YAML manifests that reference (use_case_id,
  target, profile, format) tuples; bulk-generate hits cache and is
  near-instant on re-export.
- **Coverage analytics** ask the warnings catalog (e.g., "how many use
  cases emit `FIELD_NOT_IN_PROFILE` for `splunk_cim_endpoint`?") —
  trivially computed from existing data.

---

## Out of scope for V2 generator

- ML-based detection translation (e.g., emitting Splunk MLTK searches)
- Realtime stream backends (Flink / Spark SQL)
- Sigma correlation rules with complex multi-source joins (only single-source `near` + `count` covered)
- Per-tenant scoring overrides (Phase 2)
- Human-in-the-loop tuning feedback loop (Phase 2)

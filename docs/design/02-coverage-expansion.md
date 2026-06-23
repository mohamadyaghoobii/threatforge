# Design: Coverage Expansion (Phase 1B)

## Goal
Wider rule sources, real MITRE enrichment, multi-parser support, and canonical
use-case dedup. This is what turns the MVP into a credible threat-intel surface.

## Current state
- 4 external repos + 1 local pack (configs/sources/repositories.yml).
- Parser only handles Sigma-shaped YAML (packages/rule_engine/parser.py).
- MITRE enrichment is tag-string only: `attack.tXXXX` → technique id, `attack.<tactic>` → tactic name.
  No technique name / description / data sources resolved.
- No dedup across repos — `_extract_selections` is by `raw_hash`, so the same
  rule from two forks shows up twice.

## New repositories to add

| Source                                         | Format               | License            |
|------------------------------------------------|----------------------|--------------------|
| Elastic/detection-rules                        | TOML                 | Elastic License v2 |
| splunk/security_content (ESCU)                 | YAML (Splunk schema) | Apache-2.0         |
| MITRE/cti (enterprise-attack STIX bundle)      | STIX 2.1 JSON        | Apache-2.0         |
| redcanaryco/atomic-red-team                    | YAML (atomic tests)  | MIT                |
| FalconForceTeam/FalconFriday                   | Markdown + KQL       | Apache-2.0         |
| Azure/Azure-Sentinel (Detections)              | YAML                 | MIT                |
| Neo23x0/signature-base (YARA + Sigma)          | YARA + YAML          | CC-BY-NC-4.0       |
| chainsaw rules (WithSecureLabs/chainsaw)       | YAML                 | GPL-3.0            |

Atomic Red Team and CTI bundle aren't detections per se but make use cases
richer — they let us answer "what's the detection coverage for technique
TXXXX given the known procedures?".

## Parser additions
- `parsers/sigma.py`     — existing, refactor out of `parser.py`.
- `parsers/hayabusa.py`  — already imported as Sigma-shaped, formalize.
- `parsers/elastic_toml.py` — read TOML, map `rule.threat[].technique[]` to
  MITRE ids.
- `parsers/splunk_escu.py` — YAML with `mitre_attack`, `data_source`, `search`.
- `parsers/atomic.py`    — atomic tests; produce procedure entries, not detections.

Each parser returns the same internal `ParsedRule` model (already in
`detectionforge_rule_engine/models.py`).

## MITRE STIX enrichment

### Pipeline
1. New service `mitre_loader.py` downloads
   `enterprise-attack.json` from MITRE/cti and caches under `data/cache/mitre/`.
2. On API boot (or on demand via `POST /api/mitre/refresh`), load the bundle
   into a new SQLite/Postgres tables:

```
mitre_techniques(id, name, description, is_subtechnique, parent_id, url,
                 platforms_json, data_sources_json, kill_chain_phases_json,
                 detection_text, mitigations_json, version, modified)
mitre_tactics(short_name, name, description, url)
mitre_groups(id, name, aliases_json, description, techniques_json)
mitre_software(id, type, name, aliases_json, platforms_json,
               techniques_json, description)
mitre_data_components(id, name, description, data_source_id)
```

3. Backfill: for every NormalizedRule, on import, resolve each technique id
   against the table and store a denormalized `technique_name` cache column
   on `normalized_rules`.

### API additions
```
GET  /api/mitre/techniques/{id}          # full technique detail
GET  /api/mitre/tactics/{short_name}     # tactic detail + techniques
GET  /api/mitre/groups                   # threat actors
GET  /api/mitre/groups/{id}              # actor → techniques → use cases
GET  /api/mitre/software                 # malware / tool catalog
POST /api/mitre/refresh                  # re-pull bundle
```

### UI uplift
- `/matrix` now uses real technique names.
- Use case header shows technique name + ATT&CK description.
- New `/actors` page (Phase 2 surfaces it; Phase 1B just ships the data).

## Canonical use case dedup

### Problem
Same technique can have variants from SigmaHQ, mdecrevoisier, and P4T12ICK
that are functionally identical (forks). They all appear as separate rules.

### Approach
Add a `canonical_signature` column to `normalized_rules`:

```
signature = sha1(
  technique_id_sorted ||
  logsource.product || logsource.service || logsource.category ||
  hash(detection_selections_minus_metadata)
)
```

Use cases then expose:
- `rule_count`  — raw variants
- `unique_count` — distinct canonical signatures

Variants with the same signature collapse to a "rule cluster" in the UI,
with one selected as "preferred" by quality score.

## Multi-product field mappings
Today only `configs/field_mappings/splunk_windows.yml` exists. Add:
- `splunk_cim.yml` (CIM-compliant fields)
- `sentinel_defender.yml`
- `elastic_ecs.yml`
- `chronicle_udm.yml`
- `qradar_qid_map.yml`
- `logscale_falcon.yml`

Editable in `/settings` later.

## Effort estimate
- New parsers (Elastic TOML, Splunk ESCU): 1.5 days
- MITRE STIX loader + tables + endpoints: 1.5 days
- Canonical dedup + signature: 1 day
- Field mapping packs: 0.5 day
- Add new repos to config + license review: 0.5 day

Total: ~5 days.

## Acceptance
- `GET /api/mitre/techniques/T1059` returns the real name "Command and
  Scripting Interpreter" with data sources and detection text.
- Use case page shows technique name, not the bare id.
- Two forked SigmaHQ rules of the same content collapse to one cluster.
- At least one rule successfully imported from each new repo.

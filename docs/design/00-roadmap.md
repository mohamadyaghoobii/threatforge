# ThreatForge V2 — Roadmap

Five design docs cover the V2 expansion. **The generator is the
foundation; everything else is built on top of it.**

1. [05-generator-v2.md](05-generator-v2.md) — **Phase 1, the foundation.**
   Production-grade query generator: full Sigma spec, ~70 (target, profile)
   pairs across Splunk, Sentinel, Elastic, OpenSearch, QRadar, Chronicle,
   LogScale, Sumo Logic, Devo, Wazuh; ~30 output formats with SIEM-native
   metadata (schedules, throttles, notables, RBA, MITRE embedding);
   structured warnings; offline + live validation; bulk + cache;
   explainer + optimizer + round-trip.
2. [02-coverage-expansion.md](02-coverage-expansion.md) — More rule
   repositories, multi-parser (Elastic TOML, Splunk ESCU, Atomic Red
   Team), full MITRE STIX enrichment, canonical use-case dedup.
3. [01-ui-modernization.md](01-ui-modernization.md) — Tailwind + shadcn
   shell, real MITRE matrix, command palette, type-safe API client.
4. [04-taxonomy.md](04-taxonomy.md) — Classification system that lets
   ThreatForge scale to hundreds of dashboards and thousands of use
   cases: use-case hierarchy + facets, dashboard families, layouts,
   panel kinds, per-SIEM artifact formats, curated packs, bulk
   generation, inheritance, versioning.
5. [03-dashboard-generator.md](03-dashboard-generator.md) — Wizard that
   produces ready-to-import dashboards (Splunk XML, Sentinel Workbook,
   Elastic Kibana NDJSON) from a chosen use-case scope. Now a thin
   layout layer on top of the V2 generator.

## Strategy

**Build the generator first. Make it exhaustive. Then everything else
becomes a thin layer.**

```
                      ┌───────────────────────────────────────┐
                      │  Generator V2 (foundation, doc 05)    │
                      │  full Sigma, ~70 profiles, ~30 formats│
                      └───────────────┬───────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
┌────────────────┐         ┌────────────────────┐         ┌────────────────────┐
│ Coverage +     │         │ Use case taxonomy  │         │ UI modernization   │
│ MITRE STIX     │         │ + facets (doc 04)  │         │ + matrix (doc 01)  │
│ (doc 02)       │         └────────┬───────────┘         └────────────────────┘
└────────────────┘                  │
                                    ▼
                          ┌────────────────────┐
                          │ Dashboard wizard + │
                          │ curated packs      │
                          │ (doc 03)           │
                          └────────────────────┘
```

## Sequencing

### Phase 1 — Generator V2 (~14 working days)
This is the load-bearing work. Do not skip phases.

| Step | Days | Deliverable |
|---|---|---|
| G1 | 1.5 | Refactor: generator service, structured warnings + catalog, profile YAML loader, endpoint scaffolding |
| G2 | 2 | Built-in fallback covers full Sigma modifier set (`re`, `cased`, `base64`, `base64offset`, `wide`, `windash`, `all`, `lt/lte/gt/gte`, `null`, `notexists`, negation, complex condition AST) |
| G3 | 1.5 | In-process pySigma backend selection + pipeline files; fallback chain |
| G4 | 2 | Splunk profile pack (12 profiles) + 6 output formats including `savedsearches.conf` with notable + RBA |
| G5 | 2 | Sentinel profile pack (10 profiles) + analytic_rule_arm + hunting_query_yaml |
| G6 | 2 | Elastic + OpenSearch profile packs + KQL/EQL/Lucene/ES\|QL/detection_rule_ndjson |
| G7 | 1.5 | QRadar + Chronicle + LogScale + Sumo Logic + Devo + Wazuh formats |
| G8 | 1 | Validators (offline lint + live validate behind env flags) |
| G9 | 1 | Bulk endpoint + `generation_jobs` + cache + progress |
| G10 | 1 | Explainer + optimizer + round-trip + entity inference + MITRE embedding + RBA |
| G11 | 1 | Golden file tests per (target, profile, format) |

### Phase 2 — Coverage + Use cases + UI (in parallel, ~7 days)

| Step | Days | Deliverable |
|---|---|---|
| C1 | 1.5 | MITRE STIX loader + tables; technique name/description backfill |
| C2 | 1   | `use_cases` + `use_case_facets` tables; backfill from normalized rules |
| C3 | 1.5 | New parsers (Elastic TOML, Splunk ESCU) + new repos enabled |
| C4 | 1   | Canonical dedup + rule clusters |
| U1 | 1   | Tailwind + shadcn shell + dark theme |
| U2 | 1.5 | Real MITRE matrix heatmap + use-case detail page |
| U3 | 1   | Command palette + type-safe API client |

### Phase 3 — Dashboards (~6 days)

| Step | Days | Deliverable |
|---|---|---|
| D1 | 1   | Dashboard families + layouts + panel-kinds catalogs (YAML) |
| D2 | 2   | Splunk Simple XML + Studio JSON generator; renders from cached queries |
| D3 | 1.5 | Sentinel Workbook generator |
| D4 | 1.5 | Elastic NDJSON dashboard generator |
| D5 | 1   | Bulk generation + curated packs (starter-windows, coverage-baseline, ransomware-readiness) |
| D6 | 1   | Wizard UI (scope → target → layout → preview → export/save) |

### Phase 4 — Threat-intel surfaces (Phase 2, post-V2)
- Threat actors / campaigns / malware pages
- CTI feed ingestion (MISP, OTX, AbuseCH)
- IoC pivoting
- Authentication + approval workflow + internal rule overlays
- Compliance dashboards (PCI, HIPAA, SOC2)

## Out of scope for V2
- Authentication / RBAC
- Approval workflow
- CTI feed ingestion — Phase 2
- IoC / observable pivoting
- Per-tenant data isolation
- ML-based detection translation

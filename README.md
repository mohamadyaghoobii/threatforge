# MetaSec Security Center

> A detection-engineering and threat-intelligence platform that turns raw, open-source detection rules into MITRE ATT&CK–aligned **use cases** and ready-to-deploy **SIEM queries** — and, in the next phase, ready-to-import **dashboards**.

**MetaSec Security Center** is the Security section of the MetaSec studio (`security.metasec.company`). It moves the workflow from a simple "paste a Sigma rule, get a Splunk query" form to a **use-case-first** experience: pick a tactic or technique, see every variant of that detection across multiple open-source repositories, pick the best one, and convert it for your SIEM.

> Internal note: the source tree retains the original `threatforge` / `detectionforge_rule_engine` codenames for package paths, the database, and imports. These are internal identifiers only — they are never shown in the product UI, generated artifacts, or exported content. The public product name is **MetaSec Security Center**. A `scripts/brand_guard.py` check enforces this on user-facing surfaces.

---

## Table of contents

- [What ThreatForge does today](#what-threatforge-does-today)
- [Where it's going](#where-its-going)
- [Architecture](#architecture)
- [Repository layout](#repository-layout)
- [Quick start](#quick-start)
  - [Windows / PowerShell](#windows--powershell)
  - [Linux / macOS](#linux--macos)
  - [Docker Compose](#docker-compose)
- [First-run flow](#first-run-flow)
- [REST API](#rest-api)
- [Supported SIEM targets](#supported-siem-targets)
- [Conversion engine](#conversion-engine)
- [Rule sources](#rule-sources)
- [Configuration](#configuration)
- [Design principles](#design-principles)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## What ThreatForge does today

| Capability | Status |
| --- | --- |
| Sync Sigma / Hayabusa rule repositories from GitHub | ✅ |
| Import + normalize YAML detection rules | ✅ |
| Extract MITRE ATT&CK tactics and techniques from rule tags | ✅ |
| Score rule quality (severity, completeness, references, status) | ✅ |
| Group rules into **use cases** by technique / tactic | ✅ |
| Multi-SIEM fallback query converter (7 targets) | ✅ |
| Optional `sigma-cli` conversion path | ✅ |
| FastAPI backend with a documented REST API | ✅ |
| Next.js web portal (Dashboard, Rules, MITRE coverage, Generator) | ✅ |
| Postgres-ready database layer (SQLite by default for local dev) | ✅ |
| Docker Compose setup (API + Web + Postgres + Redis) | ✅ |
| Config-driven sources, profiles, field mappings | ✅ |
| Local custom detection pack (`data/custom-rules`) | ✅ |

---

## Where it's going

This repo is the **MVP baseline**. Three design documents in [`docs/design/`](docs/design/) describe the next phase:

1. **[UI modernization](docs/design/01-ui-modernization.md)** — Tailwind + shadcn shell, a real MITRE ATT&CK matrix heatmap, command palette, type-safe API client.
2. **[Coverage expansion](docs/design/02-coverage-expansion.md)** — more rule repositories (Elastic detection-rules, Splunk ESCU, Atomic Red Team, Azure Sentinel content), multi-format parsers, full MITRE STIX enrichment (technique names, data sources, mitigations, groups, software), and canonical use-case deduplication.
3. **[Dashboard generator](docs/design/03-dashboard-generator.md)** — wizard that generates ready-to-import dashboards (Splunk Simple XML, Microsoft Sentinel Workbooks, Kibana NDJSON) from a chosen scope of use cases, tactics, or threat actors.

Phase 2 (after V2 lands): threat actors, campaigns, malware, IoC pivoting, CTI feed ingestion (MISP / OTX / AbuseCH), authentication, approvals, internal rule overlays.

---

## Architecture

```
Repository sync (git/local)
  ↓
YAML discovery → Raw rule import (immutable, hashed)
  ↓
Parser → Normalizer → MITRE enrichment → Quality scoring
  ↓
Use-case grouping (by technique / tactic)
  ↓
Multi-SIEM converter (built-in fallback + optional sigma-cli)
  ↓
FastAPI + Next.js web portal
```

Four logical layers:

1. **Ingestion** — pulls rule repos to `data/repos/`, imports YAML, hashes raw content for dedup.
2. **Normalization** — single internal `NormalizedRule` model with `mitre_tactics`, `mitre_techniques`, `product`, `service`, `category`, `severity`, `quality_score`.
3. **Conversion** — `packages/rule_engine` builds a SIEM-specific query from `logsource` + `detection`, or shells out to `sigma-cli` if available.
4. **Presentation** — REST API + Next.js portal serving use cases, rules, MITRE coverage, and a query generator.

---

## Repository layout

```
threatforge/
  apps/
    api/                          # FastAPI backend
      app/
        api/routes.py             # all REST endpoints
        services/                 # repo sync, import, use-cases, conversion, MITRE
        models/                   # SQLAlchemy ORM (Repository, RawRule, NormalizedRule, ConvertedQuery)
        schemas/                  # Pydantic models
      tests/
      pyproject.toml
    web/                          # Next.js 14 frontend (App Router, TypeScript)
      app/
        page.tsx                  # Dashboard
        rules/                    # Rule explorer + detail
        mitre/                    # MITRE coverage page
        convert/                  # Use case → SIEM query generator
      lib/api.ts                  # API client
  packages/
    rule_engine/                  # Standalone Python package
      detectionforge_rule_engine/
        parser.py                 # Sigma YAML parser
        normalizer.py             # ParsedRule → NormalizedRule
        mitre.py                  # Tag-based ATT&CK extraction
        quality.py                # Quality scoring
        converters.py             # Multi-SIEM fallback converters
        splunk_fallback.py        # Splunk shortcut
        models.py                 # Internal dataclasses
  configs/
    sources/repositories.yml      # Which rule repos to sync
    conversion_profiles/splunk.yml
    field_mappings/splunk_windows.yml
  data/
    custom-rules/                 # Local internal detection pack (versioned)
    repos/                        # Synced external repos (gitignored)
  infra/
    api/Dockerfile
    web/Dockerfile
  docs/
    architecture.md
    roadmap.md
    design/                       # V2 expansion design docs
  docker-compose.yml
  Makefile
```

---

## Quick start

### Windows / PowerShell

**Backend**

```powershell
cd apps\api
python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
pip install -e ..\..\packages\rule_engine
pip install -e .
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8010
```

**Frontend**

```powershell
cd apps\web
Set-Content .env.local "NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8010"
npm install
npm run dev
```

Open:

- Web portal — http://localhost:3000
- API docs (Swagger) — http://127.0.0.1:8010/docs

### Linux / macOS

**Backend**

```bash
cd apps/api
python -m venv .venv
source .venv/bin/activate
pip install -e ../../packages/rule_engine
pip install -e .
cp ../../.env.example .env
uvicorn app.main:app --reload --host 127.0.0.1 --port 8010
```

**Frontend**

```bash
cd apps/web
printf 'NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8010\n' > .env.local
npm install
npm run dev
```

### Docker Compose

```bash
docker compose up --build
```

Brings up Postgres, Redis, the API on `:8000`, and the web portal on `:3000`.

---

## First-run flow

1. Start the API and the web portal.
2. Open Swagger at http://127.0.0.1:8010/docs.
3. `GET /api/repositories` — see configured sources.
4. `POST /api/repositories/sync` — clone or update each enabled repository under `data/repos/`.
5. `POST /api/rules/import` — parse every YAML rule, normalize it, extract MITRE tags, score quality.
6. Open the web portal at http://localhost:3000.
7. Go to the **Query Generator** page.
8. Filter by tactic, technique, product, source, or severity.
9. Pick a rule variant.
10. Pick a target SIEM and conversion profile.
11. Generate the query and copy it.

The local custom detection pack at `data/custom-rules/` is enabled by default, so you can test the full flow even before any external GitHub sync completes.

---

## REST API

All endpoints live under `/api`.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`  | `/api/repositories`               | List configured rule repositories with last sync status |
| `POST` | `/api/repositories/sync`          | Clone / fetch every enabled repository |
| `POST` | `/api/rules/import`               | Walk synced + custom repos, parse and normalize every YAML rule |
| `GET`  | `/api/rules`                      | List normalized rules with filters (`tactic`, `technique`, `product`, `service`, `category`, `severity`, `source`, `q`) |
| `GET`  | `/api/rules/{rule_id}`            | Full rule detail including raw YAML and normalized JSON |
| `POST` | `/api/convert`                    | Convert a rule to a target SIEM query |
| `GET`  | `/api/catalog/targets`            | List supported SIEM targets, their profiles and output formats |
| `GET`  | `/api/filters`                    | Distinct values for every filter dimension |
| `GET`  | `/api/use-cases`                  | Use cases grouped by technique / tactic, with rule counts and best variant |
| `GET`  | `/api/use-cases/{use_case_id}/rules` | Rules belonging to a use case |
| `GET`  | `/api/mitre/tactics`              | Per-tactic rule counts |
| `GET`  | `/api/mitre/techniques`           | Per-technique rule counts |
| `GET`  | `/health`                         | Liveness check |

Generate a query:

```bash
curl -X POST http://127.0.0.1:8010/api/convert \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": 42,
    "target": "splunk",
    "profile": "default_splunk_windows",
    "output_format": "default"
  }'
```

---

## Supported SIEM targets

| Target | Label | Support level |
| --- | --- | --- |
| `splunk`    | Splunk SPL                 | Built-in fallback + `sigma-cli` |
| `sentinel`  | Microsoft Sentinel KQL     | Built-in fallback + `sigma-cli` |
| `elastic`   | Elastic KQL                | Built-in fallback + `sigma-cli` |
| `opensearch`| OpenSearch Query String    | Built-in fallback + `sigma-cli` |
| `qradar`    | IBM QRadar AQL             | Built-in fallback + `sigma-cli` |
| `chronicle` | Google Chronicle UDM Search| Review-grade fallback |
| `logscale`  | CrowdStrike Falcon LogScale| Review-grade fallback |

The fallback converters are intentionally **best-effort** — designed for review, hunting, and engineering workflow validation. For production deployments you still want:

- Proper field mapping for your environment
- Correct indexes, sourcetypes, or tables
- SIEM-specific validation
- Ideally a pySigma pipeline for the target

---

## Conversion engine

ThreatForge attempts conversion in this order:

1. **`sigma-cli`** — if installed and on `PATH` (configured via `SIGMA_CLI_BIN`).
2. **Built-in fallback** — `packages/rule_engine/converters.py` builds a target-specific query from `logsource` + `detection` using field mappings and base selectors.

Install `sigma-cli` and the backends you want when you're ready:

```bash
pip install sigma-cli pysigma-backend-splunk pysigma-backend-kusto
```

The built-in converter understands Sigma's common idioms: simple selections, `contains` / `startswith` / `endswith` modifiers, lists, `1 of selection*`, `all of selection*`, and basic boolean conditions. It records every assumption it had to make as a warning on the response, so you can review before deploying.

---

## Rule sources

Defined in [`configs/sources/repositories.yml`](configs/sources/repositories.yml):

| Name | URL | Type | License |
| --- | --- | --- | --- |
| `sigmahq_sigma` | github.com/SigmaHQ/sigma | Sigma | Custom (DRL) |
| `mdecrevoisier_sigma_detection_rules` | github.com/mdecrevoisier/SIGMA-detection-rules | Sigma | CC0-1.0 |
| `p4t12ick_sigma_rule_repository` | github.com/P4T12ICK/Sigma-Rule-Repository | Sigma | GPL-3.0 |
| `yamato_security_hayabusa_rules` | github.com/Yamato-Security/hayabusa-rules | Hayabusa | DRL-1.1 |
| `local_custom_detection_pack` | `data/custom-rules` | Local Sigma | Internal |

More sources are coming in V2 (see [docs/design/02-coverage-expansion.md](docs/design/02-coverage-expansion.md)): Elastic detection-rules, Splunk ESCU, Atomic Red Team, Azure Sentinel content, MITRE/cti STIX bundle, Neo23x0/signature-base, FalconForce, Chainsaw rules.

---

## Configuration

ThreatForge is config-driven. Three folders matter:

- **`configs/sources/repositories.yml`** — which rule repos to sync, their branches, types, licenses, enabled flag, optional `local_path`.
- **`configs/conversion_profiles/`** — per-SIEM profiles (e.g. Splunk Sysmon vs. Windows Security vs. CIM endpoint). Each profile knows which indexes, sourcetypes, and base searches to use.
- **`configs/field_mappings/`** — per-product field translations (Sigma field → SIEM field).

Backend environment is loaded by `app/core/settings.py` and supports an `.env` file. Useful variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_NAME` | `DetectionForge` | App name shown in `/health` and API docs |
| `APP_ENV` | `local` | Environment tag |
| `DATABASE_URL` | SQLite in `apps/api/detectionforge.db` | SQLAlchemy DSN |
| `DATA_DIR` | `data/` | Where synced repos and custom rules live |
| `CONFIG_DIR` | `configs/` | Where config YAML lives |
| `CORS_ORIGINS` | `http://localhost:3000,http://127.0.0.1:3000` | Comma-separated allowed origins |
| `SIGMA_CLI_BIN` | `sigma` | Path to `sigma-cli` if installed |

---

## Design principles

- **External rules are read-only raw material.** ThreatForge never edits an upstream rule in place. It imports, hashes, and normalizes.
- **Use cases are first-class.** A use case can have many rule variants from many repositories; the platform always shows the "best" one but lets you pick any.
- **Conversion profiles belong to the organization, not to the rule.** Fields, indexes, sourcetypes, and tables vary per environment and never go inside the rule body.
- **Generated queries are artifacts.** They are stored, versioned, and can be regenerated from the same rule + profile deterministically.
- **Fallbacks are honest.** Every assumption the converter makes is surfaced as a warning so reviewers can act on it.

---

## Roadmap

Original milestones live in [`docs/roadmap.md`](docs/roadmap.md). The active V2 plan is in [`docs/design/00-roadmap.md`](docs/design/00-roadmap.md) and the three sub-tracks:

- **[`docs/design/05-generator-v2.md`](docs/design/05-generator-v2.md) — Phase 1, the load-bearing foundation.** Full Sigma spec, ~70 (target, profile) pairs, ~30 output formats with SIEM-native metadata, structured warnings, validation, bulk + cache, explainer + optimizer + round-trip.
- [`docs/design/02-coverage-expansion.md`](docs/design/02-coverage-expansion.md) — more rule repositories, multi-parser, MITRE STIX enrichment, canonical dedup
- [`docs/design/01-ui-modernization.md`](docs/design/01-ui-modernization.md) — UI shell, matrix heatmap, command palette
- [`docs/design/04-taxonomy.md`](docs/design/04-taxonomy.md) — use-case + dashboard classification that scales to hundreds of dashboards across SIEMs
- [`docs/design/03-dashboard-generator.md`](docs/design/03-dashboard-generator.md) — dashboard wizard (built on top of Generator V2)

Short version of what's next, in order:

1. **Generator V2 — the foundation.** Full Sigma spec, ~70 (target, profile) pairs across Splunk / Sentinel / Elastic / OpenSearch / QRadar / Chronicle / LogScale / Sumo Logic / Devo / Wazuh, ~30 output formats with SIEM-native metadata (schedules, throttles, notables, RBA, MITRE embedding), structured warnings + catalog, offline + live validation, bulk + cache, explainer + optimizer + round-trip. **Everything else is built on top of this.**
2. MITRE STIX enrichment + wider rule coverage (Elastic TOML, Splunk ESCU, Atomic Red Team, Azure Sentinel, MITRE/cti) + canonical dedup.
3. Use-case taxonomy tables + facets backfill.
4. Tailwind + shadcn UI shell, dark default, real ATT&CK matrix heatmap, use-case detail page, command palette.
5. **Dashboard generator** — wizard producing Splunk Simple XML, Sentinel Workbooks, and Kibana NDJSON dashboards from a scope of use cases. Thin layer over the V2 generator + curated packs for bulk export (hundreds of dashboards across SIEMs).
6. Threat actor / campaign / malware pages, CTI feed ingestion (MISP, OTX, AbuseCH), IoC pivoting.
7. Authentication, approval workflow, internal rule overlays, compliance dashboards.

---

## Contributing

This is an internal project in active development. Contributions, PRs, and design suggestions are welcome — open an issue first to discuss anything beyond a small fix.

Local development tips:

- Backend tests: `cd apps/api && pytest`
- Lint backend: `ruff check . && mypy app`
- Lint frontend: `cd apps/web && npm run lint`
- Reset local DB: stop the API and delete `apps/api/detectionforge.db`; it will be re-created on next boot.
- Reset synced rules: delete `data/repos/` and re-run `POST /api/repositories/sync`.

---

## License

To be finalized. Imported third-party rules retain their original licenses (see [Rule sources](#rule-sources)). The ThreatForge platform code (`apps/`, `packages/`, `configs/`, `infra/`) is unreleased and not yet licensed for redistribution.

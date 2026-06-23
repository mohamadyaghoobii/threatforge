# Design: UI Modernization (Phase 1A)

## Goal
Turn the current bare-bones CSS UI into a SOC-grade threat-intel console.

## Current state
- Plain CSS in `apps/web/app/globals.css`, no design system.
- 4 pages: `/`, `/rules`, `/mitre`, `/convert` (+ `/rules/[id]`).
- No charts, no MITRE matrix heatmap, no dark mode, no keyboard nav.
- API client in `apps/web/lib/api.ts` is fetch-based and untyped at the edges.

## Target stack
- **Tailwind CSS 3** + **shadcn/ui** (Radix-based, copy-into-repo components).
- **lucide-react** icons.
- **recharts** for time-series / bars; **visx** for the MITRE matrix heatmap.
- **TanStack Query** for client-side data fetching + caching.
- **zod** for response validation, shared with backend pydantic via codegen later.

## New / changed pages

| Route                       | Purpose                                                              |
|-----------------------------|----------------------------------------------------------------------|
| `/`                         | Overview: tactic coverage donut, top use cases, recent imports, KPIs |
| `/matrix`                   | Real ATT&CK matrix (tactic columns × technique rows) heatmap         |
| `/use-cases`                | Card grid + filters; replaces the use-case list inside `/convert`    |
| `/use-cases/[id]`           | Use case detail: variants, data sources, dashboards, related actors  |
| `/rules`                    | Same as today + virtualized table, column toggles, multi-select      |
| `/rules/[id]`               | Side-by-side raw YAML / normalized JSON / preview SIEM queries       |
| `/convert`                  | Slimmed down: now just the generator step (scope picked elsewhere)   |
| `/dashboards`               | Saved generated dashboards + "new dashboard" wizard (Phase 1C)       |
| `/sources`                  | Repositories status, last sync, errors, "sync now"                   |
| `/settings`                 | Profiles, field mappings (later)                                     |

## Layout shell
- Top bar: brand, global search (⌘K command palette), env badge, theme toggle, user menu.
- Left rail: icon nav (Dashboard, Matrix, Use Cases, Rules, Sources, Dashboards, Settings).
- Content: max-w-7xl with consistent `Card`, `Section`, `KPI`, `Badge`, `DataTable` primitives.

## Command palette (⌘K)
- Search use cases by technique id or name.
- Search rules by title.
- Jump to a tactic.
- Trigger sync.
- Open dashboard wizard.

## MITRE matrix
- Columns = 14 tactics (fixed order from `use_case_service.TACTIC_ORDER`).
- Each cell = a technique; color intensity from `rule_count` (log scale, 5 buckets).
- Hover: tooltip with technique name, rule count, top sources.
- Click: opens `/use-cases/[id]` for that technique.
- Filter bar: product, severity, source.

## Use case detail
Sections:
1. Header: technique id + name + tactic badges + ATT&CK link.
2. Variants table: id, title, source, quality, severity, mitre alignment.
3. Coverage panel: which SIEMs already have generated queries.
4. Quick generate: target + profile → render query in a tabbed pane.
5. Related techniques (sibling techniques in same tactic).
6. (Phase 2) Related threat actors + campaigns + IoCs.

## API client refactor
- Replace untyped fetch in `apps/web/lib/api.ts` with a generated client from OpenAPI (`openapi-typescript` + custom fetcher).
- Wrap every endpoint with TanStack Query hooks: `useUseCases`, `useRule`, `useConvert`, etc.

## Theming
- Dark default, light optional. CSS variables in shadcn theme tokens.
- Colors tied to severity (critical/high/medium/low/info) and tactic palette.

## Effort estimate
- Tailwind + shadcn install + base shell: 1 day.
- Matrix heatmap with visx: 1 day.
- Use-case detail + variants tab: 1 day.
- Command palette: 0.5 day.
- Type-safe API client + query hooks: 1 day.
- Polish + dark theme: 1 day.

Total: ~5–6 focused days.

## Acceptance
- All current routes still work.
- `/matrix` renders for all 14 tactics with at least one cell per imported technique.
- ⌘K palette can jump to a use case in under 200ms after typing 3 chars.
- Lighthouse a11y score ≥ 90.

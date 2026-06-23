# ThreatForge — Production Deployment (Liara)

Live:
- **Web**: https://threatintel.liara.run  (Liara app `threatintel`, Next.js)
- **API**: https://threatintel-api.liara.run  (Liara app `threatintel-api`, FastAPI/Python 3.12)

The repo is the single source of truth. Deploys run from a staging
artifact under `.liara-deploy/` that mirrors `apps/`, `packages/`,
`configs/`, and seed `data/`. `.liara-deploy/` is git-ignored — never edit
it by hand; re-sync from source before every deploy.

## 1. Sync source → deploy artifact

API (`.liara-deploy/api-python/`):

```powershell
$src = "<repo>"
$art = "$src\.liara-deploy\api-python"
robocopy "$src\apps\api\app" "$art\apps\api\app" /MIR /XD __pycache__ /NFL /NDL /NJH /NJS
robocopy "$src\packages\rule_engine\detectionforge_rule_engine" "$art\packages\rule_engine\detectionforge_rule_engine" /MIR /XD __pycache__ /NFL /NDL /NJH /NJS
robocopy "$src\configs" "$art\configs" /MIR /NFL /NDL /NJH /NJS
robocopy "$src\data\atomic" "$art\data\atomic" /MIR /NFL /NDL /NJH /NJS
robocopy "$src\data\intel"  "$art\data\intel"  /MIR /NFL /NDL /NJH /NJS
```

Web (`.liara-deploy/web/`):

```powershell
robocopy "$src\apps\web\app" "$art-web\app" /MIR /NFL /NDL /NJH /NJS
robocopy "$src\apps\web\lib" "$art-web\lib" /MIR /NFL /NDL /NJH /NJS
Remove-Item "$src\.liara-deploy\web\.env.local" -ErrorAction SilentlyContinue
```

> **Critical:** the web artifact must NOT contain `.env.local` — Next.js
> loads it over `.env.production` at build time and would bake the local
> `127.0.0.1` API URL into production. Only `.env.production`
> (`NEXT_PUBLIC_API_BASE_URL=https://threatintel-api.liara.run`) should be
> present.

## 2. Pre-deploy syntax check (API)

```powershell
python -m py_compile .\.liara-deploy\api-python\apps\api\app\services\atomic\service.py
```

## 3. Deploy

```powershell
cd .liara-deploy\api-python ; liara deploy --app threatintel-api
cd ..\web              ; liara deploy --app threatintel
```

`.liaraignore` in each artifact excludes `.venv`, `__pycache__`, `*.db`,
`node_modules`, `.next`, and `data/repos` from the upload.

## 4. Verify

```powershell
liara logs --app threatintel-api    # expect "Application startup complete"
```

Then hit:
- `GET /health`
- `GET /api/atomic/stats`  → tests ~1804
- `GET /api/intel/stats`   → indicators > 0
- `GET /api/recon/stats`   → selenium_available:false in prod (HTTP-only)
- `POST /api/recon/scan`   `{"target":"example.com"}`

## Environment

API entry (`.liara-deploy/api-python/main.py`) sets safe defaults:

| Var | Value |
| --- | --- |
| `DATA_DIR` | `<artifact>/data` |
| `CONFIG_DIR` | `<artifact>/configs` |
| `DATABASE_URL` | `sqlite:////tmp/threatforge.db` (ephemeral; see note) |
| `CORS_ORIGINS` | `https://threatintel.liara.run,...` |
| `INTEL_AUTO_REFRESH_MINUTES` | `0` (enable with a positive value) |

Notes:
- The SQLite DB lives on the container's ephemeral disk, so it is
  re-seeded (Atomic Bible + Threat Intel) on every release. For durable
  data, attach a Liara disk or point `DATABASE_URL` at managed Postgres.
- **Selenium/browser rendering is unavailable on Liara** (no Chrome); the
  recon engine automatically runs HTTP-only there. Screenshots require a
  host with Chrome (local dev, or a custom Docker image with chromium).
- `THREATFOX_AUTH_TOKEN` is optional; the configured feeds (URLhaus,
  ThreatFox public CSV, Feodo, MalwareBazaar, blocklist.de) need no keys.

## Local (Docker Compose)

`docker-compose.yml` brings up Postgres + Redis + API (8000) + Web (3000)
for local development. See the root README for the non-Docker quick start.

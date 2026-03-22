# TCIO Platform

Security-first monorepo for the Tanzania Cyber Intelligence Observatory (TCIO).

## Stack
- Backend: Django + Django REST Framework
- Frontend: Next.js (App Router)
- Services: Scrapers, AI analytics, scanner orchestrator, automation, smart-contract gateway
- Infrastructure: Docker Compose

## Monorepo Layout
- `backend/` Django API and domain apps
- `frontend/` Next.js dashboard
- `scrapers/` OSINT ingestion service
- `ai-engine/` analytics and scoring service
- `scanner-orchestrator/` legal-safe scan execution orchestrator
- `automation/` alert rules and delivery channels
- `contracts/` smart-contract integration gateway
- `docs/` architecture notes

## Project Generation Commands Used
- Frontend scaffold:
  - `npx create-next-app@latest frontend --ts --eslint --tailwind --app --src-dir --use-npm --import-alias "@/*" --yes`
- Backend scaffold:
  - `python3 -m django startproject config backend`
  - `python3 manage.py startapp common authn audit osint scans analytics alerts consent` (executed as individual `startapp` commands)
- Contracts scaffold:
  - `npm init -y`

## Run Locally
1. Backend:
   - `cd backend`
   - `python3 manage.py migrate`
   - `python3 manage.py runserver`
2. Frontend:
   - `cd frontend`
   - `npm run dev`
3. Optional service checks:
   - `cd scrapers && python3 src/main.py`
   - `cd ai-engine && python3 src/main.py`
   - `cd scanner-orchestrator && python3 src/main.py`
   - `cd automation && python3 src/main.py`
   - `cd contracts && npm run start`
   - `cd contracts && npm run compile`
4. Full containers:
   - `docker compose up --build -d redis backend backend-worker backend-beat frontend`
   - Run job modules on demand:
     - `docker compose run --rm scrapers`
     - `docker compose --profile jobs run --rm scrapers-scheduler` (continuous scheduler; stop with Ctrl+C)
     - `docker compose run --rm scanner-orchestrator`
     - `docker compose run --rm automation`
     - `docker compose run --rm ai-engine`
     - `docker compose run --rm contracts`
5. Full integration verification:
   - `python3 scripts/verify_system.py --base-url http://localhost:8001/api/v1`

## Frontend Demo Journeys
- Home: `http://localhost:3001/`
- Command center dashboard: `http://localhost:3001/dashboard`
- OSINT intelligence: `http://localhost:3001/osint-intelligence` (alias to `/threat-map`)
- Vulnerability scans: `http://localhost:3001/vulnerability-scans` (alias to `/exposure`)
- Regional intelligence: `http://localhost:3001/regional-cyber-intelligence` (alias to `/regional`)
- Malware trends: `http://localhost:3001/malware`
- Threat alerts: `http://localhost:3001/threat-alerts` (alias to `/alerts`)
- Reports: `http://localhost:3001/reports`
- API access: `http://localhost:3001/api-access`
- Organization management: `http://localhost:3001/organization-management`
- System monitoring: `http://localhost:3001/system-monitoring`
- User journeys: `http://localhost:3001/journeys`
- Auth role flow: `http://localhost:3001/auth`

## External Feed Credentials (Optional but Recommended)
- Add these to `.env` to enable all configured OSINT collectors:
  - `ABUSEIPDB_API_KEY=...`
  - `OTX_API_KEY=...`
  - `ACLED_API_KEY=...`
  - `ACLED_EMAIL=...`
- Without them, `abuseipdb`, `otx`, and `acled` collectors will remain at zero events.

## AI Configuration (Gemini)
- Add these to `.env` to enable Gemini-assisted regional risk adjustment in `ai-engine`:
  - `GEMINI_API_KEY=...`
  - `GEMINI_MODEL=gemini-2.0-flash`
  - `GEMINI_TIMEOUT_SECONDS=45`
- If `GEMINI_API_KEY` is empty, `ai-engine` falls back to deterministic scoring logic.

## Async Worker Pipeline
- Celery + Redis now power background processing:
  - queued scan processing (`scans.process_queued_scan_jobs`)
  - alert dispatch (`alerts.dispatch_open_alerts`)
  - hourly regional snapshot generation (`analytics.generate_regional_snapshots`)
- Worker and beat run as `backend-worker` and `backend-beat` containers.

## Map Rendering Notes
- The threat map now uses Leaflet and OpenStreetMap tiles.
- Administrative boundaries are loaded from:
  - `https://raw.githubusercontent.com/Heed725/Tanzania_Adm_Geojson/main/Regions.geojson`
  - `https://raw.githubusercontent.com/Heed725/Tanzania_Adm_Geojson/main/District_Unsegmented.geojson`
  - `https://raw.githubusercontent.com/Heed725/Tanzania_Adm_Geojson/main/Wards.geojson`
  - `https://raw.githubusercontent.com/Heed725/Tanzania_Adm_Geojson/main/Villages.geojson`
- Users can switch boundary levels (`regions`, `districts`, `wards`, `villages`) directly in `/threat-map`.
- Boundary polygons are styled from OSINT event count + maximum severity at the selected admin level.

## Initial API Endpoints
- `GET /api/v1/health/`
- `GET /api/v1/authn/profile/`
- `POST /api/v1/authn/bootstrap/`
- `POST /api/v1/authn/token/`
- `GET /api/v1/audit/logs/`
- `GET /api/v1/osint/summary/`
- `GET /api/v1/osint/sources-health/`
- `GET /api/v1/osint/events/`
- `POST /api/v1/osint/events/ingest/`
- `POST /api/v1/consent/grants/`
- `GET /api/v1/consent/grants/list/`
- `GET /api/v1/scans/summary/`
- `GET /api/v1/scans/jobs/list/`
- `POST /api/v1/scans/jobs/`
- `POST /api/v1/scans/jobs/reserve/`
- `POST /api/v1/scans/jobs/process-once/`
- `POST /api/v1/scans/jobs/process-async/`
- `POST /api/v1/scans/jobs/{job_id}/complete/`
- `GET /api/v1/scans/findings/`
- `GET /api/v1/scans/jobs/{job_id}/progress/`
- `GET /api/v1/analytics/risk-overview/`
- `GET /api/v1/analytics/snapshots/`
- `POST /api/v1/analytics/snapshots/ingest/`
- `POST /api/v1/analytics/snapshots/generate/`
- `GET /api/v1/alerts/active/`
- `POST /api/v1/alerts/dispatch/`
- `POST /api/v1/alerts/{alert_id}/ack/`
- `GET /api/v1/consent/status/`
- `GET /api/v1/reports/summary/`
- `GET /api/v1/reports/export/`
- `GET /api/v1/system/metrics/`
- `GET /api/v1/authn/users/`
- `POST /api/v1/authn/users/{username}/role/`
- `GET /api/v1/authn/organizations/`
- `GET /api/v1/authn/api-keys/`
- `POST /api/v1/authn/api-keys/rotate/`
- `POST /api/v1/authn/api-keys/revoke/`

## API Flow Example (Consent-Gated Scanning)
1. Create a consent grant:
   - `POST /api/v1/consent/grants/`
   - body:
     ```json
     {
       "requester_name": "Security Team",
       "requester_email": "secops@example.com",
       "target": "203.0.113.10",
       "allowed_scanners": ["nmap", "openvas"],
       "valid_until": "2026-12-31T23:59:59Z"
     }
     ```
2. Create a scan job with returned `consent_id`:
   - `POST /api/v1/scans/jobs/`
   - body:
     ```json
     {
       "consent_id": "replace-with-consent-uuid",
       "asset_type": "ip",
       "asset_value": "203.0.113.10",
       "scanner_type": "nmap",
       "requested_by": "secops@example.com"
     }
     ```
3. Ingest OSINT events (manual or scraper pipeline):
   - `POST /api/v1/osint/events/ingest/`
   - body accepts one event object or an array of event objects.
4. Process queued jobs through orchestrator:
   - `cd scanner-orchestrator`
   - `python3 src/main.py`
   - This reserves queued jobs, generates findings, completes jobs, and auto-creates high/critical alerts.
5. Dispatch/ack alerts via automation:
   - `cd automation`
   - `python3 src/main.py`
6. Generate and ingest snapshots via AI service:
   - `cd ai-engine`
   - `python3 src/main.py`
7. Register smart-contract style consent via gateway:
   - `cd contracts`
   - `npm run start`

## Notes
- Scanning must remain authorization-gated.
- No exploit functionality is included.
- Mutation endpoints are protected with role checks (`owner/analyst/compliance`) and support local debug header: `X-Debug-Role`.
- CI workflow is configured at `.github/workflows/ci.yml` (backend tests + frontend lint/build + contract compile/test).

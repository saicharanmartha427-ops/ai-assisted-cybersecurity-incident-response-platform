url link: https://cyber-ir-dashboard.onrender.com/
# AI-Assisted Cybersecurity Incident Response Platform

A college-ready full-stack Security Operations Center (SOC) prototype built with **React + Bootstrap + Chart.js** and a **Flask REST API**. It ingests security telemetry through CSV or manual events, performs hybrid anomaly detection, creates incidents, recommends response actions, tracks response metrics, and exports reports.

## Core workflow

`Security event → Ingestion → AI-assisted detection → Incident → Severity → AI recommendation → Response playbook → Resolution → Metrics/Report`

## Features

- Interactive SOC dashboard with incident trend, severity distribution, active alerts and KPIs.
- CSV telemetry ingestion with preview/results and suspicious-vs-normal classification.
- Manual event input to demonstrate a live SIEM/IDS-style event source without requiring external hardware.
- Hybrid detection: standardized statistical anomaly scoring + explicit cybersecurity spike rules.
- Optional **real Generative AI enrichment** through an OpenAI-compatible Chat Completions API: explains flagged incidents, proposes investigation steps, states confidence/limitations, and suggests a response. The LLM does not decide the initial suspicious/not-suspicious result; deterministic detection stays separate.
- The Settings page shows whether the backend has a live LLM API key configured. If the key is absent or the provider call fails, the app falls back to deterministic analysis.
- Incident management with search, severity/status filters, details, response execution and resolution.
- Response playbooks: Block IP, Quarantine File, Notify Admin; Admin-only CRUD.
- JWT authentication with Admin/Analyst roles and password hashing.
- Audit log for security-sensitive actions.
- MTTD/MTTR reporting and CSV/PDF export.
- OpenAPI specification at `/api/openapi.json` and `docs/openapi.yaml` for Swagger/Postman use.
- Docker and deployment documentation.
- Automated backend smoke tests and CI workflow.

## Demo accounts

- Analyst: `analyst` / `Analyst@123`
- Admin: `admin` / `Admin@123`

These are demo-only local credentials. Change them before any real deployment. The backend generates a temporary JWT secret if `JWT_SECRET` is missing; set a persistent random secret in `backend/.env` for normal local use.


## Enable real Generative AI (optional, recommended for the project demonstration)

1. In the `backend` folder, copy `.env.example` to a new file named `.env`.
2. Open `backend/.env` and set `JWT_SECRET` to a long random value.
3. Add an API key from your chosen OpenAI-compatible provider to `OPENAI_API_KEY`. The default endpoint is OpenAI's API and the default model is `gpt-4o-mini`; set `OPENAI_BASE_URL` and `OPENAI_MODEL` if your provider uses another compatible endpoint/model.
4. Restart `python app.py`, log in again, and open **Settings → Generative AI integration**. It should show **Configured**.
5. Upload a CSV with suspicious events or enter a suspicious manual event. The detector first flags the event using deterministic rules/statistical scoring; the configured LLM then enriches up to five suspicious events per CSV upload with an explanation, investigation steps, confidence and limitations.

**Important:** The API key stays on the Flask backend. Do not place it in `frontend/.env`, React code, screenshots, Git, or the ZIP you submit. Keep `backend/.env` private. API usage may incur provider charges. LLM output can be wrong and must be reviewed by an analyst. The platform records response actions in its workflow; it does not connect to a real firewall or quarantine files unless you build and configure those integrations.

Without `OPENAI_API_KEY`, the app remains functional in **rules-only mode** and does not pretend that a live LLM was called.

## Automated checks

From the project root, with Python dependencies installed:

```cmd
cd backend
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Build the frontend from a second terminal:

```cmd
cd frontend
npm install
npm run build
```

A successful build/test command is evidence for that specific check only; it does not replace end-to-end manual verification.

## Windows Smart App Control note

The local runtime intentionally avoids NumPy/Pandas/scikit-learn/ReportLab native extensions because Smart App Control on the target Windows machine blocked native `.pyd` files. The production architecture remains compatible with those tools: `backend/requirements-ai-reference.txt` documents the optional Pandas/scikit-learn stack for environments where native scientific wheels are permitted. The application uses Python's standard CSV parser and a deterministic statistical/rules engine in SAC-compatible mode.

## Run locally on Windows

Backend:

```cmd
cd backend
python app.py
```

Frontend in a second terminal:

```cmd
cd frontend
npm run dev
```

Open `http://localhost:5173`.

## API / documentation

- Health: `GET /api/health`
- Generative AI status (authenticated): `GET /api/ai/status`
- Login: `POST /api/auth/login`
- Dashboard: `GET /api/dashboard`
- Manual event: `POST /api/events`
- CSV AI analysis: `POST /api/analyze`
- Incidents: `GET /api/incidents`, `PATCH /api/incidents/{id}`
- Response action: `POST /api/incidents/{id}/actions`
- Playbooks: `/api/playbooks`
- Reports: `/api/reports`
- Exports: `/api/reports/export.csv`, `/api/reports/export.pdf`
- Audit: `GET /api/audit` (Admin)
- OpenAPI: `GET /api/openapi.json`

## Software-engineering evidence

The project maps to the supplied Product 26 guide through the documents in `docs/`:

- requirements and workflow
- architecture/database design
- prompt-engineering and AI-assisted SDLC notes
- testing/debugging/security checklist
- deployment/maintenance plan
- responsible AI and limitations

Postman collection is in `postman/`.

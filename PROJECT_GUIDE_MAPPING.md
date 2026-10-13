# Product 26 — Requirement Mapping

| Guide requirement | Implemented evidence |
|---|---|
| Requirement Analysis & Workflow Design | `docs/REQUIREMENTS.md`, end-to-end SOC workflow in README |
| Prompt Engineering & AI-assisted Planning | `docs/AI_ASSISTED_SDLС.md` |
| Database & System Architecture Design | `docs/ARCHITECTURE.md`, SQLite schema, PostgreSQL option documented |
| Frontend Module Development | React dashboard, ingestion, incidents, playbooks, reports, settings |
| Backend REST API Development | Flask REST API under `/api/*` |
| Database Integration | Persistent SQLite database; PostgreSQL adapter plan in `requirements-postgresql.txt` |
| AI-assisted Testing & Debugging | `backend/test_backend.py`, CI workflow, debugging notes |
| Documentation Generation & Code Review | `docs/` + README + OpenAPI |
| Security Testing & Performance Optimization | JWT, role-based authorization, password hashing, CORS allowlist, audit log, input validation, auto-refresh |
| Cloud Deployment & Final Demonstration | `Dockerfile`, `docker-compose.yml`, `docs/DEPLOYMENT.md` |
| Interactive dashboard and analytics | Chart.js, KPIs, trend and severity analytics |
| Secure database and REST APIs | Authenticated endpoints, hashed passwords, audit trail |
| Well-documented and maintainable source code | Modular React components, backend functions, docs, tests |
| Cloud-ready | Docker + environment variables + deployment guide |
| Pandas | Optional scientific/data-science stack documented in `requirements-ai-reference.txt`; SAC runtime uses stdlib CSV fallback |
| JWT Authentication | PyJWT runtime authentication |
| Swagger/OpenAPI | `backend/openapi.json`, `docs/openapi.yaml`, `/api/openapi.json` |
| Git & GitHub | `.gitignore` and CI workflow included |
| Postman | `postman/CyberGuard.postman_collection.json` |
| Replit | `docs/DEPLOYMENT.md` includes Replit deployment notes |
| Docker | `Dockerfile` and `docker-compose.yml` |


## Generative AI integration update

The backend now supports optional live incident enrichment through an OpenAI-compatible Chat Completions API. The deterministic statistical/rule detector remains separate and decides whether an event is suspicious; the LLM adds an explanation, investigation steps, confidence, limitations and a suggested response for flagged events. Provider status is exposed at authenticated `GET /api/ai/status` and in Settings. Configure `OPENAI_API_KEY` in the private backend `.env` file to enable live calls. Without a key or if the provider call fails, the system falls back to deterministic analysis. This is a prototype integration, not autonomous response or production-grade threat detection.

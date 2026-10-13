# Architecture and Database Design

```text
React + Bootstrap + Chart.js
        |
        | HTTPS/HTTP REST + JWT
        v
Flask API / detection service
        |
        +---- Authentication / RBAC
        +---- CSV/manual event ingestion
        +---- Hybrid anomaly engine
        +---- Incident response service
        +---- Reporting/export service
        |
        v
SQLite (local) / PostgreSQL adapter path
```

## Tables

- `users` — credentials, display name, role.
- `events` — ingested security telemetry.
- `incidents` — security incidents and lifecycle timestamps.
- `incident_actions` — response action history.
- `playbooks` — reusable response actions.
- `reports` — generated metric snapshots.
- `audit_logs` — security-sensitive activity history.
- `settings` — platform configuration.

## API security

Protected routes require `Authorization: Bearer <JWT>`. Admin-only operations protect playbook administration, platform settings and audit access.

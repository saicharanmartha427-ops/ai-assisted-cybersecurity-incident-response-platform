# Requirements and Workflow

## Functional requirements

1. Authenticate users as Admin or Analyst.
2. Accept cybersecurity telemetry through CSV upload and manual event entry.
3. Normalize numeric telemetry and calculate an anomaly score.
4. Apply security-specific detection rules for failed logins, request rate, transferred bytes and risky ports.
5. Create persistent incidents from suspicious events.
6. Assign severity and an AI-assisted recommended response.
7. Allow analysts to inspect, contain and resolve incidents.
8. Allow administrators to manage response playbooks.
9. Calculate MTTD and MTTR.
10. Generate and export reports.
11. Maintain an audit trail.
12. Expose documented REST APIs.

## Non-functional requirements

- Responsive web UI.
- Local development without cloud dependencies.
- Configurable environment variables.
- Smart App Control-compatible local runtime.
- Deterministic demo data and reproducible testing.
- Input validation and authentication on protected APIs.

## Demonstration scenario

A CSV containing mostly normal traffic plus high failed-logins/request-rate rows is uploaded. The backend calculates a statistical anomaly score and applies security rules. Suspicious rows become incidents. The analyst sees the incidents, accepts the recommended playbook action, resolves them, and generates a report.

# Security Testing and Performance Checklist

- [x] JWT authentication on protected API routes
- [x] Passwords stored as salted hashes
- [x] Admin-only authorization for playbook/settings/audit administration
- [x] CORS allowlist rather than wildcard by default
- [x] CSV extension validation
- [x] Numeric input validation for manual events
- [x] Audit logging of login, incident actions, ingestion, reports and administration
- [x] No shell execution or external command execution from uploaded data
- [x] Parameterized SQLite SQL statements
- [x] Response exports generated server-side
- [ ] Add HTTPS/TLS at the reverse proxy in production
- [ ] Replace demo credentials and JWT secret before deployment
- [ ] Add rate limiting/WAF in production
- [ ] Add a real SIEM/EDR connector for production telemetry

## Performance notes

The prototype uses bounded dashboard queries and only returns the latest 100 events/audit records. CSV processing is streaming through Python's CSV reader into a bounded preview; production deployments should add upload-size limits, background jobs and a queue for very large files.

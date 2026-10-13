# Deployment

## Docker

Build and run:

```bash
docker compose up --build
```

The frontend is served by Vite in development in this project; for production, build it with `npm run build` and serve the `dist/` directory from a reverse proxy/static host. The Flask API listens on port 5000.

## Replit

Create a Python/Node workspace, copy the `backend` and `frontend` directories, set `JWT_SECRET` and `CORS_ORIGINS` as secrets/environment variables, run Flask on the public backend port, then run the React build through a static server. Use a managed PostgreSQL service for persistent production data.

## Cloud production checklist

- PostgreSQL instead of local SQLite.
- HTTPS.
- Secret manager for JWT secret and database credentials.
- Reverse proxy and rate limiting.
- Separate frontend/backend services.
- Centralized logging and monitoring.
- Backups and database migrations.

# Production Database Path

The classroom/demo runtime uses SQLite because it is zero-setup and avoids native database drivers that can trigger Windows Smart App Control. The project also includes a PostgreSQL dependency option (`pg8000`, pure Python) and documents the migration path.

For a cloud deployment, move the repository layer to PostgreSQL and run schema migrations rather than relying on SQLite's `ALTER TABLE` compatibility. PostgreSQL is the recommended production database because it supports concurrent workloads, backups, roles and managed cloud services.

MySQL can also be used with a compatible DB adapter; the REST API and frontend do not depend on database-specific features.

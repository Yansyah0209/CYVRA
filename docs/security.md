# Security configuration
Run on localhost and use only owned or authorized evidence. No autonomous scanning or exploitation is implemented. The default Postgres password is a local-only convenience; change it when adapting deployment.

CYVRA_API_KEY, if set, protects backend `/api/` routes and is supplied server-side by the Next.js proxy. The frontend itself has no login; a key is not enough to make the application public-safe. Health and API schema/docs remain public at loopback.

DATABASE_URL configures persistence. CORS_ORIGINS is a comma-separated explicit origin list. Secrets belong in environment configuration, never committed files. `.env` and local database files are ignored. Imports are capped and validated. No LLM receives private evidence in this version.

Before any public beta, implement authentication/authorization, access-controlled exports, tenant separation, rate limits, TLS, deployment review, dependency monitoring, migration/backup strategy, and an audit trail. Report issues through a private channel agreed with the repository owner; avoid posting live sensitive data in public issues.

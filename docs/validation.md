# Validation recorded for this implementation

- 25 pytest backend unit/integration tests passed: risk scores and context ordering, freshness and missing evidence, correlated-source handling, contradictions, reference/range checks, cycles, parallel edges, search bounds, zero-hop paths, all-resolved inputs, intervention immutability, alternate entries, controls, optimization budget, project imports, API key, oversized payloads, and grounded explanations.
- Python Ruff lint and formatting passed.
- Alembic initial migration completed against SQLite.
- Next.js production build and TypeScript checks passed; standalone static files prepared.
- Prettier formatting checks passed.
- Actual built Next.js proxy → FastAPI → temporary SQLite full workflow passed using scripts/smoke.py (with optional backend key enabled): create, demo import, analysis, recommendations, segmentation, non-mutating export, and cited explanation.
- Demo: seven assets, seven findings, six candidate paths; portfolio modeled risk 78.4. Simulated segmentation of internal API: risk 46.3 and zero candidate paths. This is a hypothetical intervention with connectivity disruption, not an actual security outcome.
- Reproducible synthetic benchmark framework executed on 20 seeds; results.json contains all results and limitations. Results use the model's own objective and differing action spaces, so they do not establish real-world superiority.
- npm audit and pip-audit of the locked dependency sets reported no known advisories at checking time. This is not proof of absence of vulnerabilities. Next.js transitive PostCSS and sharp are explicitly overridden to patched registry versions and the resulting build passed.

## Unverified locally
Docker and a PostgreSQL server were unavailable, so Compose execution and PostgreSQL integration were not tested here. Browser tests could not run because browser archive downloads returned invalid/truncated files in the execution environment. A Playwright workflow test is supplied and wired into CI, but no local browser pass is claimed. No visual screenshot inspection was possible.

A third-party Starlette TestClient deprecation warning about its httpx transport appears during pytest; tests pass. Live GitHub Actions results are separate from local checks and must be reviewed on the PR. No public deployment, multi-tenant production test, independent incident calibration, or patent assessment was performed.

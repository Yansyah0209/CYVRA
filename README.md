# CYVRA
**Cyber Vulnerability & Risk Analysis AI** — an evidence-aware, explainable defensive cyber risk intelligence MVP.

CYVRA imports security evidence, ranks contextual risk, constructs a risk graph, identifies **possible** connectivity paths to critical assets, and simulates remediation without changing infrastructure. Analytical engines decide; the offline explanation provider presents their structured results. No paid API or LLM key is required.

## Start with Docker
```bash
git clone https://github.com/Yansyah0209/CYVRA.git
cd CYVRA
git checkout feat/cyvra-mvp
cp .env.example .env
docker compose up --build
```
Open **http://localhost:3000**, choose **Launch demo**, then explore Overview, Risk Graph, Assets, Findings, Attack Paths, Remediation, and CYVRA AI. API documentation: **http://localhost:8000/docs**. Health: **http://localhost:8000/health**.

PostgreSQL data persists in the `cyvra_data` volume. The demo is explicitly synthetic and contains no genuine CVEs or threat intelligence. Its fixed evidence timestamps intentionally demonstrate confidence decay.

## Without Docker
Prerequisites: Python 3.12+, Node 22+, npm. From the repository root:
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate; macOS/Linux:
source .venv/bin/activate
pip install -r backend/requirements.lock
cd backend
alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
In a second terminal from the repository root:
```bash
cd frontend
npm ci
npm run dev
```
The local backend defaults to SQLite; Docker uses PostgreSQL. Do not load the Docker `.env` DATABASE_URL into the SQLite setup. Frontend server proxies API requests using `BACKEND_URL` (default `http://127.0.0.1:8000`). The optional API key stays server-side.

## Use your own authorized evidence
Create an environment, then import JSON matching [the demo schema](datasets/synthetic/aurora.json). Import replaces that environment's dataset atomically. Export retrieves the stored dataset. Strict Pydantic validation rejects unknown fields, invalid ranges, duplicate record IDs, and unresolved references. Payload cap: 2 MB; 200 assets, 2,000 findings, 1,000 relationships. JSON is the implemented ingestion adapter; scanner, telemetry, and threat-intelligence integrations are future work.

## Implemented
- Project creation and persistent JSON snapshots through SQLAlchemy and Alembic.
- Transparent six-factor contextual scores, mitigation, individual contributions, separate evidence confidence.
- Evidence provenance, age decay, source-group correlation handling, contradictory and missing evidence.
- NetworkX risk graph and bounded candidate path reasoning.
- Patch, exposure removal, segmentation, relationship restriction, and control simulations.
- Greedy budget-constrained remediation with illustrative costs and explicit operational impact.
- Responsive Next.js/React dashboard with interactive React Flow graph, imports, exports, and explanations.
- Offline grounded assistant behind a provider protocol; no external generative provider enabled.
- Backend tests, frontend type/build checks, CI, synthetic benchmark framework, methodology and threat model.

## Validation
```bash
pip install -r backend/requirements-dev.txt
pytest -q
ruff check backend research scripts
ruff format --check backend research scripts
cd frontend
npm ci
npm run typecheck
npm run build
npm run format:check
# Back at repository root:
python scripts/smoke.py
```
Run the reproducible synthetic benchmark from the root:
```bash
PYTHONPATH=backend python research/benchmarks/run.py --seeds 20 --budget 3
```
See [validation notes](docs/validation.md) for checks actually run and limitations.

## Research MVP limits
This is a **local, single-user research MVP**, not a multi-tenant production SaaS. No public deployment is configured. Docker binds ports to loopback. The optional backend API key is not user authentication; the frontend proxy is intended for a trusted local user. Do not expose it publicly without real authentication, tenant isolation, rate limits, encrypted transport, security review, and deployment controls.

Risk and confidence are heuristic indices, not calibrated probabilities. Network connectivity does not prove exploitation. Counterfactual reductions are modeled, not guaranteed. Optimization is greedy and bounded, not exact. No scanner, exploitation, malware, external enrichment, trained ML, or real-time monitoring runs. Benchmark results are synthetic and share the production model's objective; they cannot validate real-world accuracy or patentability.

Start with [architecture](docs/architecture.md), [risk methodology](docs/risk-methodology.md), and [threat model](docs/threat-model.md). The implementation is a foundation for user validation, calibration, independent benchmarking, and future integrations—not a claim of enterprise maturity.

Browser workflow test: activate the Python environment, then from frontend run `npx playwright install chromium` and `npm run test:e2e` after building. See LICENSE for the current rights policy; no open-source license has been granted yet.

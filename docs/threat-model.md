# Threat model
Scope: a trusted local single user imports authorized security data. Assets: imported topology, evidence, findings, DB snapshots, optional API key. Boundaries: browser → Next.js proxy → FastAPI → database. No active scanner or infrastructure actuator exists.

Risks and controls:
- Malformed or oversized imports: streamed API 2 MB cap, schema collection limits, reference/range validation.
- Excessive graph search: explicit depth/path/expansion limits. Repeated analyses and recommendation requests still consume CPU; production rate limits and jobs are not implemented.
- UI content injection: React escapes text; no raw HTML rendering or model-driven command execution.
- Backend proxy SSRF: fixed backend origin and route allowlist; no user-selected URL.
- Data exfiltration: offline explanation makes no provider requests; no secrets or raw imported data in logs.
- Unauthorized access: loopback ports by default; optional backend API key. Frontend is NOT an authenticated public gateway.
- Data poisoning: confidence and observed flags are supplied assertions; expose provenance, contradictions, and uncertainty. A malicious trusted importer can manipulate results.
- Accidental production changes: no actuator; simulations are copies.

Not solved: multi-user authentication, tenant isolation, encryption at rest, fine-grained authorization, audit history, robust distributed rate limits, browser session protection, external secret management, backups, or independent evidence verification. Do not deploy publicly as-is.

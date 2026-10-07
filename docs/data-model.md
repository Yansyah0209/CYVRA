# Canonical data model
Dataset contains assets, findings, and directed relationships. Pydantic strict extra-field rejection is enabled (numeric coercion follows Pydantic defaults).

Asset: id, name, type, criticality [0,1], internet_exposed, owner, environment, control_strength [0,1]. Supported types: application, API, server, database, identity, repository, service.

Finding: id, asset_id, title, optional CVE, CVSS [0,10], optional known_exploited, exploit_likelihood [0,1], telemetry, open/resolved status, evidence list.

Evidence: id, source, timezone-aware collected_at (not future), reliability [0,1], supports, independence group. Reliability and independence are input assumptions, not independently verified facts. Repeated evidence within one source group cannot inflate its weight beyond that group's strongest record.

Relationship: id, source, target, type (CONNECTS_TO, DEPENDS_ON, HAS_ACCESS_TO, TRUSTS, HOSTS), confidence [0,1], observed/inferred flag, evidence IDs, enabled flag. Relationship evidence IDs must refer to finding evidence. Observed is a supplied assertion, not independently confirmed by CYVRA. Relationship confidence is presently supplied, not automatically calibrated.

Record IDs must be unique within each collection, and assets and findings must have disjoint IDs. Asset references are validated. Evidence IDs may appear in multiple findings because the same observation can support multiple hypotheses; repeated IDs must have identical fields.

Project: UUID, name, created_at, nullable JSON dataset. Import is a replacement transaction; export preserves supplied values. This version has no audit history, version locking, user accounts, or normalized per-asset tables.

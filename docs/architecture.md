# Architecture
A modular monolith keeps deployment and learning practical while isolating schemas, persistence, graph construction, evidence fusion, risk calculation, interventions, and explanation.

Next.js client → same-origin server proxy → FastAPI → SQLAlchemy project snapshot. The analytical pipeline is canonical Dataset → risk features → evidence confidence → graph and bounded paths → structured analysis → counterfactual interventions → grounded explanation.

PostgreSQL is the Compose store; SQLite supports local development. JSON snapshots preserve original evidence without prematurely introducing an extensive enterprise ontology. Alembic manages the projects table. Simulations deep-copy data and never mutate persisted snapshots. All APIs are documented by FastAPI.

React Flow provides graph navigation. The API proxy keeps an optional backend key off the browser and constrains destinations to fixed routes; it is not an authentication boundary for public deployment.

Future adapters should map external reports to Dataset and preserve source timestamps/IDs. Future graph stores can replace NetworkX behind the construction and traversal interfaces. No external LLM integration is active; ExplanationProvider defines an extension seam. Adding one requires data minimization, explicit opt-in, structured grounding, citation validation, and prompt-injection review.

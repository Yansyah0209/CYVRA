from dataclasses import dataclass, field
from datetime import datetime, timezone
import networkx as nx
from app.schemas import Dataset
from app.intelligence.evidence import fuse
from app.intelligence.graph import build_graph, paths


@dataclass(frozen=True)
class RiskConfig:
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "severity": 0.30,
            "exposure": 0.20,
            "criticality": 0.20,
            "known_exploitation": 0.15,
            "exploit_likelihood": 0.10,
            "telemetry": 0.05,
        }
    )
    control_discount: float = 0.5

    def __post_init__(self):
        expected = {"severity", "exposure", "criticality", "known_exploitation", "exploit_likelihood", "telemetry"}
        if (
            set(self.weights) != expected
            or any(v < 0 for v in self.weights.values())
            or abs(sum(self.weights.values()) - 1) > 1e-9
        ):
            raise ValueError("Weights must match six features and sum to one")
        if not 0 <= self.control_discount <= 1:
            raise ValueError("Invalid control discount")


def category(score: float) -> str:
    return "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "low"


def analyze(data: Dataset, now: datetime | None = None, config: RiskConfig | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    cfg = config or RiskConfig()
    graph = build_graph(data)
    asset_graph = nx.DiGraph()
    asset_graph.add_nodes_from(a.id for a in data.assets)
    asset_graph.add_edges_from((r.source, r.target) for r in data.relationships if r.enabled)
    reachable = set()
    for a in data.assets:
        if a.internet_exposed:
            reachable |= {a.id} | nx.descendants(asset_graph, a.id)
    assets = {a.id: a for a in data.assets}
    findings = []
    for f in data.findings:
        a = assets[f.asset_id]
        features = {
            "severity": f.cvss / 10,
            "exposure": 1.0 if a.id in reachable else 0.0,
            "criticality": a.criticality,
            "known_exploitation": float(f.known_exploited or False),
            "exploit_likelihood": f.exploit_likelihood if f.exploit_likelihood is not None else 0.5,
            "telemetry": float(f.telemetry or False),
        }
        contributions = {k: round(100 * cfg.weights[k] * v, 4) for k, v in features.items()}
        raw = sum(contributions.values())
        risk = round(raw * (1 - cfg.control_discount * a.control_strength), 2) if f.status == "open" else 0.0
        evidence = fuse(f, now)
        findings.append(
            {
                **f.model_dump(mode="json"),
                **evidence,
                "asset_name": a.name,
                "features": features,
                "contributions": contributions,
                "mitigation": round(raw * cfg.control_discount * a.control_strength, 2),
                "risk": risk,
                "category": category(risk),
                "reachable": a.id in reachable,
                "explanation": f"{f.title}: {risk}/100 modeled risk on {a.name}; "
                f"severity {f.cvss}/10, reachable from public entry: {a.id in reachable}, "
                f"asset criticality {a.criticality}. Evidence confidence {evidence['confidence']}%.",
            }
        )
    findings.sort(key=lambda f: (-f["risk"], f["id"]))
    path_result = paths(data, {f["id"]: f for f in findings})
    critical_ids = {a.id for a in data.assets if a.criticality >= 0.8}
    critical_risks = [f["risk"] for f in findings if f["asset_id"] in critical_ids]
    path_risks = [p["risk"] for p in path_result["items"]]
    # Sum objective makes individual reductions visible; score is bounded portfolio maximum.
    objective = round(sum(critical_risks) + sum(path_risks), 2)
    portfolio = max(critical_risks + path_risks, default=0)
    return {
        "as_of": now.isoformat(),
        "model_version": "0.1.0",
        "risk": portfolio,
        "category": category(portfolio),
        "objective": objective,
        "findings": findings,
        "paths": path_result,
        "assets": [a.model_dump() for a in data.assets],
        "graph": {
            "nodes": [{"id": n, **attrs} for n, attrs in graph.nodes(data=True)],
            "edges": [
                {"source": u, "target": v, "key": k, **attrs} for u, v, k, attrs in graph.edges(keys=True, data=True)
            ],
        },
        "summary": {
            "assets": len(assets),
            "findings": len(findings),
            "high_risk": sum(f["risk"] >= 60 for f in findings),
            "paths": len(path_risks),
            "critical_assets_reachable": len(critical_ids & reachable),
        },
        "assumptions": [
            "Scores are heuristic indices, not breach probabilities.",
            "Connectivity is not proof of exploitation; paths are possible only.",
            "Missing exploit likelihood uses 0.5; missing exploitation and telemetry add no bonus.",
            "Portfolio score is maximum critical finding or modeled path; objective is their sum.",
        ],
    }

"""Reproducible synthetic model-relative comparison. Not independent validation."""

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
import networkx as nx
from app.schemas import Dataset, Intervention
from app.intelligence.risk import analyze
from app.intelligence.counterfactual import recommend, simulate


def run(seeds: int, budget: int):
    raw = json.loads((Path(__file__).resolve().parents[2] / "datasets/synthetic/aurora.json").read_text())
    now = datetime(2026, 1, 2, tzinfo=timezone.utc)
    records = []
    for seed in range(seeds):
        rng = random.Random(seed)
        data = Dataset.model_validate(raw)
        for finding in data.findings:
            finding.cvss = round(rng.uniform(3, 10), 1)
            finding.exploit_likelihood = rng.random()
        analysis = analyze(data, now)
        contextual = {f["id"]: f["risk"] for f in analysis["findings"]}
        graph = nx.DiGraph()
        graph.add_nodes_from(a.id for a in data.assets)
        graph.add_edges_from((r.source, r.target) for r in data.relationships)
        centrality = nx.betweenness_centrality(graph)
        policies = {
            "cvss": sorted(data.findings, key=lambda f: (-f.cvss, f.id)),
            "severity_plus_exploitation": sorted(
                data.findings, key=lambda f: (-(f.cvss + 2 * bool(f.known_exploited)), f.id)
            ),
            "contextual": sorted(data.findings, key=lambda f: (-contextual[f.id], f.id)),
            "centrality": sorted(data.findings, key=lambda f: (-centrality[f.asset_id], -f.cvss, f.id)),
        }
        for name, order in policies.items():
            start = time.perf_counter()
            result = simulate(data, [Intervention(kind="patch", target_id=f.id) for f in order[:budget]], now)
            records.append(
                {
                    "seed": seed,
                    "policy": name,
                    "cost": min(budget, len(order)),
                    "objective_reduction": result["objective_reduction"],
                    "risk_reduction": result["risk_reduction"],
                    "paths_removed": len(result["removed_paths"]),
                    "runtime_ms": round((time.perf_counter() - start) * 1000, 3),
                }
            )
        start = time.perf_counter()
        plan = recommend(data, budget, now)
        actions = [Intervention(kind=a["kind"], target_id=a["target_id"]) for a in plan["plan"]]
        result = simulate(data, actions, now)
        records.append(
            {
                "seed": seed,
                "policy": "cyvra_greedy",
                "cost": plan["cost"],
                "objective_reduction": result["objective_reduction"],
                "risk_reduction": result["risk_reduction"],
                "paths_removed": len(result["removed_paths"]),
                "runtime_ms": round((time.perf_counter() - start) * 1000, 3),
            }
        )
    summary = {
        name: {
            metric: round(mean(r[metric] for r in records if r["policy"] == name), 3)
            for metric in ("objective_reduction", "risk_reduction", "paths_removed", "runtime_ms", "cost")
        }
        for name in sorted({r["policy"] for r in records})
    }
    return {
        "warning": "Synthetic, internal model objective; differing action spaces; no independent outcome labels.",
        "seeds": seeds,
        "budget": budget,
        "clock": now.isoformat(),
        "summary": summary,
        "records": records,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--budget", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.seeds <= 1000 or not 1 <= args.budget <= 10:
        parser.error("Seeds must be 1..1000 and budget 1..10")
    print(json.dumps(run(args.seeds, args.budget), indent=2))

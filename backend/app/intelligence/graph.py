import hashlib
import json

import networkx as nx
from app.schemas import Dataset


def build_graph(data: Dataset) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for a in data.assets:
        graph.add_node(a.id, **a.model_dump(), node_type="ASSET")
    for f in data.findings:
        graph.add_node(f.id, **f.model_dump(mode="json"), node_type="FINDING")
        graph.add_edge(f.asset_id, f.id, key="finding:" + f.id, type="AFFECTED_BY", traversable=False)
    for r in data.relationships:
        if r.enabled:
            graph.add_edge(r.source, r.target, key=r.id, **r.model_dump(), traversable=True)
    return graph


def paths(data: Dataset, scores: dict, max_paths: int = 200, max_hops: int = 6) -> dict:
    assets = {a.id: a for a in data.assets}
    outgoing: dict[str, list] = {}
    for r in sorted(data.relationships, key=lambda r: r.id):
        if r.enabled:
            outgoing.setdefault(r.source, []).append(r)
    entries = sorted(a.id for a in data.assets if a.internet_exposed)
    critical = {a.id for a in data.assets if a.criticality >= 0.8}
    results = []
    truncated = False
    expansions = 0
    # Bounded DFS; relationships are connectivity evidence, never proof of exploitability.
    for entry in entries:
        stack = [(entry, [entry], [])]
        while stack:
            node, nodes, edges = stack.pop()
            expansions += 1
            if expansions > 10000 or len(results) >= max_paths:
                truncated = True
                break
            if node in critical:
                relevant = [s for s in scores.values() if s["asset_id"] in nodes and s["status"] == "open"]
                if relevant:
                    conf = min([s["confidence"] / 100 for s in relevant] + [r.confidence for r in edges])
                    strength = max(s["risk"] for s in relevant) * assets[node].criticality
                    results.append(
                        {
                            "id": "path:"
                            + hashlib.sha256(json.dumps([entry, [r.id for r in edges], node]).encode()).hexdigest()[
                                :24
                            ],
                            "nodes": nodes,
                            "relationship_ids": [r.id for r in edges],
                            "finding_ids": [s["id"] for s in relevant],
                            "risk": round(strength, 2),
                            "confidence": round(conf * 100, 2),
                            "target": node,
                            "classification": "possible",
                            "inferred": any(not r.observed for r in edges),
                        }
                    )
            if len(edges) < max_hops:
                for r in reversed(outgoing.get(node, [])):
                    if r.target not in nodes:
                        stack.append((r.target, nodes + [r.target], edges + [r]))
        if truncated:
            break
    return {
        "items": sorted(results, key=lambda p: (-p["risk"], p["id"])),
        "truncated": truncated,
        "max_paths": max_paths,
        "max_hops": max_hops,
        "expansions": expansions,
    }

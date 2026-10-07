from datetime import datetime, timezone
from app.schemas import Dataset, Intervention
from app.intelligence.risk import analyze


def intervene(data: Dataset, actions: list[Intervention]) -> Dataset:
    changed = data.model_copy(deep=True)
    assets = {a.id: a for a in changed.assets}
    findings = {f.id: f for f in changed.findings}
    rels = {r.id: r for r in changed.relationships}
    for action in actions:
        key = action.target_id
        if action.kind == "patch":
            if key not in findings:
                raise ValueError("Unknown finding")
            findings[key].status = "resolved"
        elif action.kind == "disable_relationship":
            if key not in rels:
                raise ValueError("Unknown relationship")
            rels[key].enabled = False
        else:
            if key not in assets:
                raise ValueError("Unknown asset")
            if action.kind == "remove_exposure":
                assets[key].internet_exposed = False
            elif action.kind == "apply_control":
                assets[key].control_strength = 1
            elif action.kind == "segment":
                assets[key].internet_exposed = False
                for r in changed.relationships:
                    if r.source == key or r.target == key:
                        r.enabled = False
    return changed


def simulate(data: Dataset, actions: list[Intervention], now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    before = analyze(data, now)
    after = analyze(intervene(data, actions), now)
    removed = {p["id"] for p in before["paths"]["items"]} - {p["id"] for p in after["paths"]["items"]}
    return {
        "before": {k: before[k] for k in ("risk", "objective", "summary")},
        "after": {k: after[k] for k in ("risk", "objective", "summary")},
        "risk_reduction": round(before["risk"] - after["risk"], 2),
        "objective_reduction": round(before["objective"] - after["objective"], 2),
        "removed_paths": sorted(removed),
        "actions": [a.model_dump() for a in actions],
        "warning": "Simulation only. No infrastructure changes performed. Modeled effects are not guarantees.",
        "truncated": before["paths"]["truncated"] or after["paths"]["truncated"],
    }


def candidates(data: Dataset) -> list[dict]:
    result = [
        {"kind": "patch", "target_id": f.id, "cost": 1, "impact": "maintenance", "label": "Patch: " + f.title}
        for f in data.findings
        if f.status == "open"
    ]
    result += [
        {
            "kind": "remove_exposure",
            "target_id": a.id,
            "cost": 2,
            "impact": "public access disrupted",
            "label": "Remove exposure: " + a.name,
        }
        for a in data.assets
        if a.internet_exposed
    ]
    result += [
        {
            "kind": "disable_relationship",
            "target_id": r.id,
            "cost": 1,
            "impact": "service connectivity disrupted",
            "label": "Restrict relationship: " + r.id,
        }
        for r in data.relationships
        if r.enabled
    ]
    return result


def recommend(data: Dataset, budget: int = 3, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    baseline = analyze(data, now)
    actions = []
    chosen = []
    remaining = budget
    current = baseline["objective"]
    options = candidates(data)
    # Bound expensive repeated graph analyses; explicitly expose the limitation.
    limited = len(options) > 60
    options = options[:60]
    while remaining:
        best = None
        for option in options:
            if option in chosen or option["cost"] > remaining:
                continue
            action = Intervention(kind=option["kind"], target_id=option["target_id"])
            result = simulate(data, actions + [action], now)
            gain = current - result["after"]["objective"]
            ratio = gain / option["cost"]
            if gain > 0 and (best is None or ratio > best[0]):
                best = (ratio, option, action, result)
        if best is None:
            break
        _, option, action, result = best
        actions.append(action)
        chosen.append(option)
        remaining -= option["cost"]
        current = result["after"]["objective"]
    return {
        "method": "greedy marginal objective reduction per cost; not globally optimal",
        "budget": budget,
        "cost": budget - remaining,
        "plan": chosen,
        "candidate_limit_reached": limited,
        "simulation": simulate(data, actions, now) if actions else None,
    }

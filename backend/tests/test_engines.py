from datetime import datetime, timezone, timedelta
import pytest
from pydantic import ValidationError
from app.schemas import Dataset, Intervention
from app.intelligence.risk import analyze, RiskConfig
from app.intelligence.evidence import fuse
from app.intelligence.graph import build_graph, paths
from app.intelligence.counterfactual import simulate, intervene, recommend

NOW = datetime(2026, 1, 2, tzinfo=timezone.utc)


def test_risk_context_not_cvss(data):
    a = analyze(data, NOW)
    f = {f["id"]: f for f in a["findings"]}
    assert f["F-01"]["risk"] > f["F-06"]["risk"]
    assert f["F-01"]["risk"] == 78.4
    assert f["F-06"]["risk"] == 32.4
    assert all(0 <= f["risk"] <= 100 for f in a["findings"])


def test_confidence_missing_and_freshness(data):
    f = data.findings[0]
    assert fuse(f, NOW)["confidence"] > fuse(f, NOW + timedelta(days=365))["confidence"]
    incomplete = f.model_copy(update={"telemetry": None, "exploit_likelihood": None})
    assert fuse(incomplete, NOW)["confidence"] < fuse(f, NOW)["confidence"]
    assert len(fuse(incomplete, NOW)["missing"]) == 2


def test_duplicate_source_not_independent(data):
    f = data.findings[0]
    original = fuse(f, NOW)
    f.evidence.append(f.evidence[0].model_copy(update={"id": "copy"}))
    assert fuse(f, NOW)["confidence"] == original["confidence"]


def test_contradiction(data):
    f = data.findings[0]
    original = fuse(f, NOW)["confidence"]
    f.evidence.append(
        f.evidence[0].model_copy(update={"id": "opposition", "supports": False, "group": "independent-audit"})
    )
    assert fuse(f, NOW)["confidence"] < original
    assert fuse(f, NOW)["contradictory"]


def test_paths_provenance(data):
    a = analyze(data, NOW)
    assert len(a["paths"]["items"]) == 6
    assert all(p["classification"] == "possible" for p in a["paths"]["items"])
    assert any(p["inferred"] for p in a["paths"]["items"])
    assert all(p["finding_ids"] for p in a["paths"]["items"])
    g = build_graph(data)
    assert g.nodes["F-01"]["node_type"] == "FINDING"
    assert g.has_edge("identity", "db")


def test_patch_nonmutating_and_recomputed(data):
    original = data.model_dump()
    r = simulate(data, [Intervention(kind="patch", target_id="F-01")], NOW)
    assert data.model_dump() == original
    assert r["after"]["objective"] < r["before"]["objective"]


def test_segment_disconnects_paths(data):
    r = simulate(data, [Intervention(kind="segment", target_id="api")], NOW)
    assert r["after"]["summary"]["paths"] == 0
    assert len(r["removed_paths"]) == 6


def test_parallel_edges_and_cycles(data):
    data.relationships.append(data.relationships[0].model_copy(update={"id": "parallel"}))
    data.relationships.append(data.relationships[0].model_copy(update={"id": "cycle", "source": "db", "target": "web"}))
    a = analyze(data, NOW)
    assert len(a["paths"]["items"]) == 9
    assert all(len(p["nodes"]) == len(set(p["nodes"])) for p in a["paths"]["items"])


def test_bounds(data):
    a = analyze(data, NOW)
    p = paths(data, {f["id"]: f for f in a["findings"]}, max_paths=1)
    assert p["truncated"] and len(p["items"]) == 1


def test_invalid_references_and_values(data):
    raw = data.model_dump(mode="json")
    raw["findings"][0]["asset_id"] = "missing"
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)
    raw = data.model_dump(mode="json")
    raw["findings"][0]["cvss"] = 11
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)
    raw = data.model_dump(mode="json")
    raw["assets"].append(raw["assets"][0])
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)


def test_empty_and_missing_evidence():
    a = analyze(Dataset(assets=[], findings=[]), NOW)
    assert a["risk"] == 0 and a["objective"] == 0


def test_unknown_action(data):
    with pytest.raises(ValueError):
        intervene(data, [Intervention(kind="patch", target_id="missing")])


def test_optimizer_budget_and_baseline(data):
    result = recommend(data, 2)
    assert result["cost"] <= 2
    assert result["simulation"]["objective_reduction"] > 0
    assert sum(p["cost"] for p in result["plan"]) == result["cost"]


def test_weight_validation():
    with pytest.raises(ValueError):
        RiskConfig(weights={"severity": 1})


def test_all_resolved(data):
    for f in data.findings:
        f.status = "resolved"
    result = analyze(data, NOW)
    assert result["risk"] == 0 and result["paths"]["items"] == []


def test_remove_one_entry_preserves_alternative(data):
    changed = intervene(data, [Intervention(kind="remove_exposure", target_id="web")])
    result = analyze(changed, NOW)
    assert result["paths"]["items"]
    assert all(p["nodes"][0] == "gateway" for p in result["paths"]["items"])


def test_control_and_relationship_effect(data):
    before = analyze(data, NOW)
    changed = intervene(data, [Intervention(kind="apply_control", target_id="db")])
    result = analyze(changed, NOW)
    b = next(f for f in before["findings"] if f["id"] == "F-05")
    a = next(f for f in result["findings"] if f["id"] == "F-05")
    assert a["risk"] == round(b["risk"] * 0.5, 2)
    simulation = simulate(data, [Intervention(kind="disable_relationship", target_id="R-4")], NOW)
    assert simulation["removed_paths"]


def test_evidence_timestamp_and_unknown_fields(data):
    raw = data.model_dump(mode="json")
    raw["findings"][0]["evidence"][0]["collected_at"] = "2999-01-01T00:00:00Z"
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)
    raw = data.model_dump(mode="json")
    raw["findings"][0]["invented_threat"] = True
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)


def test_zero_evidence_zero_confidence(data):
    data.findings[0].evidence = []
    result = analyze(data, NOW)
    assert next(f for f in result["findings"] if f["id"] == "F-01")["confidence"] == 0


def test_public_critical_asset_self_path(data):
    data.assets[0].criticality = 1
    result = analyze(data, NOW)
    assert any(p["nodes"] == ["web"] for p in result["paths"]["items"])


def test_conflicting_provenance_ids(data):
    raw = data.model_dump(mode="json")
    raw["findings"][1]["evidence"][0]["id"] = raw["findings"][0]["evidence"][0]["id"]
    raw["findings"][1]["evidence"][0]["source"] = "different observation"
    with pytest.raises(ValidationError):
        Dataset.model_validate(raw)

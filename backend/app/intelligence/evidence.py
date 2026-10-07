from datetime import datetime
from math import exp
from app.schemas import Finding


def fuse(finding: Finding, now: datetime) -> dict:
    groups: dict[str, list[tuple[bool, float]]] = {}
    for e in finding.evidence:
        age = max(0, (now - e.collected_at).total_seconds() / 86400)
        groups.setdefault(e.group, []).append((e.supports, e.reliability * exp(-age / 90)))
    support = opposition = 0.0
    for values in groups.values():
        support += max((v for s, v in values if s), default=0)
        opposition += max((v for s, v in values if not s), default=0)
    missing = [
        name for name in ("known_exploited", "exploit_likelihood", "telemetry") if getattr(finding, name) is None
    ]
    completeness = 1 - len(missing) / 3
    coverage = min(1, (support + opposition) / 2)
    agreement = abs(support - opposition) / (support + opposition) if support + opposition else 0
    confidence = round(100 * coverage * agreement * (0.5 + 0.5 * completeness), 2)
    return {
        "confidence": confidence,
        "support": round(support, 3),
        "opposition": round(opposition, 3),
        "missing": missing,
        "contradictory": support > 0 and opposition > 0,
        "evidence_ids": sorted({e.id for e in finding.evidence}),
        "independent_groups": len(groups),
    }

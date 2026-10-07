from datetime import datetime, timezone
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class Evidence(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    source: str = Field(min_length=1, max_length=200)
    collected_at: datetime
    reliability: float = Field(default=0.8, ge=0, le=1)
    supports: bool = True
    group: str = Field(default="scanner", max_length=100)

    @model_validator(mode="after")
    def timestamp(self):
        if self.collected_at.tzinfo is None:
            raise ValueError("Evidence timestamps require a timezone")
        if self.collected_at > datetime.now(timezone.utc):
            raise ValueError("Evidence timestamps cannot be in the future")
        return self


class Asset(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    type: Literal["application", "api", "server", "database", "identity", "repository", "service"] = "server"
    criticality: float = Field(default=0.5, ge=0, le=1)
    internet_exposed: bool = False
    owner: str = Field(default="Unknown", max_length=200)
    environment: str = Field(default="production", max_length=100)
    control_strength: float = Field(default=0, ge=0, le=1)


class Finding(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    asset_id: str
    title: str = Field(min_length=1, max_length=500)
    cvss: float = Field(ge=0, le=10)
    cve: str | None = Field(default=None, max_length=100)
    known_exploited: bool | None = None
    exploit_likelihood: float | None = Field(default=None, ge=0, le=1)
    telemetry: bool | None = None
    status: Literal["open", "resolved"] = "open"
    evidence: list[Evidence] = Field(default_factory=list, max_length=50)


class Relationship(StrictModel):
    id: str = Field(min_length=1, max_length=100)
    source: str
    target: str
    type: Literal["CONNECTS_TO", "DEPENDS_ON", "HAS_ACCESS_TO", "TRUSTS", "HOSTS"] = "CONNECTS_TO"
    confidence: float = Field(default=0.8, ge=0, le=1)
    observed: bool = True
    evidence_ids: list[str] = Field(default_factory=list, max_length=50)
    enabled: bool = True


class Dataset(StrictModel):
    assets: list[Asset] = Field(max_length=200)
    findings: list[Finding] = Field(max_length=2000)
    relationships: list[Relationship] = Field(default_factory=list, max_length=1000)

    @model_validator(mode="after")
    def references(self):
        for records in (self.assets, self.findings, self.relationships):
            ids = [r.id for r in records]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate record IDs")
        assets = {a.id for a in self.assets}
        evidence_records = {}
        for finding in self.findings:
            for item in finding.evidence:
                if item.id in evidence_records and evidence_records[item.id] != item.model_dump():
                    raise ValueError("Repeated evidence IDs must identify the same observation")
                evidence_records[item.id] = item.model_dump()
        evidence = set(evidence_records)
        if assets & {f.id for f in self.findings}:
            raise ValueError("Asset and finding IDs must be disjoint")
        if any(f.asset_id not in assets for f in self.findings):
            raise ValueError("Finding references unknown asset")
        if any(r.source not in assets or r.target not in assets for r in self.relationships):
            raise ValueError("Relationship references unknown asset")
        if any(set(r.evidence_ids) - evidence for r in self.relationships):
            raise ValueError("Relationship references unknown evidence")
        return self


class ProjectCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)


class Intervention(StrictModel):
    kind: Literal["patch", "remove_exposure", "segment", "disable_relationship", "apply_control"]
    target_id: str


class SimulationRequest(StrictModel):
    actions: list[Intervention] = Field(min_length=1, max_length=20)


class OptimizeRequest(StrictModel):
    budget: int = Field(default=3, ge=1, le=10)


class Question(StrictModel):
    question: str = Field(min_length=1, max_length=2000)

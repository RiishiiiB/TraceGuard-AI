from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


class Event(BaseModel):
    id: str
    row: int = Field(description="Data row number in the uploaded CSV (header = row 1)")
    timestamp: datetime
    username: str
    source_ip: str
    event_type: str
    status: str
    finding_ids: list[str] = []
    suspicious: bool = False


class EvidenceItem(BaseModel):
    label: str
    value: str


class ScoreFactor(BaseModel):
    factor: str
    points: int
    note: str


class Finding(BaseModel):
    id: str
    rule_id: str
    rule_name: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    title: str
    explanation: str
    caveat: str
    usernames: list[str]
    source_ips: list[str]
    first_seen: datetime
    last_seen: datetime
    event_ids: list[str]
    evidence: list[EvidenceItem]
    score_factors: list[ScoreFactor]
    incident_id: Optional[str] = None


class Incident(BaseModel):
    id: str
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    first_seen: datetime
    last_seen: datetime
    usernames: list[str]
    source_ips: list[str]
    rule_ids: list[str]
    finding_ids: list[str]
    event_count: int
    finding_count: int
    summary: str
    correlation_basis: list[str]
    score_factors: list[ScoreFactor]
    suggested_steps: list[str]
    timeline: list[Event]


class DatasetSummary(BaseModel):
    total_events: int
    suspicious_events: int
    findings_count: int
    incidents_count: int
    high_critical_incidents: int
    incidents_by_severity: dict[str, int]
    findings_by_severity: dict[str, int]
    unique_users: int
    unique_ips: int
    first_event: Optional[datetime] = None
    last_event: Optional[datetime] = None
    rows_received: int
    rows_skipped: int
    duplicates_removed: int
    warnings: list[str] = []
    row_errors: list[str] = []


class AnalysisResult(BaseModel):
    analysis_id: str
    created_at: datetime
    source_name: str
    is_demo: bool
    data_notice: str
    summary: DatasetSummary
    events: list[Event]
    findings: list[Finding]
    incidents: list[Incident]
    config: dict


class RuleInfo(BaseModel):
    id: str
    name: str
    description: str
    logic: str
    parameters: dict
    base_score: int
    benign_causes: str


class RulesResponse(BaseModel):
    rules: list[RuleInfo]
    scoring_model: dict
    correlation_model: dict
    limitations: list[str]

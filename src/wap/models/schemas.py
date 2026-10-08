from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class CrawlStatus(str, Enum):
    pending = "pending"
    success = "success"
    failed = "failed"
    skipped = "skipped"


class ParseStatus(str, Enum):
    pending = "pending"
    success = "success"
    failed = "failed"
    needs_review = "needs_review"


class EvidenceType(str, Enum):
    direct = "direct"
    inferred = "inferred"
    mentioned = "mentioned"
    unknown = "unknown"


class MappingStatus(str, Enum):
    retained = "retained"
    excluded = "excluded"
    unmatched = "unmatched"
    pending_review = "pending_review"


class MappingRole(str, Enum):
    primary = "primary"
    secondary = "secondary"
    sole = "sole"


class LinkedResource(BaseModel):
    url: str
    kind: str = "page"
    title: Optional[str] = None
    local_path: Optional[str] = None


class DiscoveredItem(BaseModel):
    source_id: str
    title: str
    url: str
    task_name: Optional[str] = None
    benchmark_name: Optional[str] = None
    published_at: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WriteupRecord(BaseModel):
    writeup_id: str
    source_id: str
    source_name: str
    title: str
    canonical_url: str
    task_name: Optional[str] = None
    benchmark_name: Optional[str] = None
    published_at: Optional[str] = None
    crawled_at: datetime
    content_format: str = "markdown"
    raw_content_path: str
    parsed_content_path: Optional[str] = None
    content_hash: str
    linked_resources: list[LinkedResource] = Field(default_factory=list)
    crawl_status: CrawlStatus = CrawlStatus.success
    parse_status: ParseStatus = ParseStatus.pending
    version: int = 1
    error: Optional[str] = None


class ChainStatus(str, Enum):
    selected = "selected"
    excluded = "excluded"
    unknown = "unknown"
    pending = "pending"


class AttackStep(BaseModel):
    step_id: str
    writeup_id: str
    sequence: int
    action: str
    target: Optional[str] = None
    input: Optional[str] = None
    output: Optional[str] = None
    purpose: Optional[str] = None
    prerequisite: Optional[str] = None
    evidence: str
    evidence_location: str
    evidence_type: EvidenceType
    inference: bool = False
    confidence: float = 0.0
    chunk_id: Optional[str] = None
    step_type: str = "other"
    phase: str = "其他"
    # Successful-attack-chain annotation (separate from ATT&CK mapping)
    chain_status: str = "pending"  # selected|excluded|unknown|pending
    chain_reason: str = ""
    path_id: str = ""
    depends_on_json: str = "[]"


class PathEdge(BaseModel):
    from_step_id: str
    to_step_id: str
    relation: str


class TechniqueRef(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    description: str = ""
    retained: bool = True
    # display metadata (filled by attck_meta.enrich_ref)
    technique_name_en: str = ""
    technique_name_zh: str = ""
    tactic_en: str = ""
    tactic_zh: str = ""


class TechniqueMapping(BaseModel):
    mapping_id: str
    step_id: str
    writeup_id: str
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    mapping_status: MappingStatus
    mapping_type: str = "behavior"
    mapping_reason: str
    evidence: str
    evidence_location: str
    confidence: float
    review_status: str = "open"
    mapping_role: str = "sole"
    supporting_behavior: str = ""
    # Stage-2 verification fields (auditability)
    behavior_observed: str = ""
    definition_match: bool = False
    required_conditions_met: bool = False
    evidence_directness: str = "direct"  # direct|indirect|inferred
    mapping_evidence: str = ""
    counterevidence: str = ""


class ValidationIssue(BaseModel):
    issue_id: str
    writeup_id: Optional[str] = None
    step_id: Optional[str] = None
    mapping_id: Optional[str] = None
    severity: str
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)

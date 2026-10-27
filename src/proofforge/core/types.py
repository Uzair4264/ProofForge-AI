"""Shared data structures for ProofForge AI.

These are the canonical types referenced throughout the pipeline. They use
Pydantic for validation and (de)serialization to/from session JSON. Enum values
are stored as their string ``value`` so session files stay human-readable.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field as PydField


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
class EvidenceType(str, Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    SCREENSHOT = "screenshot"
    CODE_SNIPPET = "code_snippet"
    REPRO_STEPS = "repro_steps"
    VIDEO = "video"
    LOG_OUTPUT = "log_output"


class SensitivityLevel(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"      # contains PoC details
    RESTRICTED = "restricted"    # contains PII or secrets


class Evidence(BaseModel):
    id: str                                  # e.g., "ev-001"
    type: EvidenceType
    source_path: str                         # stored as string for JSON portability
    content_hash: str                        # SHA-256 of the content
    sensitivity: SensitivityLevel = SensitivityLevel.SENSITIVE
    extracted_text: Optional[str] = None     # searchable content
    metadata: dict[str, Any] = PydField(default_factory=dict)
    captured_at: Optional[datetime] = None
    notes: Optional[str] = None


# --------------------------------------------------------------------------- #
# Fields (adaptive elicitation)
# --------------------------------------------------------------------------- #
ImpactBasis = Literal["demonstrated", "inferred"]


class FieldState(str, Enum):
    PENDING = "pending"              # not yet processed
    INFERRED = "inferred"            # value set by inference engine
    CONFIRMED = "confirmed"          # user accepted the inferred value
    USER_PROVIDED = "user_provided"  # user typed it directly
    SKIPPED = "skipped"              # user explicitly skipped (warning issued)
    UNKNOWN = "unknown"              # user said "I don't know"


class Field(BaseModel):
    id: str                                  # e.g., "rendering_context"
    label: str
    field_type: str                          # "url", "choice", "long_text", ...
    value: Optional[Any] = None
    state: FieldState = FieldState.PENDING
    confidence: Optional[float] = None       # set when state == INFERRED
    inference_reasoning: Optional[str] = None
    is_required: bool = True
    # For impact: did the evidence demonstrate it, or is it inferred / potential?
    basis: Optional[ImpactBasis] = None


# --------------------------------------------------------------------------- #
# Claims and provenance
# --------------------------------------------------------------------------- #
class ClaimCategory(str, Enum):
    VULNERABILITY_ASSERTION = "vuln_assertion"
    IMPACT_ASSERTION = "impact_assertion"
    REPRODUCTION = "reproduction"
    SEVERITY_JUSTIFICATION = "severity_just"
    REMEDIATION = "remediation"


class Claim(BaseModel):
    id: str                                  # e.g., "claim-A"
    category: ClaimCategory
    text: str
    evidence_ids: list[str] = PydField(default_factory=list)
    author: str = "user"                     # "user", "inferred", "llm_polished"
    confidence: Optional[float] = None
    basis: Optional[ImpactBasis] = None      # impact claims only


class ProvenanceLink(BaseModel):
    claim_id: str
    evidence_id: str
    relation: str = "supports"               # "supports", "demonstrates", "contradicts"
    verified: bool = False                   # confirmed by the LLM verifier?
    verifier_notes: Optional[str] = None


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
CheckStatus = Literal["pass", "warn", "block"]


class Report(BaseModel):
    vuln_class: str
    subtype: Optional[str] = None
    title: Optional[str] = None
    fields: dict[str, Field] = PydField(default_factory=dict)
    claims: list[Claim] = PydField(default_factory=list)
    provenance: list[ProvenanceLink] = PydField(default_factory=list)
    severity_vector: Optional[str] = None
    severity_score: Optional[float] = None
    severity_rating: Optional[str] = None
    # Outcome of the last full `verify` / `check` run; None = not run since the
    # report or its evidence last changed.
    integrity_status: Optional[CheckStatus] = None
    compliance_status: Optional[CheckStatus] = None

    def field_value(self, field_id: str) -> Any:
        f = self.fields.get(field_id)
        return f.value if f else None

    def reset_checks(self) -> None:
        self.integrity_status = None
        self.compliance_status = None


# --------------------------------------------------------------------------- #
# Session
# --------------------------------------------------------------------------- #
class Session(BaseModel):
    id: str
    program_id: str
    created_at: datetime
    vuln_class: Optional[str] = None
    subtype: Optional[str] = None
    evidence: list[Evidence] = PydField(default_factory=list)
    report: Optional[Report] = None

    def next_evidence_id(self) -> str:
        return f"ev-{len(self.evidence) + 1:03d}"


# --------------------------------------------------------------------------- #
# Inference result (LLM contract for Stage 2)
# --------------------------------------------------------------------------- #
class InferenceResult(BaseModel):
    value: Any
    confidence: float = 0.0
    reasoning: Optional[str] = None


# --------------------------------------------------------------------------- #
# Verification verdicts (Stage 4)
# --------------------------------------------------------------------------- #
class VerificationVerdict(BaseModel):
    supports: Literal["true", "false", "partial"] | bool
    confidence: float = 0.0
    reasoning: Optional[str] = None
    missing_for_full_support: Optional[str] = None


# --------------------------------------------------------------------------- #
# Check results (Stages 4 & 5)
# --------------------------------------------------------------------------- #
class CheckResult(BaseModel):
    name: str
    status: CheckStatus
    message: str
    overridable: bool = True
    details: dict[str, Any] = PydField(default_factory=dict)


class ComplianceReport(BaseModel):
    program_id: str
    checks_run: list[CheckResult] = PydField(default_factory=list)
    overall_status: CheckStatus = "pass"
    actionable_items: list[str] = PydField(default_factory=list)


class IntegrityReport(BaseModel):
    checks_run: list[CheckResult] = PydField(default_factory=list)
    overall_status: CheckStatus = "pass"
    actionable_items: list[str] = PydField(default_factory=list)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class AuditEntry(BaseModel):
    sequence: int
    timestamp: str                           # ISO-8601 string for stable hashing
    previous_hash: str
    entry_hash: str = ""                     # filled in by the chain
    actor: str                               # "system", "user", "llm", "inference"
    action: str
    target: str
    result: str
    details: dict[str, Any] = PydField(default_factory=dict)

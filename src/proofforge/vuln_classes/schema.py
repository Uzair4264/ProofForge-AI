"""Pydantic schema for vuln-class templates (spec §5.6).

A vuln class is *data*: this schema validates the YAML in ``templates/`` so a
contributor can add a vulnerability class without writing Python.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class InferenceSpec(BaseModel):
    from_evidence: list[str] = Field(default_factory=list)
    llm_prompt: str
    confidence_threshold: float = 0.7
    mode: str = "auto"  # "auto" | "suggest_only"


class HelpSpec(BaseModel):
    short: Optional[str] = None
    long: Optional[str] = None
    examples: list[str] = Field(default_factory=list)


class FieldSpec(BaseModel):
    id: str
    label: str
    field_type: str
    options: list[str] = Field(default_factory=list)
    validation: Optional[str] = None
    editor: bool = False
    is_required: bool = True
    inference: Optional[InferenceSpec] = None
    help: Optional[HelpSpec] = None


class RequiredEvidenceSpec(BaseModel):
    type: str
    description: str = ""
    required: bool = True
    note: Optional[str] = None


# A condition on resolved field values: {field_id: [accepted values]}. Every
# listed field must hold one of its values (case-insensitive); empty = always.
FieldConditions = dict[str, list[str]]


class CeilingTier(BaseModel):
    """A ceiling that replaces the default when its field conditions hold."""

    when: FieldConditions
    ceiling: str
    note: Optional[str] = None


class LiftRule(BaseModel):
    """Lets one CVSS metric rise above the ceiling, up to ``to``.

    Applies only when ``when`` holds and, if ``demonstrated``, an impact claim
    is marked demonstrated and linked to evidence.
    """

    metric: str
    to: str
    when: FieldConditions = Field(default_factory=dict)
    demonstrated: bool = True
    note: Optional[str] = None


class SeverityHints(BaseModel):
    default_cvss_v31: Optional[str] = None
    # First matching tier sets the ceiling; none matching = default_cvss_v31.
    ceiling_tiers: list[CeilingTier] = Field(default_factory=list)
    # None = legacy rule: any demonstrated, linked impact lifts every metric.
    lift_rules: Optional[list[LiftRule]] = None
    notes: Optional[str] = None


class AcceptanceRule(BaseModel):
    """A finding shape platforms usually reject. Matching it warns, never blocks."""

    when: FieldConditions
    message: str


class VulnClassTemplate(BaseModel):
    vuln_class: str
    display_name: str
    cwe: Optional[str] = None
    subtypes: list[str] = Field(default_factory=list)
    required_fields: list[FieldSpec] = Field(default_factory=list)
    required_evidence: list[RequiredEvidenceSpec] = Field(default_factory=list)
    severity_hints: Optional[SeverityHints] = None
    verifier_focus: list[str] = Field(default_factory=list)
    # Deterministic evidence checks run by `verify` (names in vuln_classes/checks.py).
    evidence_checks: list[str] = Field(default_factory=list)
    # Pre-check: commonly rejected findings and how to upgrade them (`check`).
    never_accepted: list[AcceptanceRule] = Field(default_factory=list)

    def field(self, field_id: str) -> Optional[FieldSpec]:
        for f in self.required_fields:
            if f.id == field_id:
                return f
        return None

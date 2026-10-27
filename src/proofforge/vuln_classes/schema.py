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


class SeverityHints(BaseModel):
    default_cvss_v31: Optional[str] = None
    notes: Optional[str] = None


class VulnClassTemplate(BaseModel):
    vuln_class: str
    display_name: str
    cwe: Optional[str] = None
    subtypes: list[str] = Field(default_factory=list)
    required_fields: list[FieldSpec] = Field(default_factory=list)
    required_evidence: list[RequiredEvidenceSpec] = Field(default_factory=list)
    severity_hints: Optional[SeverityHints] = None
    verifier_focus: list[str] = Field(default_factory=list)

    def field(self, field_id: str) -> Optional[FieldSpec]:
        for f in self.required_fields:
            if f.id == field_id:
                return f
        return None

"""Pydantic schema for program rule packs (spec §5.5)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class Scope(BaseModel):
    in_scope_assets: list[str] = Field(default_factory=list)
    out_of_scope_assets: list[str] = Field(default_factory=list)
    in_scope_vuln_types: list[str] = Field(default_factory=list)
    out_of_scope_vuln_types: list[str] = Field(default_factory=list)


class ForbiddenPattern(BaseModel):
    type: str = "regex"
    pattern: str
    description: str = ""


class ForbiddenContent(BaseModel):
    patterns: list[ForbiddenPattern] = Field(default_factory=list)
    llm_checks: list[str] = Field(default_factory=list)


class DisclosureRules(BaseModel):
    embargo_days: int = 0
    public_disclosure_requires_approval: bool = False
    must_include_disclosure_statement: bool = False


class OutputPreferences(BaseModel):
    format: str = "markdown_generic"
    include_cvss_vector: bool = True
    include_screenshots: str = "inline"


class RulePack(BaseModel):
    program_id: str
    program_name: str = ""
    platform: str = ""
    last_updated: Optional[str] = None
    source_url: Optional[str] = None
    scope: Scope = Field(default_factory=Scope)
    required_fields: list[str] = Field(default_factory=list)
    severity_framework: str = "cvss_v3.1"
    severity_overrides: dict = Field(default_factory=dict)
    forbidden_content: ForbiddenContent = Field(default_factory=ForbiddenContent)
    disclosure_rules: DisclosureRules = Field(default_factory=DisclosureRules)
    output_preferences: OutputPreferences = Field(default_factory=OutputPreferences)

"""Shared helpers for renderers.

Renderers turn a ``Report`` (plus its evidence) into a dual-audience document:
a triager-facing summary up top and developer-facing detail below, with stable
evidence references.
"""

from __future__ import annotations

from ..core.types import Claim, Evidence, Report

_ATTRIBUTION_PREFIX = "_Drafted with ProofForge AI — an evidence-integrity assistant. "


def attribution(report: Report) -> str:
    """Footer that states only what the integrity/compliance checks actually showed."""
    statuses = (report.integrity_status, report.compliance_status)
    if statuses == ("pass", "pass"):
        outcome = "All claims passed integrity and compliance checks against the attached evidence._"
    elif None in statuses:
        outcome = ("Integrity and compliance checks have not both been run on this version; "
                   "review each claim against the attached evidence._")
    else:
        outcome = ("Integrity or compliance checks flagged issues; "
                   "review each claim against the attached evidence._")
    return _ATTRIBUTION_PREFIX + outcome


# Fields with their own report sections; everything else is listed as a detail.
SECTION_FIELDS = ("affected_endpoint", "impact_description", "remediation")


def detail_fields(report: Report):
    """(field_id, Field) pairs for the generic detail list, skipping empty values."""
    for fid, field in report.fields.items():
        if fid in SECTION_FIELDS or field.value in (None, ""):
            continue
        yield fid, field


def claims_by_category(report: Report, category: str) -> list[Claim]:
    return [c for c in report.claims if c.category.value == category]


def evidence_index(evidence: list[Evidence]) -> str:
    lines = []
    for ev in evidence:
        desc = ev.notes or (ev.extracted_text or "").splitlines()[:1]
        desc_str = desc[0] if isinstance(desc, list) and desc else (ev.notes or "")
        lines.append(f"- **{ev.id}** ({ev.type.value}) — `{ev.content_hash[:12]}…` {desc_str}")
    return "\n".join(lines)

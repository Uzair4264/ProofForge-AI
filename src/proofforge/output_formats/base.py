"""Shared helpers for renderers.

Renderers turn a ``Report`` (plus its evidence) into a dual-audience document:
a triager-facing summary up top and developer-facing detail below, with stable
evidence references.
"""

from __future__ import annotations

from ..core.types import Claim, Evidence, Report

ATTRIBUTION = (
    "_Drafted with ProofForge AI — an evidence-integrity assistant. "
    "All claims are backed by the attached evidence; nothing was fabricated._"
)


def claims_by_category(report: Report, category: str) -> list[Claim]:
    return [c for c in report.claims if c.category.value == category]


def evidence_index(evidence: list[Evidence]) -> str:
    lines = []
    for ev in evidence:
        desc = ev.notes or (ev.extracted_text or "").splitlines()[:1]
        desc_str = desc[0] if isinstance(desc, list) and desc else (ev.notes or "")
        lines.append(f"- **{ev.id}** ({ev.type.value}) — `{ev.content_hash[:12]}…` {desc_str}")
    return "\n".join(lines)

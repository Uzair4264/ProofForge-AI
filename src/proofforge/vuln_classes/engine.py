"""Generic elicitation/claim engine.

The same engine runs every vuln class; the differences live in the YAML template.
It consumes a template + resolved ``Field`` values and produces a structured set
of ``Claim`` objects linked to the evidence that supports them.
"""

from __future__ import annotations

from ..core.types import Claim, ClaimCategory, Evidence, Field, FieldState
from .schema import VulnClassTemplate


def _author_for(field: Field) -> str:
    if field.state in (FieldState.INFERRED, FieldState.CONFIRMED):
        return "inferred"
    return "user"


# Canonical field ids shared by every template (see plan / enforcer conventions).
ENDPOINT_FIELD = "affected_endpoint"
IMPACT_FIELD = "impact_description"
# Optional; rendered in its own section, not as part of the vulnerability assertion.
REMEDIATION_FIELD = "remediation"

_RESOLVED_STATES = (FieldState.INFERRED, FieldState.CONFIRMED, FieldState.USER_PROVIDED)


def _is_resolved(field: Field | None) -> bool:
    return bool(field and field.state in _RESOLVED_STATES and field.value not in (None, ""))


def build_claims(
    template: VulnClassTemplate,
    fields: dict[str, Field],
    evidence: list[Evidence],
    *,
    subtype: str | None = None,
) -> list[Claim]:
    """Derive claims from filled template fields (class-agnostic).

    The vulnerability assertion is built from the affected endpoint plus every
    other resolved field (except the narrative impact). The impact field becomes
    an impact assertion; any repro-steps evidence becomes a reproduction claim.
    Each claim is linked to the evidence it depends on.
    """
    all_evidence_ids = [e.id for e in evidence]
    http_evidence_ids = [
        e.id for e in evidence if e.type.value in ("http_request", "http_response")
    ]
    claims: list[Claim] = []

    endpoint = fields.get(ENDPOINT_FIELD)

    # 1. Vulnerability assertion — generic across vuln classes.
    subtype_str = f"{subtype} " if subtype else ""
    vuln_text = f"The target is vulnerable to {subtype_str}{template.display_name}"
    if _is_resolved(endpoint):
        vuln_text += f" at {endpoint.value}"

    detail_bits: list[str] = []
    for spec in template.required_fields:
        if spec.id in (ENDPOINT_FIELD, IMPACT_FIELD, REMEDIATION_FIELD):
            continue
        field = fields.get(spec.id)
        if _is_resolved(field):
            detail_bits.append(f"{spec.label.lower()}: {field.value}")
    if detail_bits:
        vuln_text += " (" + "; ".join(detail_bits) + ")"

    claims.append(
        Claim(
            id="claim-vuln",
            category=ClaimCategory.VULNERABILITY_ASSERTION,
            text=vuln_text.strip(),
            evidence_ids=http_evidence_ids or all_evidence_ids,
            author="inferred" if (endpoint and endpoint.state != FieldState.USER_PROVIDED) else "user",
            confidence=endpoint.confidence if endpoint else None,
        )
    )

    # 2. Impact assertion.
    impact = fields.get("impact_description")
    if impact and impact.value:
        claims.append(
            Claim(
                id="claim-impact",
                category=ClaimCategory.IMPACT_ASSERTION,
                text=str(impact.value),
                evidence_ids=all_evidence_ids,
                author=_author_for(impact),
                confidence=impact.confidence,
                basis=impact.basis,
            )
        )

    # 3. Reproduction (from repro-steps evidence, if present).
    repro_ids = [e.id for e in evidence if e.type.value == "repro_steps"]
    if repro_ids:
        claims.append(
            Claim(
                id="claim-repro",
                category=ClaimCategory.REPRODUCTION,
                text="Reproduction steps as documented in the attached evidence.",
                evidence_ids=repro_ids,
                author="user",
            )
        )

    return claims

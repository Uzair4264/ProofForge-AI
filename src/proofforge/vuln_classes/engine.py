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


def _linked_evidence(fields: list[Field], known: set[str]) -> list[str]:
    """Ordered union of the fields' evidence ids that exist in the session."""
    ids: list[str] = []
    for field in fields:
        for ev_id in field.evidence_ids:
            if ev_id in known and ev_id not in ids:
                ids.append(ev_id)
    return ids


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

    Each claim links only to the evidence its fields actually came from
    (``Field.evidence_ids``). Typed-in values carry no links, so a claim built
    only from them is an orphan until evidence is linked explicitly.
    """
    known = {e.id for e in evidence}
    claims: list[Claim] = []

    endpoint = fields.get(ENDPOINT_FIELD)

    # 1. Vulnerability assertion — generic across vuln classes.
    subtype_str = f"{subtype} " if subtype else ""
    vuln_text = f"The target is vulnerable to {subtype_str}{template.display_name}"
    vuln_sources: list[Field] = []
    if _is_resolved(endpoint):
        vuln_text += f" at {endpoint.value}"
        vuln_sources.append(endpoint)

    detail_bits: list[str] = []
    for spec in template.required_fields:
        if spec.id in (ENDPOINT_FIELD, IMPACT_FIELD, REMEDIATION_FIELD):
            continue
        field = fields.get(spec.id)
        if _is_resolved(field):
            detail_bits.append(f"{spec.label.lower()}: {field.value}")
            vuln_sources.append(field)
    if detail_bits:
        vuln_text += " (" + "; ".join(detail_bits) + ")"

    claims.append(
        Claim(
            id="claim-vuln",
            category=ClaimCategory.VULNERABILITY_ASSERTION,
            text=vuln_text.strip(),
            evidence_ids=_linked_evidence(vuln_sources, known),
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
                evidence_ids=_linked_evidence([impact], known),
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

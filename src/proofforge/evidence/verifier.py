"""LLM-backed claim/evidence verification (Gap-1, Stage 4).

Every function returns a structured verdict, never freeform text. All verdicts
are advisory — the human researcher confirms (spec §7.3.5). Verdict values are
parsed strictly: an unrecognizable ``supports`` / ``overreach`` comes back as
None ("unverified"), never as a guess. Backend failures raise ``LLMError``.
"""

from __future__ import annotations

from typing import Any

from ..core.types import Claim, Evidence
from ..inference.prompts import render_prompt
from ..llm_backends.base import LLMBackend
from ..llm_backends.verdicts import parse_bool, parse_confidence, parse_support


def _truncate(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]..."


def verify_claim_evidence(
    backend: LLMBackend, claim: Claim, evidence: Evidence
) -> dict[str, Any]:
    """Ask the LLM whether a single evidence item supports a claim."""
    prompt = render_prompt(
        "verify_claim",
        claim_text=claim.text,
        evidence_type=evidence.type.value,
        evidence_content=_truncate(evidence.extracted_text),
    )
    result = backend.complete(prompt, expected_format="json")
    return {
        "claim_id": claim.id,
        "evidence_id": evidence.id,
        "supports": parse_support(result.get("supports")),
        "confidence": parse_confidence(result.get("confidence")),
        "reasoning": str(result.get("reasoning") or ""),
        "missing_for_full_support": str(result.get("missing_for_full_support") or ""),
    }


def detect_overreach(
    backend: LLMBackend, claim: Claim, evidence: list[Evidence]
) -> dict[str, Any]:
    """Ask the LLM whether a claim extrapolates beyond its evidence."""
    joined = "\n\n".join(
        f"[{e.id} | {e.type.value}]\n{_truncate(e.extracted_text, 2000)}" for e in evidence
    )
    prompt = render_prompt(
        "detect_overreach",
        claim_text=claim.text,
        evidence_content=joined,
    )
    result = backend.complete(prompt, expected_format="json")
    return {
        "claim_id": claim.id,
        "overreach": parse_bool(result.get("overreach")),
        "confidence": parse_confidence(result.get("confidence")),
        "reasoning": str(result.get("reasoning") or ""),
    }

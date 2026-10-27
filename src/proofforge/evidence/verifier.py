"""LLM-backed claim/evidence verification (Gap-1, Stage 4).

Every function returns a structured verdict, never freeform text. All verdicts
are advisory — the human researcher confirms (spec §7.3.5).
"""

from __future__ import annotations

from typing import Any

from ..core.types import Claim, Evidence
from ..inference.prompts import render_prompt
from ..llm_backends.base import LLMBackend


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
    supports = result.get("supports", "false")
    return {
        "claim_id": claim.id,
        "evidence_id": evidence.id,
        "supports": supports,
        "confidence": float(result.get("confidence", 0.0)),
        "reasoning": result.get("reasoning", ""),
        "missing_for_full_support": result.get("missing_for_full_support", ""),
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
        "overreach": bool(result.get("overreach", False)),
        "confidence": float(result.get("confidence", 0.0)),
        "reasoning": result.get("reasoning", ""),
    }

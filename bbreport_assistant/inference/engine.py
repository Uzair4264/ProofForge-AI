"""The inference engine (Stage 2).

Walks every field in a vuln-class template, and for each field with an
``inference`` block, gathers the relevant evidence, renders the field's prompt,
calls the LLM, and applies the confidence threshold (spec §8.2). It never blocks
the workflow: any failure simply leaves the field PENDING so the user is asked.
"""

from __future__ import annotations

from typing import Callable

from ..core.exceptions import LLMError, LLMFormatError
from ..core.types import Evidence, Field, FieldState
from ..llm_backends.base import LLMBackend
from ..vuln_classes.schema import FieldSpec, VulnClassTemplate
from . import confidence as conf

# A hook the orchestrator can use to log each inference attempt.
InferenceObserver = Callable[[str, Field], None]


def _truncate(text: str | None, limit: int = 4000) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[:limit] + "\n...[truncated]..."


def _relevant_evidence(evidence: list[Evidence], wanted_types: list[str]) -> list[Evidence]:
    if not wanted_types:
        return list(evidence)
    return [e for e in evidence if e.type.value in wanted_types]


def _render_evidence_block(evidence: list[Evidence]) -> str:
    return "\n\n".join(
        f"[{e.id} | {e.type.value}]\n{_truncate(e.extracted_text)}" for e in evidence
    )


def infer_field(
    backend: LLMBackend,
    spec: FieldSpec,
    evidence: list[Evidence],
) -> Field:
    """Run inference for a single field, returning a populated ``Field``."""
    base = Field(
        id=spec.id,
        label=spec.label,
        field_type=spec.field_type,
        state=FieldState.PENDING,
        is_required=spec.is_required,
    )
    if spec.inference is None:
        return base

    relevant = _relevant_evidence(evidence, spec.inference.from_evidence)
    if not relevant:
        base.inference_reasoning = (
            f"No evidence of type {spec.inference.from_evidence} available."
        )
        return base

    from .prompts import render_prompt

    try:
        prompt = render_prompt(
            spec.inference.llm_prompt,
            field_label=spec.label,
            options=", ".join(spec.options) if spec.options else "",
            evidence=_render_evidence_block(relevant),
        )
        result = backend.complete(prompt, expected_format="json")
    except (LLMError, LLMFormatError) as exc:
        base.inference_reasoning = f"Inference failed: {exc}"
        return base

    value = result.get("value")
    confidence = float(result.get("confidence", 0.0))
    reasoning = result.get("reasoning", "")

    # suggest_only fields (e.g., impact draft) are always presented as a draft
    # for review and never auto-confirmed, regardless of confidence.
    if spec.inference.mode == "suggest_only":
        base.value = value
        base.state = FieldState.INFERRED
        base.confidence = confidence
        base.inference_reasoning = reasoning
        return base

    if value is not None and conf.is_confident(confidence, spec.inference.confidence_threshold):
        base.value = value
        base.state = FieldState.INFERRED
        base.confidence = confidence
        base.inference_reasoning = reasoning
    else:
        base.inference_reasoning = (
            f"Low-confidence inference ({confidence:.2f}): {value!r}"
            if value is not None
            else (reasoning or "Model was uncertain.")
        )
    return base


def run_inference(
    backend: LLMBackend,
    template: VulnClassTemplate,
    evidence: list[Evidence],
    *,
    observer: InferenceObserver | None = None,
) -> dict[str, Field]:
    """Infer every field in the template. Sequential in v0 (parallel later)."""
    inferred: dict[str, Field] = {}
    for spec in template.required_fields:
        field = infer_field(backend, spec, evidence)
        inferred[spec.id] = field
        if observer is not None:
            observer(spec.id, field)
    return inferred

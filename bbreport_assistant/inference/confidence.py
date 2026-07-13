"""Confidence thresholding for inferred fields (spec §8.3)."""

from __future__ import annotations

DEFAULT_THRESHOLD = 0.7


def is_confident(confidence: float | None, threshold: float = DEFAULT_THRESHOLD) -> bool:
    """A field is confidently inferred iff confidence >= its threshold."""
    if confidence is None:
        return False
    return confidence >= threshold


def confidence_label(confidence: float | None) -> str:
    """Human-readable bucket for display in the confirmation UI."""
    if confidence is None:
        return "unknown"
    if confidence >= 0.85:
        return "high"
    if confidence >= 0.7:
        return "medium"
    return "low"

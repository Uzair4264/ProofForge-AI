"""Strict parsing of the values an LLM returns inside its JSON verdicts.

Models return booleans as strings (``"false"``), confidences as words
(``"high"``), and ``"uncertain"`` where they mean "no answer". Python's
truthiness gets all three wrong (``bool("false") is True``), so every verdict
field is read through these helpers instead of ``bool()`` / ``float()``.
"""

from __future__ import annotations

import math
from typing import Any, Literal, Optional

_TRUE = {"true", "yes", "1"}
_FALSE = {"false", "no", "0"}
_NO_ANSWER = {"", "uncertain", "unknown", "none", "null", "n/a", "na"}

Support = Literal["true", "false", "partial"]


def parse_bool(value: Any) -> Optional[bool]:
    """True / False for recognizable booleans, None for anything else."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        low = value.strip().lower()
        if low in _TRUE:
            return True
        if low in _FALSE:
            return False
    return None


def parse_support(value: Any) -> Optional[Support]:
    """Normalize a ``supports`` verdict to "true" / "false" / "partial", or None."""
    if isinstance(value, str) and value.strip().lower() == "partial":
        return "partial"
    parsed = parse_bool(value)
    if parsed is None:
        return None
    return "true" if parsed else "false"


def parse_confidence(value: Any) -> float:
    """A confidence in [0, 1]. Anything else (``"high"``, 85, NaN) counts as 0.0."""
    if isinstance(value, bool):
        return 0.0
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    if math.isnan(number) or not 0.0 <= number <= 1.0:
        return 0.0
    return number


def is_no_answer(value: Any) -> bool:
    """True when the model gave no usable value (None, "", "uncertain", ...)."""
    if value is None:
        return True
    return isinstance(value, str) and value.strip().lower() in _NO_ANSWER

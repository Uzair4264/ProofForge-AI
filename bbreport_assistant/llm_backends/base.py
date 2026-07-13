"""Abstract LLM backend interface.

All backends expose a single ``complete`` method. Per spec §7.3, when structured
output is expected we parse JSON, and on a parse failure we retry exactly once
before raising. Backends themselves only need to implement ``_raw_complete``.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import Any, Optional

from ..core.exceptions import LLMFormatError

_JSON_BLOCK_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(text: str) -> dict[str, Any]:
    """Best-effort extraction of a JSON object from model output.

    Models sometimes wrap JSON in prose or fenced code blocks; we grab the first
    balanced-looking ``{...}`` span. Raises ``LLMFormatError`` if nothing parses.
    """
    text = text.strip()
    # Strip ```json fences if present.
    if text.startswith("```"):
        text = text.strip("`")
        if text.lstrip().lower().startswith("json"):
            text = text.lstrip()[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK_RE.search(text)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError as exc:
            raise LLMFormatError(f"Could not parse JSON from model output: {exc}") from exc
    raise LLMFormatError("Model output contained no JSON object")


class LLMBackend(ABC):
    """Base class for all LLM backends."""

    name: str = "base"

    @abstractmethod
    def _raw_complete(self, prompt: str) -> str:
        """Return the raw text completion for a prompt."""

    def complete(self, prompt: str, expected_format: Optional[str] = "json") -> Any:
        """Complete a prompt.

        If ``expected_format`` is ``"json"`` (the default), parse and return a
        dict, retrying once on malformed output. Otherwise return raw text.
        """
        raw = self._raw_complete(prompt)
        if expected_format != "json":
            return raw
        try:
            return extract_json(raw)
        except LLMFormatError:
            # Retry once (spec §7.3.4).
            raw = self._raw_complete(prompt)
            return extract_json(raw)

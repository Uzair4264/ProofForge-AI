"""Prompt loading and rendering.

Prompt templates live as ``.txt`` files in the top-level ``prompts/`` directory
(spec §4.2). Each carries a ``PROMPT_ID:`` marker on its first line so the mock
backend can recognize it. Rendering uses ``str.format`` with named placeholders;
literal braces in templates must be doubled.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from ..core.exceptions import LLMError

# prompts/ sits next to the package root (bbreport_assistant/../prompts is wrong;
# we keep prompts inside the package for install portability).
PROMPTS_DIR = Path(__file__).parent.parent / "prompts"


@lru_cache(maxsize=64)
def load_prompt(name: str) -> str:
    path = PROMPTS_DIR / f"{name}.txt"
    if not path.exists():
        raise LLMError(f"Prompt template not found: {path}")
    with path.open("r", encoding="utf-8") as fh:
        return fh.read()


def render_prompt(name: str, **kwargs: object) -> str:
    """Load a prompt and substitute ``{placeholder}`` values."""
    template = load_prompt(name)
    try:
        return template.format(**kwargs)
    except KeyError as exc:
        raise LLMError(f"Prompt '{name}' missing placeholder value: {exc}") from exc

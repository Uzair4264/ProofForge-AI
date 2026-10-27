"""Plain-text parser for repro steps, code snippets, and log output."""

from __future__ import annotations

from typing import Any


def parse(text: str) -> tuple[str, dict[str, Any]]:
    lines = text.splitlines()
    meta = {"line_count": len(lines), "char_count": len(text)}
    return text, meta

"""Screenshot handler.

v0 records image dimensions/format only (no OCR — that arrives in v0.2). The
extracted text is a short human-readable descriptor used in rendering.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def parse(path: Path) -> tuple[str, dict[str, Any]]:
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - pillow is a declared dependency
        return (f"Screenshot: {path.name}", {"format": "unknown"})

    try:
        with Image.open(path) as img:
            width, height = img.size
            fmt = img.format or "unknown"
    except Exception:  # noqa: BLE001 - any decode error degrades gracefully
        return (f"Screenshot: {path.name}", {"format": "unreadable"})

    meta = {"width": width, "height": height, "format": fmt}
    text = f"Screenshot {path.name} ({width}x{height} {fmt})"
    return text, meta

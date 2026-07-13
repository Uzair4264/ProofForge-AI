"""Transparent caching wrapper for LLM backends.

Caches by ``sha256(prompt + model + temperature)`` as a JSON file under the
OS cache directory (spec §7.7). Wraps any ``LLMBackend`` without the inner
backend knowing it is cached.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Optional

from ..core import paths
from .base import LLMBackend


class CachingBackend(LLMBackend):
    def __init__(self, inner: LLMBackend, *, model: str, temperature: float) -> None:
        self.inner = inner
        self.model = model
        self.temperature = temperature
        self.name = f"cached:{inner.name}"
        paths.LLM_CACHE_DIR.mkdir(parents=True, exist_ok=True)

    def _key(self, prompt: str) -> str:
        material = f"{prompt}\x00{self.model}\x00{self.temperature}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _path(self, key: str):
        return paths.LLM_CACHE_DIR / f"{key}.json"

    def _raw_complete(self, prompt: str) -> str:
        # Cache operates at the raw-text layer.
        return self.inner._raw_complete(prompt)

    def complete(self, prompt: str, expected_format: Optional[str] = "json") -> Any:
        key = self._key(prompt)
        cache_path = self._path(key)
        if cache_path.exists():
            try:
                with cache_path.open("r", encoding="utf-8") as fh:
                    cached = json.load(fh)
                return cached["result"] if expected_format == "json" else cached["raw"]
            except (OSError, json.JSONDecodeError, KeyError):
                pass  # corrupt cache entry — fall through and recompute

        result = self.inner.complete(prompt, expected_format=expected_format)
        raw = result if isinstance(result, str) else json.dumps(result)
        try:
            with cache_path.open("w", encoding="utf-8") as fh:
                json.dump({"raw": raw, "result": result}, fh, ensure_ascii=False)
        except OSError:
            pass  # cache write failures are non-fatal
        return result

"""Local Ollama backend (the default live path).

Talks to an Ollama server's ``/api/generate`` endpoint over HTTP. Tuned for
``qwen2.5:3b-instruct-q4_K_M`` on modest hardware (low temperature for
near-deterministic structured output).
"""

from __future__ import annotations

import httpx

from ..core.exceptions import LLMError
from .base import LLMBackend


class OllamaBackend(LLMBackend):
    name = "ollama"

    def __init__(
        self,
        *,
        model: str = "qwen2.5:3b-instruct-q4_K_M",
        endpoint: str = "http://localhost:11434",
        temperature: float = 0.1,
        max_tokens: int = 1024,
        timeout_seconds: int = 120,
    ) -> None:
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds

    def _raw_complete(self, prompt: str) -> str:
        url = f"{self.endpoint}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_tokens,
            },
        }
        try:
            resp = httpx.post(url, json=payload, timeout=self.timeout_seconds)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            raise LLMError(
                f"Ollama request failed ({exc}). Is the server running at "
                f"{self.endpoint} and is model '{self.model}' pulled?"
            ) from exc
        text = data.get("response")
        if not isinstance(text, str):
            raise LLMError("Ollama response missing 'response' field")
        return text

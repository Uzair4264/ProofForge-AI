"""OpenAI-compatible cloud backend (opt-in only).

Gated behind ``privacy.allow_cloud_backends`` / ``--allow-cloud``. Sensitive
evidence is never routed here (enforced upstream). This is a thin stub for v0;
it implements the chat-completions contract used by Groq, OpenAI, etc.
"""

from __future__ import annotations

import os

import httpx

from ..core.exceptions import LLMError
from .base import LLMBackend


class OpenAICompatibleBackend(LLMBackend):
    name = "openai_compatible"

    def __init__(
        self,
        *,
        model: str,
        endpoint: str = "https://api.openai.com/v1",
        temperature: float = 0.1,
        api_key_env: str = "BBREPORT_LLM_API_KEY",
    ) -> None:
        self.model = model
        self.endpoint = endpoint.rstrip("/")
        self.temperature = temperature
        self.api_key = os.environ.get(api_key_env, "")
        if not self.api_key:
            raise LLMError(f"No API key found in environment variable {api_key_env}")

    def _raw_complete(self, prompt: str) -> str:
        url = f"{self.endpoint}/chat/completions"
        headers = {"Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": "user", "content": prompt}],
        }
        try:
            resp = httpx.post(url, json=payload, headers=headers, timeout=120)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]
        except (httpx.HTTPError, KeyError, IndexError) as exc:
            raise LLMError(f"Cloud backend request failed: {exc}") from exc

"""Pluggable LLM backends. Backends never know what they are being asked."""

from __future__ import annotations

from ..core.config import Config
from ..core.exceptions import ConfigError
from .base import LLMBackend
from .cache import CachingBackend
from .mock_backend import MockLLMBackend
from .ollama_backend import OllamaBackend


def build_backend(config: Config, *, no_cache: bool = False) -> LLMBackend:
    """Instantiate the configured backend, wrapping it in a cache if enabled."""
    name = config.llm.backend.lower()
    backend: LLMBackend
    if name == "mock":
        backend = MockLLMBackend()
    elif name == "ollama":
        backend = OllamaBackend(
            model=config.llm.model,
            endpoint=config.llm.endpoint,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
            timeout_seconds=config.llm.timeout_seconds,
        )
    elif name in ("openai", "openai_compatible", "groq"):
        from .openai_compatible import OpenAICompatibleBackend

        if not config.privacy.allow_cloud_backends:
            raise ConfigError(
                "Cloud backend requested but privacy.allow_cloud_backends is false. "
                "Pass --allow-cloud to opt in."
            )
        backend = OpenAICompatibleBackend(
            model=config.llm.model,
            endpoint=config.llm.endpoint,
            temperature=config.llm.temperature,
        )
    else:
        raise ConfigError(f"Unknown LLM backend: {config.llm.backend!r}")

    if config.cache.enabled and not no_cache:
        backend = CachingBackend(backend, model=config.llm.model, temperature=config.llm.temperature)
    return backend


__all__ = ["LLMBackend", "MockLLMBackend", "OllamaBackend", "CachingBackend", "build_backend"]

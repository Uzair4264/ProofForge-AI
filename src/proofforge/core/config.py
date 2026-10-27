"""Configuration loading and defaults.

The config file lives at the OS-appropriate location (see ``paths.CONFIG_FILE``).
Spec defaults (§7.1, §12.8) are applied first, then the user's YAML is merged on
top. The mock backend is selectable here for offline/test runs.
"""

from __future__ import annotations

from typing import Any

import yaml
from pydantic import BaseModel, Field

from . import paths
from .exceptions import ConfigError


class LLMConfig(BaseModel):
    backend: str = "mock"
    model: str = "qwen2.5:3b-instruct-q4_K_M"
    endpoint: str = "http://localhost:11434"
    temperature: float = 0.1
    max_tokens: int = 1024
    timeout_seconds: int = 120


class InferenceConfig(BaseModel):
    enabled: bool = True
    parallel: bool = True
    cache: bool = True


class PrivacyConfig(BaseModel):
    allow_cloud_backends: bool = False
    cloud_only_for_non_sensitive: bool = True


class CacheConfig(BaseModel):
    enabled: bool = True
    ttl_days: int = 30


class Config(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    inference: InferenceConfig = Field(default_factory=InferenceConfig)
    privacy: PrivacyConfig = Field(default_factory=PrivacyConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config() -> Config:
    """Load config from disk, merging user values over defaults."""
    defaults = Config().model_dump()
    if not paths.CONFIG_FILE.exists():
        return Config(**defaults)
    try:
        with paths.CONFIG_FILE.open("r", encoding="utf-8") as fh:
            user = yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigError(f"Failed to read config at {paths.CONFIG_FILE}: {exc}") from exc
    if not isinstance(user, dict):
        raise ConfigError("Config file must be a YAML mapping")
    return Config(**_deep_merge(defaults, user))


def write_default_config(*, force: bool = False) -> bool:
    """Write a default config file. Returns True if written, False if it existed."""
    paths.ensure_dirs()
    if paths.CONFIG_FILE.exists() and not force:
        return False
    with paths.CONFIG_FILE.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(Config().model_dump(), fh, sort_keys=False, default_flow_style=False)
    return True

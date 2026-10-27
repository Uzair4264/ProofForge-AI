"""Shared CLI helpers: console, config access, backend construction, status glyphs."""

from __future__ import annotations

import sys

from rich.console import Console

from ..core.config import Config, load_config
from ..llm_backends import build_backend
from ..llm_backends.base import LLMBackend

console = Console()

# ASCII fallbacks for terminals that can't render Unicode (spec §16.3).
_UNICODE_OK = (sys.stdout.encoding or "").lower().startswith("utf")
OK = "[green]✓[/green]" if _UNICODE_OK else "[green][OK][/green]"
WARN = "[yellow]![/yellow]" if _UNICODE_OK else "[yellow][!][/yellow]"
FAIL = "[red]✗[/red]" if _UNICODE_OK else "[red][X][/red]"
ASK = "[cyan]?[/cyan]"


def get_config() -> Config:
    return load_config()


def get_backend(*, no_cache: bool = False, allow_cloud: bool = False) -> LLMBackend:
    config = load_config()
    if allow_cloud:
        config.privacy.allow_cloud_backends = True
    return build_backend(config, no_cache=no_cache)


def error(message: str) -> None:
    console.print(f"{FAIL} [red]{message}[/red]")

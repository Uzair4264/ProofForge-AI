"""``proofforge doctor`` — platform-aware setup diagnostics (spec §16.5)."""

from __future__ import annotations

import platform
import sys

import httpx

from ...core import paths
from ...core.config import load_config
from ...program_packs.loader import available_programs
from ...vuln_classes.loader import available_classes
from ..common import FAIL, OK, WARN, console


def doctor() -> None:
    """Diagnose the local setup."""
    console.print("[bold]ProofForge AI — doctor[/bold]\n")

    # Python version.
    py = sys.version_info
    if py >= (3, 11):
        console.print(f"{OK} Python {py.major}.{py.minor}.{py.micro}")
    else:
        console.print(f"{FAIL} Python {py.major}.{py.minor} (3.11+ required)")

    # OS.
    console.print(f"{OK} OS: {platform.system()} {platform.release()}")

    # Directories writable.
    try:
        paths.ensure_dirs()
        console.print(f"{OK} Runtime directories writable")
        console.print(f"    config: {paths.CONFIG_DIR}")
        console.print(f"    data:   {paths.DATA_DIR}")
        console.print(f"    cache:  {paths.CACHE_DIR}")
    except OSError as exc:
        console.print(f"{FAIL} Cannot create runtime directories: {exc}")

    # Config.
    config = load_config()
    if paths.CONFIG_FILE.exists():
        console.print(f"{OK} Config present ({config.llm.backend} / {config.llm.model})")
    else:
        console.print(f"{WARN} No config file yet (using defaults). Run 'proofforge config init'.")

    # Data packs / templates.
    console.print(f"{OK} Vuln classes available: {', '.join(available_classes()) or '(none)'}")
    console.print(f"{OK} Programs available: {', '.join(available_programs()) or '(none)'}")

    # LLM backend reachability.
    if config.llm.backend == "mock":
        console.print(f"{OK} Mock backend selected — no model required.")
    elif config.llm.backend == "ollama":
        try:
            resp = httpx.get(f"{config.llm.endpoint.rstrip('/')}/api/tags", timeout=3)
            resp.raise_for_status()
            models = [m.get("name", "") for m in resp.json().get("models", [])]
            console.print(f"{OK} Ollama reachable at {config.llm.endpoint}")
            if config.llm.model in models:
                console.print(f"{OK} Model '{config.llm.model}' is pulled")
            else:
                console.print(f"{WARN} Model '{config.llm.model}' not pulled. Run: ollama pull {config.llm.model}")
        except httpx.HTTPError:
            console.print(f"{WARN} Ollama not reachable at {config.llm.endpoint} (optional; mock backend still works).")
    else:
        console.print(f"{WARN} Backend '{config.llm.backend}' configured.")

    # Terminal capabilities.
    enc = (sys.stdout.encoding or "").lower()
    if enc.startswith("utf"):
        console.print(f"{OK} Terminal encoding: {sys.stdout.encoding}")
    else:
        console.print(f"{WARN} Terminal encoding '{sys.stdout.encoding}' — using ASCII status glyphs.")

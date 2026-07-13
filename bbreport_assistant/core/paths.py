"""Cross-platform runtime path resolution.

All runtime directories are resolved via ``platformdirs`` so the tool behaves
correctly on Linux, macOS, and Windows. Never hardcode ``~/.bbreport-assistant``
anywhere in the codebase — always go through this module.
"""

from __future__ import annotations

import re
from pathlib import Path

from platformdirs import user_cache_dir, user_config_dir, user_data_dir

from .exceptions import PathValidationError

APP_NAME = "bbreport-assistant"

# appauthor=False avoids the "Author\AppName" double-nesting on Windows, matching
# the single-directory layout documented in the spec (§4.2).
CONFIG_DIR = Path(user_config_dir(APP_NAME, appauthor=False))
DATA_DIR = Path(user_data_dir(APP_NAME, appauthor=False))
CACHE_DIR = Path(user_cache_dir(APP_NAME, appauthor=False))

SESSIONS_DIR = DATA_DIR / "sessions"
LLM_CACHE_DIR = CACHE_DIR / "llm"

CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Windows reserved device names (case-insensitive, with or without extension).
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}


def ensure_dirs() -> None:
    """Create all runtime directories if they do not yet exist."""
    for directory in (CONFIG_DIR, DATA_DIR, CACHE_DIR, SESSIONS_DIR, LLM_CACHE_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def session_dir(session_id: str) -> Path:
    """Return the directory for a given session id (does not create it)."""
    return SESSIONS_DIR / session_id


def validate_input_path(raw: str | Path) -> Path:
    """Resolve and validate a user-supplied file path.

    Guards against the cross-platform quirks called out in the spec: reserved
    Windows device filenames. Returns an absolute, resolved ``Path``.
    """
    path = Path(raw).expanduser()
    stem = path.stem.lower()
    if stem in _WINDOWS_RESERVED:
        raise PathValidationError(f"'{path.name}' uses a reserved device name")
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:  # pragma: no cover - OS dependent
        raise PathValidationError(f"Cannot resolve path '{raw}': {exc}") from exc


def is_within(child: Path, parent: Path) -> bool:
    """Return True if ``child`` is inside ``parent`` (no traversal escape)."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9._-]")


def safe_component(name: str) -> str:
    """Sanitize a string for safe use as a single path component."""
    return _SAFE_ID_RE.sub("_", name)

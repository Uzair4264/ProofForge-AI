"""Session persistence under the OS data directory.

A session is one report in progress. State is stored as ``session.json`` in the
session's directory; a small ``current`` pointer file records the active session
so subsequent CLI commands operate on it without repeating the id.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from . import paths
from .exceptions import SessionError
from .types import Session

_CURRENT_FILE = paths.DATA_DIR / "current_session"


def new_session_id() -> str:
    now = datetime.now(timezone.utc)
    base = now.strftime("sess-%Y-%m-%d")
    # Disambiguate same-day sessions with a counter.
    n = 1
    while paths.session_dir(f"{base}-{n:03d}").exists():
        n += 1
    return f"{base}-{n:03d}"


def session_json_path(session_id: str) -> Path:
    return paths.session_dir(session_id) / "session.json"


def audit_log_path(session_id: str) -> Path:
    return paths.session_dir(session_id) / "audit.jsonl"


def save(session: Session) -> None:
    sdir = paths.session_dir(session.id)
    sdir.mkdir(parents=True, exist_ok=True)
    with session_json_path(session.id).open("w", encoding="utf-8") as fh:
        fh.write(session.model_dump_json(indent=2))


def load(session_id: str) -> Session:
    path = session_json_path(session_id)
    if not path.exists():
        raise SessionError(f"Session '{session_id}' not found.")
    with path.open("r", encoding="utf-8") as fh:
        return Session.model_validate_json(fh.read())


def set_current(session_id: str) -> None:
    paths.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _CURRENT_FILE.open("w", encoding="utf-8") as fh:
        fh.write(session_id)


def get_current_id() -> str | None:
    if not _CURRENT_FILE.exists():
        return None
    with _CURRENT_FILE.open("r", encoding="utf-8") as fh:
        sid = fh.read().strip()
    return sid or None


def load_current() -> Session:
    sid = get_current_id()
    if sid is None:
        raise SessionError("No active session. Run 'bbreport init' first.")
    return load(sid)


def list_sessions() -> list[str]:
    if not paths.SESSIONS_DIR.exists():
        return []
    return sorted(p.name for p in paths.SESSIONS_DIR.iterdir() if p.is_dir())

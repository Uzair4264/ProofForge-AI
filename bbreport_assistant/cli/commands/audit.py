"""``bbreport audit`` — verify the integrity of an audit log chain (spec §11.4)."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer

from ...audit.logger import verify_log
from ...core import session_store
from ..common import FAIL, OK, console, error

app = typer.Typer(help="Audit log integrity.")


@app.command("verify")
def verify(
    log_file: Optional[str] = typer.Argument(None, help="Path to an audit.jsonl (defaults to current session's log)"),
) -> None:
    """Walk the hash chain and report any break."""
    if log_file is not None:
        path = Path(log_file).resolve()
    else:
        sid = session_store.get_current_id()
        if sid is None:
            error("No log file given and no active session.")
            raise typer.Exit(code=1)
        path = session_store.audit_log_path(sid)

    if not path.exists():
        error(f"Audit log not found: {path}")
        raise typer.Exit(code=1)

    ok, broken = verify_log(path)
    if ok:
        console.print(f"{OK} Audit chain intact: {path}")
    else:
        console.print(f"{FAIL} [red]Audit chain BROKEN at sequence {broken}: {path}[/red]")
        raise typer.Exit(code=2)

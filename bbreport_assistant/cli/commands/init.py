"""``bbreport init`` — start a new report session."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

import typer

from ...audit.logger import AuditLogger
from ...core import paths, session_store
from ...core.exceptions import BBReportError
from ...core.types import Session
from ...program_packs.loader import available_programs, get_pack
from ..common import OK, console, error


def init(
    program: str = typer.Option(..., "--program", "-p", help="Program id, e.g. hackerone:example-corp"),
    vuln_class: Optional[str] = typer.Option(None, "--vuln-class", help="Optionally pin the vuln class now"),
) -> None:
    """Create a new session for the given program."""
    paths.ensure_dirs()
    try:
        get_pack(program)  # validate program exists
    except BBReportError as exc:
        error(str(exc))
        console.print(f"  Available programs: {', '.join(available_programs())}")
        raise typer.Exit(code=1)

    session_id = session_store.new_session_id()
    session = Session(
        id=session_id,
        program_id=program,
        created_at=datetime.now(timezone.utc),
        vuln_class=vuln_class,
    )
    session_store.save(session)
    session_store.set_current(session_id)

    logger = AuditLogger(session_store.audit_log_path(session_id))
    logger.log(actor="system", action="session_start", target=session_id, result="ok",
               details={"program_id": program, "vuln_class": vuln_class})

    console.print(f"{OK} Session created: {session_id}")
    console.print(f"  Program: {program}")
    console.print(f"  Location: {paths.session_dir(session_id)}")

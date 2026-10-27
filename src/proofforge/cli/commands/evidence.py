"""``proofforge evidence`` — add / list / remove evidence files."""

from __future__ import annotations

from typing import Optional

import typer
from rich.table import Table

from ...audit.logger import AuditLogger
from ...core import session_store
from ...core.exceptions import BBReportError
from ...core.types import EvidenceType, SensitivityLevel
from ...evidence.ingester import ingest
from ..common import OK, console, error

app = typer.Typer(help="Manage evidence files.")


@app.command("add")
def add(
    file: str = typer.Option(..., "--file", "-f", help="Path to the evidence file"),
    type_: str = typer.Option(..., "--type", "-t", help="Evidence type, e.g. http_request"),
    sensitivity: str = typer.Option("sensitive", "--sensitivity", "-s", help="public|internal|sensitive|restricted"),
    notes: Optional[str] = typer.Option(None, "--notes", help="Optional note"),
) -> None:
    """Add an evidence file to the current session."""
    try:
        session = session_store.load_current()
        ev_type = EvidenceType(type_)
        sens = SensitivityLevel(sensitivity)
    except (BBReportError, ValueError) as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    ev_id = session.next_evidence_id()
    try:
        evidence = ingest(evidence_id=ev_id, file=file, evidence_type=ev_type, sensitivity=sens, notes=notes)
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    session.evidence.append(evidence)
    if session.report is not None:
        session.report.reset_checks()
    session_store.save(session)

    logger = AuditLogger(session_store.audit_log_path(session.id))
    logger.log(actor="user", action="evidence_add", target=ev_id, result="ok",
               details={"type": ev_type.value, "content_hash": evidence.content_hash, "sensitivity": sens.value})

    console.print(f"{OK} Added {ev_id} ({ev_type.value})  [dim]{evidence.content_hash[:12]}…[/dim]")


@app.command("list")
def list_() -> None:
    """List evidence in the current session."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    if not session.evidence:
        console.print("[dim]No evidence added yet.[/dim]")
        return

    table = Table("ID", "Type", "Sensitivity", "Hash", "Source")
    for ev in session.evidence:
        table.add_row(ev.id, ev.type.value, ev.sensitivity.value, ev.content_hash[:12] + "…", ev.source_path)
    console.print(table)


@app.command("remove")
def remove(id_: str = typer.Option(..., "--id", help="Evidence id to remove, e.g. ev-002")) -> None:
    """Remove an evidence item by id."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    before = len(session.evidence)
    session.evidence = [e for e in session.evidence if e.id != id_]
    if len(session.evidence) == before:
        error(f"No evidence with id {id_}")
        raise typer.Exit(code=1)
    if session.report is not None:
        session.report.reset_checks()
    session_store.save(session)

    logger = AuditLogger(session_store.audit_log_path(session.id))
    logger.log(actor="user", action="evidence_remove", target=id_, result="ok")
    console.print(f"{OK} Removed {id_}")

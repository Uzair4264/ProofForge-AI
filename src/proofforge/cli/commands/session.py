"""``proofforge session`` — list / switch / show sessions."""

from __future__ import annotations

import typer
from rich.table import Table

from ...core import session_store
from ...core.exceptions import BBReportError
from ..common import OK, console, error

app = typer.Typer(help="Manage sessions.")


@app.command("list")
def list_() -> None:
    current = session_store.get_current_id()
    sessions = session_store.list_sessions()
    if not sessions:
        console.print("[dim]No sessions yet. Run 'proofforge init'.[/dim]")
        return
    table = Table("", "Session", "Program", "Vuln class", "Evidence", "Report")
    for sid in sessions:
        try:
            s = session_store.load(sid)
        except BBReportError:
            continue
        marker = "*" if sid == current else ""
        table.add_row(marker, sid, s.program_id, s.vuln_class or "-",
                      str(len(s.evidence)), "yes" if s.report else "no")
    console.print(table)


@app.command("use")
def use(session_id: str = typer.Argument(..., help="Session id to activate")) -> None:
    try:
        session_store.load(session_id)
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    session_store.set_current(session_id)
    console.print(f"{OK} Active session: {session_id}")


@app.command("show")
def show() -> None:
    try:
        s = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    console.print(f"[bold]{s.id}[/bold]")
    console.print(f"  Program: {s.program_id}")
    console.print(f"  Vuln class: {s.vuln_class or '-'}  Subtype: {s.subtype or '-'}")
    console.print(f"  Evidence: {len(s.evidence)} item(s)")
    console.print(f"  Report: {'assembled' if s.report else 'not yet'}")

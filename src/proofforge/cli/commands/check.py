"""``proofforge check`` — run compliance checks (Gap 3, Stage 5)."""

from __future__ import annotations

import typer

from ...audit.logger import AuditLogger
from ...core import session_store
from ...core.exceptions import BBReportError
from ...core.orchestrator import Orchestrator
from ..common import FAIL, OK, WARN, console, error, get_backend


def check(
    no_llm: bool = typer.Option(False, "--no-llm", help="Run only deterministic compliance checks"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the LLM cache"),
) -> None:
    """Check the current report against its program rule pack."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    if session.report is None:
        error("No report yet. Run 'proofforge report new' first.")
        raise typer.Exit(code=1)

    orch = Orchestrator(get_backend(no_cache=no_cache))
    console.print(f"Running compliance checks against {session.program_id}...")
    try:
        report = orch.check_compliance(session, run_llm=not no_llm)
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    logger = AuditLogger(session_store.audit_log_path(session.id))
    for c in report.checks_run:
        glyph = OK if c.status == "pass" else WARN if c.status == "warn" else FAIL
        console.print(f"  {glyph} {c.name}: {c.message}")
        logger.log(actor="system", action="compliance_check", target=c.name,
                   result=c.status, details={"message": c.message})

    # A --no-llm pass skipped the LLM forbidden-content scan, so it does not count as checked.
    skipped_llm_pass = no_llm and report.overall_status == "pass"
    session.report.compliance_status = None if skipped_llm_pass else report.overall_status
    session_store.save(session)

    if report.overall_status == "block":
        console.print(f"\n{FAIL} [red]Compliance blocked.[/red]")
        raise typer.Exit(code=2)
    if report.overall_status == "warn":
        console.print(f"\n{WARN} [yellow]Compliance passed with warnings.[/yellow]")
    else:
        console.print(f"\n{OK} All compliance checks passed.")

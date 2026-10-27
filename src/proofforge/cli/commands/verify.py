"""``proofforge verify`` — run integrity checks (Gap 1, Stage 4)."""

from __future__ import annotations

import typer

from ...audit.logger import AuditLogger
from ...core import session_store
from ...core.exceptions import BBReportError
from ...core.orchestrator import Orchestrator
from ..common import FAIL, OK, WARN, console, error, get_backend


def verify(
    no_llm: bool = typer.Option(False, "--no-llm", help="Run only deterministic integrity checks"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the LLM cache"),
) -> None:
    """Verify claim-to-evidence integrity for the current report."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    if session.report is None:
        error("No report yet. Run 'proofforge report new' first.")
        raise typer.Exit(code=1)

    orch = Orchestrator(get_backend(no_cache=no_cache))
    console.print("Running integrity checks...")
    report = orch.verify_integrity(session.report, session.evidence, run_llm=not no_llm)

    logger = AuditLogger(session_store.audit_log_path(session.id))
    for check in report.checks_run:
        glyph = OK if check.status == "pass" else WARN if check.status == "warn" else FAIL
        console.print(f"  {glyph} {check.name}: {check.message}")
        logger.log(actor="system", action="integrity_check", target=check.name,
                   result=check.status, details={"message": check.message})

    # A --no-llm pass skipped the consistency checks, so it does not count as verified.
    skipped_llm_pass = no_llm and report.overall_status == "pass"
    session.report.integrity_status = None if skipped_llm_pass else report.overall_status
    session_store.save(session)

    if report.overall_status == "block":
        console.print(f"\n{FAIL} [red]Integrity checks blocked. Resolve issues or override before rendering.[/red]")
        raise typer.Exit(code=2)
    if report.overall_status == "warn":
        console.print(f"\n{WARN} [yellow]Integrity passed with warnings.[/yellow]")
    else:
        console.print(f"\n{OK} All integrity checks passed.")

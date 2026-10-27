"""``proofforge render`` — produce the final report + audit + integrity summary (Stage 6)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import typer

from ...audit.logger import AuditLogger
from ...core import session_store
from ...core.exceptions import BBReportError
from ...core.orchestrator import Orchestrator
from ..common import OK, console, error, get_backend


def render(
    output: str = typer.Option("report.md", "--output", "-o", help="Output file path"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the LLM cache"),
) -> None:
    """Render the report and write the report, audit log, and integrity summary."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    if session.report is None:
        error("No report yet. Run 'proofforge report new' first.")
        raise typer.Exit(code=1)

    orch = Orchestrator(get_backend(no_cache=no_cache))
    try:
        text = orch.render(session)
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    out_path = Path(output).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        fh.write(text)

    # Integrity summary (claims, evidence, links).
    summary = {
        "vuln_class": session.report.vuln_class,
        "subtype": session.report.subtype,
        "severity": {
            "vector": session.report.severity_vector,
            "score": session.report.severity_score,
            "rating": session.report.severity_rating,
        },
        "claims": [c.model_dump() for c in session.report.claims],
        "evidence": [
            {"id": e.id, "type": e.type.value, "content_hash": e.content_hash}
            for e in session.evidence
        ],
        "provenance": [p.model_dump() for p in session.report.provenance],
    }
    summary_path = out_path.with_name("integrity_summary.json")
    with summary_path.open("w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2, ensure_ascii=False)

    # Copy the session audit log next to the output.
    src_log = session_store.audit_log_path(session.id)
    logger = AuditLogger(src_log)
    logger.log(actor="system", action="report_finalized", target=str(out_path), result="ok",
               details={"format": session.report.vuln_class})
    audit_out = out_path.with_name("audit.jsonl")
    if src_log.exists():
        shutil.copyfile(src_log, audit_out)

    console.print(f"{OK} Report written to: {out_path}")
    console.print(f"{OK} Integrity summary: {summary_path}")
    console.print(f"{OK} Audit log: {audit_out}")

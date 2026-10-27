"""``proofforge render`` — produce the final report + audit + integrity summary (Stage 6)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

import typer

from ...audit.logger import AuditLogger
from ...core import session_store
from ...core.exceptions import BBReportError
from ...core.orchestrator import Orchestrator
from ..common import FAIL, OK, WARN, console, error, get_backend


def _hard_blocks(orch: Orchestrator, session) -> list[str]:
    """Non-overridable blocks from the deterministic checks, re-run now.

    Re-running catches changes since `verify` / `check` (e.g. edited evidence).
    """
    integrity = orch.verify_integrity(session.report, session.evidence, run_llm=False)
    compliance = orch.check_compliance(session, run_llm=False)
    return [
        f"{c.name}: {c.message}"
        for c in (*integrity.checks_run, *compliance.checks_run)
        if c.status == "block" and not c.overridable
    ]


def _soft_gate_problems(session) -> list[str]:
    problems = []
    for label, cmd, status in (
        ("Integrity", "verify", session.report.integrity_status),
        ("Compliance", "check", session.report.compliance_status),
    ):
        if status is None:
            problems.append(f"{label} checks have not been run on this version (run 'proofforge {cmd}').")
        elif status == "block":
            problems.append(f"{label} checks blocked (see 'proofforge {cmd}').")
    return problems


def render(
    output: str = typer.Option("report.md", "--output", "-o", help="Output file path"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the LLM cache"),
    override: Optional[str] = typer.Option(
        None, "--override",
        help="Render even though verify/check did not pass, with this reason (audit-logged). "
             "Cannot override orphan, hash, evidence or scope blocks.",
    ),
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
    logger = AuditLogger(session_store.audit_log_path(session.id))

    # --- Gate: render only what verify + check let through ---------------- #
    try:
        hard = _hard_blocks(orch, session)
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    if hard:
        error("Cannot render: these checks block and cannot be overridden:")
        for item in hard:
            console.print(f"  {FAIL} {item}")
        logger.log(actor="system", action="render_refused", target=session.id, result="block",
                   details={"hard_blocks": hard})
        raise typer.Exit(code=2)

    problems = _soft_gate_problems(session)
    if problems and override is None:
        error("Cannot render yet:")
        for item in problems:
            console.print(f"  {WARN} {item}")
        console.print("  Fix these, or pass --override \"<reason>\" (recorded in the audit log).")
        raise typer.Exit(code=2)
    if problems:
        if not override.strip():
            error("--override needs a reason.")
            raise typer.Exit(code=1)
        logger.log(actor="user", action="render_override", target=session.id, result="override",
                   details={"reason": override.strip(), "problems": problems})
        console.print(f"{WARN} Rendering with override: {override.strip()}")

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
    logger.log(actor="system", action="report_finalized", target=str(out_path), result="ok",
               details={"format": session.report.vuln_class})
    audit_out = out_path.with_name("audit.jsonl")
    if src_log.exists():
        shutil.copyfile(src_log, audit_out)

    console.print(f"{OK} Report written to: {out_path}")
    console.print(f"{OK} Integrity summary: {summary_path}")
    console.print(f"{OK} Audit log: {audit_out}")

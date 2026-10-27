"""``proofforge report`` — build the structured report (Stages 1-3 + assembly)."""

from __future__ import annotations

from typing import Optional

import typer

from ...audit.logger import AuditLogger
from ...core import session_store
from ...core.exceptions import BBReportError
from ...core.orchestrator import Orchestrator
from ...core.types import Field, FieldState
from ...elicitation.confirmation import ask_impact_basis, ask_impact_evidence, present_inferred
from ...elicitation.dialog import ElicitationCancelled, elicit_pending
from ...vuln_classes.engine import IMPACT_FIELD
from ...vuln_classes.loader import available_classes, get_template
from ..common import ASK, OK, WARN, console, error, get_backend

app = typer.Typer(help="Work on the report itself.")


@app.command("new")
def new(
    vuln_class: Optional[str] = typer.Option(None, "--vuln-class", help="Vulnerability class (omit to classify from evidence)"),
    subtype: Optional[str] = typer.Option(None, "--subtype", help="Subtype, e.g. reflected"),
    severity: Optional[str] = typer.Option(None, "--severity", help="Override CVSS v3.1 vector"),
    title: Optional[str] = typer.Option(None, "--title", help="Report title"),
    description: str = typer.Option("", "--description", "-d", help="Initial vulnerability description"),
    yes: bool = typer.Option(False, "--yes", "-y", help="Auto-confirm inferred fields (non-interactive). Never accepts AI drafts such as the impact."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass the LLM cache"),
    allow_cloud: bool = typer.Option(False, "--allow-cloud", help="Permit cloud LLM backends"),
) -> None:
    """Classify (if needed), infer fields, elicit the rest, and assemble the report."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    if not session.evidence:
        error("No evidence in this session. Add evidence before building a report.")
        raise typer.Exit(code=1)

    backend = get_backend(no_cache=no_cache, allow_cloud=allow_cloud)
    orch = Orchestrator(backend)
    logger = AuditLogger(session_store.audit_log_path(session.id))

    # --- Stage 1: classification --------------------------------------- #
    if vuln_class is None:
        vuln_class = session.vuln_class
    if vuln_class is None:
        console.print("Classifying vulnerability from evidence...")
        try:
            result = orch.classify(session, description)
        except BBReportError as exc:
            error(f"Classification failed: {exc}")
            raise typer.Exit(code=1)
        vuln_class = result.get("vuln_class")
        subtype = subtype or result.get("subtype")
        conf = result.get("confidence", 0.0)
        console.print(f"  -> {vuln_class} (confidence: {conf})")
        logger.log(actor="llm", action="classify", target=session.id, result=str(vuln_class),
                   details={"confidence": conf})
        if vuln_class in (None, "uncertain") or vuln_class not in available_classes():
            error(f"Could not confidently classify. Re-run with --vuln-class. Available: {', '.join(available_classes())}")
            raise typer.Exit(code=1)
        if not yes:
            ans = console.input(f"Proceed with {vuln_class}? [Y/n] ").strip().lower()
            if ans not in ("", "y", "yes"):
                raise typer.Exit(code=0)

    try:
        template = get_template(vuln_class)
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)

    # --- Stage 2: inference -------------------------------------------- #
    console.print("\nInferring fields from evidence...")

    def observe(field_id: str, field: Field) -> None:
        logger.log(actor="inference", action="infer_field", target=field_id,
                   result=field.state.value,
                   details={"value": field.value, "confidence": field.confidence})

    inferred = orch.infer(vuln_class, session.evidence, observer=observe)

    # --- Stage 3: confirmation + elicitation --------------------------- #
    drafts = frozenset(
        s.id for s in template.required_fields
        if s.inference is not None and s.inference.mode == "suggest_only"
    )
    drafted = {fid for fid in drafts if inferred.get(fid) and inferred[fid].state == FieldState.INFERRED}
    confirmed = present_inferred(console, inferred, auto_confirm=yes, drafts=drafts)
    for fid, field in confirmed.items():
        if field.state in (FieldState.CONFIRMED, FieldState.USER_PROVIDED):
            logger.log(actor="user", action="confirm_field", target=fid, result=field.state.value)
        elif fid in drafted:
            logger.log(actor="user" if not yes else "system", action="reject_draft", target=fid,
                       result="rejected", details={"auto": yes})

    try:
        resolved = elicit_pending(
            console, template.required_fields, confirmed,
            responder=(lambda _fid: "skip") if yes else None,
        )
    except ElicitationCancelled:
        console.print(f"{WARN} Report cancelled.")
        raise typer.Exit(code=0)

    # Demonstrated vs inferred impact: asked only interactively; --yes never
    # resolves the impact (the draft is rejected and the question skipped).
    impact = resolved.get(IMPACT_FIELD)
    if not yes and impact and impact.value and impact.state in (FieldState.CONFIRMED, FieldState.USER_PROVIDED):
        impact.basis = ask_impact_basis(console, impact)
        logger.log(actor="user", action="impact_basis", target=IMPACT_FIELD, result=impact.basis)
        impact_spec = next(s for s in template.required_fields if s.id == IMPACT_FIELD)
        impact.evidence_ids = ask_impact_evidence(
            console, impact, session.evidence,
            impact_spec.inference.from_evidence if impact_spec.inference else [],
        )
        logger.log(actor="user", action="link_evidence", target=IMPACT_FIELD, result="ok",
                   details={"evidence_ids": impact.evidence_ids})

    # --- Assemble ------------------------------------------------------- #
    report = orch.build_report(
        vuln_class, subtype, resolved, session.evidence,
        severity_vector=severity, title=title,
    )
    session.vuln_class = vuln_class
    session.subtype = subtype
    session.report = report
    session_store.save(session)

    logger.log(actor="system", action="report_assembled", target=session.id, result="ok",
               details={"claims": len(report.claims), "severity": report.severity_score})

    console.print(f"\n{OK} Report assembled: {len(report.claims)} claim(s).")
    if report.severity_vector:
        console.print(f"  Severity: {report.severity_score} ({report.severity_rating})  {report.severity_vector}")
    console.print(f"  {ASK} Next: [bold]proofforge verify[/bold], then [bold]proofforge check[/bold], then [bold]proofforge render[/bold].")


@app.command("link")
def link(
    claim: str = typer.Option(..., "--claim", help="Claim id, e.g. claim-vuln"),
    evidence: str = typer.Option(..., "--evidence", help="Comma-separated evidence ids, e.g. ev-001,ev-002"),
) -> None:
    """Set which evidence supports a claim (replaces its current links)."""
    try:
        session = session_store.load_current()
    except BBReportError as exc:
        error(str(exc))
        raise typer.Exit(code=1)
    if session.report is None:
        error("No report yet. Run 'proofforge report new' first.")
        raise typer.Exit(code=1)

    target = next((c for c in session.report.claims if c.id == claim), None)
    if target is None:
        error(f"No claim '{claim}'. Claims: {', '.join(c.id for c in session.report.claims)}")
        raise typer.Exit(code=1)

    ids = [part.strip() for part in evidence.split(",") if part.strip()]
    known = {e.id for e in session.evidence}
    unknown = [i for i in ids if i not in known]
    if not ids or unknown:
        error(f"Unknown or missing evidence id(s): {', '.join(unknown) or '(none given)'}. "
              f"Evidence: {', '.join(sorted(known))}")
        raise typer.Exit(code=1)

    target.evidence_ids = ids
    session.report.rebuild_provenance()
    session.report.reset_checks()
    session_store.save(session)
    AuditLogger(session_store.audit_log_path(session.id)).log(
        actor="user", action="link_evidence", target=claim, result="ok",
        details={"evidence_ids": ids},
    )
    console.print(f"{OK} {claim} now linked to {', '.join(ids)}. Re-run verify and check.")

"""Pipeline controller.

Drives the six stages in order without holding domain logic itself: it wires
together the inference engine, vuln-class engine, severity calculator, integrity
verifier, and compliance enforcer. The CLI calls these methods; tests call them
directly with a ``MockLLMBackend``.
"""

from __future__ import annotations

from typing import Callable, Optional

from ..evidence import verifier
from ..evidence.ingester import verify_hash
from ..evidence.provenance import ProvenanceGraph
from ..inference.engine import run_inference
from ..llm_backends.base import LLMBackend
from ..output_formats import get_renderer
from ..program_packs import enforcer as compliance
from ..program_packs.loader import get_pack
from ..severity_frameworks import cvss_v31
from ..vuln_classes.engine import build_claims
from ..vuln_classes.loader import get_template
from .exceptions import LLMError
from .types import (
    CheckResult,
    ComplianceReport,
    Evidence,
    Field,
    IntegrityReport,
    Report,
    Session,
)

ProgressFn = Callable[[str, Field], None]

_SEVERITY_ORDER = {"pass": 0, "warn": 1, "block": 2}


def _worse(current: str, new: str) -> str:
    return new if _SEVERITY_ORDER[new] > _SEVERITY_ORDER[current] else current


class Orchestrator:
    def __init__(self, backend: LLMBackend) -> None:
        self.backend = backend

    # -- Stage 1: classification ------------------------------------------ #
    def classify(self, session: Session, description: str = "") -> dict:
        from ..inference.prompts import render_prompt

        evidence_block = "\n\n".join(
            f"[{e.id} | {e.type.value}]\n{(e.extracted_text or '')[:2000]}"
            for e in session.evidence
        )
        prompt = render_prompt("classify_vuln", evidence=evidence_block, description=description)
        return self.backend.complete(prompt, expected_format="json")

    # -- Stages 2 & 3: inference (elicitation happens in the CLI layer) ---- #
    def infer(self, vuln_class: str, evidence: list[Evidence], *, observer: Optional[ProgressFn] = None) -> dict[str, Field]:
        template = get_template(vuln_class)
        return run_inference(self.backend, template, evidence, observer=observer)

    # -- Build report from resolved fields -------------------------------- #
    def build_report(
        self,
        vuln_class: str,
        subtype: Optional[str],
        fields: dict[str, Field],
        evidence: list[Evidence],
        *,
        severity_vector: Optional[str] = None,
        title: Optional[str] = None,
    ) -> Report:
        template = get_template(vuln_class)
        claims = build_claims(template, fields, evidence, subtype=subtype)

        report = Report(
            vuln_class=vuln_class,
            subtype=subtype,
            title=title,
            fields=fields,
            claims=claims,
        )

        vector = severity_vector or (
            template.severity_hints.default_cvss_v31 if template.severity_hints else None
        )
        if vector:
            result = cvss_v31.base_score(vector)
            report.severity_vector = result.vector
            report.severity_score = result.score
            report.severity_rating = result.rating

        report.rebuild_provenance()
        return report

    # -- Stage 4: integrity verification ---------------------------------- #
    def verify_integrity(self, report: Report, evidence: list[Evidence], *, run_llm: bool = True) -> IntegrityReport:
        checks: list[CheckResult] = []
        graph = ProvenanceGraph.build(evidence, report.claims)

        # 1. Orphan check (hard, non-overridable).
        orphans = graph.orphans()
        if orphans:
            checks.append(CheckResult(
                name="orphan", status="block", overridable=False,
                message=(
                    f"Orphan claims with no evidence: {', '.join(c.id for c in orphans)}. "
                    "Link evidence with 'proofforge report link --claim <id> --evidence <ids>'."
                ),
            ))
        else:
            checks.append(CheckResult(name="orphan", status="pass", message="All claims have supporting evidence."))

        # 2. Evidence existence check.
        missing = graph.missing_evidence_refs()
        if missing:
            checks.append(CheckResult(
                name="evidence_exists", status="block", overridable=False,
                message=f"Claims reference unknown evidence: {missing}",
            ))
        else:
            checks.append(CheckResult(name="evidence_exists", status="pass", message="All referenced evidence exists."))

        # 3. Hash integrity check.
        tampered = [e.id for e in evidence if not verify_hash(e)]
        if tampered:
            checks.append(CheckResult(
                name="hash_integrity", status="block", overridable=False,
                message=f"Evidence content changed since registration: {', '.join(tampered)}",
            ))
        else:
            checks.append(CheckResult(name="hash_integrity", status="pass", message="Evidence hashes intact."))

        # 4 & 5. LLM-backed consistency + over-reach (advisory).
        if run_llm:
            ev_by_id = {e.id: e for e in evidence}
            for claim in report.claims:
                related = [ev_by_id[i] for i in claim.evidence_ids if i in ev_by_id]
                worst = "pass"
                notes: list[str] = []
                for ev in related:
                    # A failed or unreadable verdict means "unverified" (warn), never "pass".
                    try:
                        verdict = verifier.verify_claim_evidence(self.backend, claim, ev)
                    except LLMError as exc:
                        worst = _worse(worst, "warn")
                        notes.append(f"{ev.id}: could not be verified ({exc})")
                        continue
                    supports = verdict["supports"]
                    if supports == "false" and verdict["confidence"] >= 0.7:
                        worst = "block"
                        notes.append(f"{ev.id}: not supported ({verdict['reasoning']})")
                    elif supports == "false":
                        worst = _worse(worst, "warn")
                        notes.append(f"{ev.id}: possibly not supported ({verdict['reasoning']})")
                    elif supports == "partial":
                        worst = _worse(worst, "warn")
                        notes.append(f"{ev.id}: partial support")
                    elif supports is None:
                        worst = _worse(worst, "warn")
                        notes.append(f"{ev.id}: unclear verdict, not verified")
                if claim.category.value in ("impact_assertion", "vuln_assertion") and related:
                    try:
                        over = verifier.detect_overreach(self.backend, claim, related)
                    except LLMError as exc:
                        worst = _worse(worst, "warn")
                        notes.append(f"over-reach could not be checked ({exc})")
                    else:
                        if over["overreach"] is None:
                            worst = _worse(worst, "warn")
                            notes.append("over-reach verdict unclear, not checked")
                        elif over["overreach"] and over["confidence"] >= 0.7:
                            worst = _worse(worst, "warn")
                            notes.append(f"over-reach: {over['reasoning']}")
                checks.append(CheckResult(
                    name=f"consistency:{claim.id}",
                    status=worst,
                    message=notes[0] if notes else "Claim consistent with its evidence.",
                    details={"notes": notes},
                ))

        statuses = {c.status for c in checks}
        overall = "block" if "block" in statuses else "warn" if "warn" in statuses else "pass"
        actionable = [f"[{c.status}] {c.name}: {c.message}" for c in checks if c.status != "pass"]
        return IntegrityReport(checks_run=checks, overall_status=overall, actionable_items=actionable)

    # -- Stage 5: compliance ---------------------------------------------- #
    def check_compliance(self, session: Session, *, run_llm: bool = True) -> ComplianceReport:
        if session.report is None:
            raise ValueError("No report to check. Run 'proofforge report new' first.")
        pack = get_pack(session.program_id)
        report_text = self.render(session)
        backend = self.backend if run_llm else None
        return compliance.enforce(session.report, pack, report_text, backend=backend)

    # -- Stage 6: rendering ----------------------------------------------- #
    def render(self, session: Session) -> str:
        if session.report is None:
            raise ValueError("No report to render. Run 'proofforge report new' first.")
        pack = get_pack(session.program_id)
        renderer = get_renderer(pack.output_preferences.format)
        return renderer(
            session.report,
            session.evidence,
            include_cvss_vector=pack.output_preferences.include_cvss_vector,
        )

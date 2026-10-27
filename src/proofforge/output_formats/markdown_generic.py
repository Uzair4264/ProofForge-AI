"""Generic Markdown renderer (dual-audience)."""

from __future__ import annotations

from ..core.types import Evidence, Report
from . import base


def render(report: Report, evidence: list[Evidence], *, include_cvss_vector: bool = True) -> str:
    title = report.title or f"{report.vuln_class.upper()} vulnerability"
    parts: list[str] = [f"# {title}", ""]

    # --- Triager summary -------------------------------------------------- #
    parts.append("## Summary")
    if report.subtype:
        parts.append(f"- **Type:** {report.vuln_class} ({report.subtype})")
    else:
        parts.append(f"- **Type:** {report.vuln_class}")
    endpoint = report.field_value("affected_endpoint")
    if endpoint:
        parts.append(f"- **Affected endpoint:** {endpoint}")
    if report.severity_score is not None:
        vec = f" `{report.severity_vector}`" if (include_cvss_vector and report.severity_vector) else ""
        parts.append(f"- **Severity:** {report.severity_score} ({report.severity_rating}){vec}")
    parts.append("")

    # --- Vulnerability description ---------------------------------------- #
    vuln_claims = base.claims_by_category(report, "vuln_assertion")
    if vuln_claims:
        parts.append("## Vulnerability")
        for c in vuln_claims:
            refs = ", ".join(c.evidence_ids)
            parts.append(f"{c.text}" + (f" _(see {refs})_" if refs else ""))
        parts.append("")

    # --- Reproduction / details (generic across vuln classes) ------------- #
    parts.append("## Reproduction")
    for fid, field in report.fields.items():
        if fid in ("affected_endpoint", "impact_description"):
            continue
        if field.value in (None, ""):
            continue
        value = f"`{field.value}`" if field.field_type in ("string", "url") else field.value
        parts.append(f"- **{field.label}:** {value}")
    repro_claims = base.claims_by_category(report, "reproduction")
    for c in repro_claims:
        parts.append(f"- {c.text} _(see {', '.join(c.evidence_ids)})_")
    parts.append("")

    # --- Impact ----------------------------------------------------------- #
    impact_claims = base.claims_by_category(report, "impact_assertion")
    if impact_claims:
        parts.append("## Impact")
        for c in impact_claims:
            note = "" if c.author == "user" else " _(drafted — review for accuracy)_"
            parts.append(f"{c.text}{note} _(see {', '.join(c.evidence_ids)})_")
        parts.append("")

    # --- Developer detail: evidence --------------------------------------- #
    parts.append("## Evidence")
    parts.append(base.evidence_index(evidence))
    parts.append("")

    parts.append("---")
    parts.append(base.ATTRIBUTION)
    return "\n".join(parts) + "\n"

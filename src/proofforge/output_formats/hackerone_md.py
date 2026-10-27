"""HackerOne-flavored Markdown renderer.

Same dual-audience structure as the generic renderer, with section headings and
a CVSS line tuned to HackerOne's submission form conventions.
"""

from __future__ import annotations

from ..core.types import Evidence, Report
from . import base


def render(report: Report, evidence: list[Evidence], *, include_cvss_vector: bool = True) -> str:
    title = report.title or f"{report.vuln_class.upper()} on {report.field_value('affected_endpoint') or 'target'}"
    parts: list[str] = [f"# {title}", ""]

    parts.append("## Summary")
    subtype = f" ({report.subtype})" if report.subtype else ""
    parts.append(
        f"A {report.vuln_class}{subtype} vulnerability was identified"
        + (f" at {report.field_value('affected_endpoint')}." if report.field_value("affected_endpoint") else ".")
    )
    parts.append("")

    if report.severity_score is not None:
        parts.append("## Severity")
        vec = f"\n\nVector: `{report.severity_vector}`" if (include_cvss_vector and report.severity_vector) else ""
        parts.append(f"**{report.severity_rating}** — CVSS {report.severity_score}{vec}")
        parts.append("")

    parts.append("## Steps To Reproduce")
    endpoint = report.field_value("affected_endpoint")
    n = 1
    if endpoint:
        parts.append(f"{n}. Navigate to `{endpoint}`.")
        n += 1
    # Generic numbered detail steps from the remaining resolved fields.
    for fid, field in report.fields.items():
        if fid in ("affected_endpoint", "impact_description"):
            continue
        if field.value in (None, ""):
            continue
        value = f"`{field.value}`" if field.field_type in ("string", "url") else field.value
        parts.append(f"{n}. {field.label}: {value}")
        n += 1
    for c in base.claims_by_category(report, "reproduction"):
        parts.append(f"{n}. {c.text} (see {', '.join(c.evidence_ids)})")
        n += 1
    parts.append("")

    impact_claims = base.claims_by_category(report, "impact_assertion")
    if impact_claims:
        parts.append("## Impact")
        for c in impact_claims:
            note = "" if c.author == "user" else " _(AI-drafted — review for accuracy)_"
            parts.append(f"{c.text}{note}")
        parts.append("")

    parts.append("## Evidence")
    parts.append(base.evidence_index(evidence))
    parts.append("")

    parts.append("---")
    parts.append(base.attribution(report))
    return "\n".join(parts) + "\n"

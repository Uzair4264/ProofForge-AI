"""Evidence-derived severity ceiling for a report.

The ceiling starts at the template's default vector, or at the first
``ceiling_tiers`` entry whose field conditions hold. Each ``lift_rules`` entry
then lets one metric rise when its own conditions hold, so demonstrating one
kind of impact never lifts unrelated metrics.

Templates without ``lift_rules`` keep the older rule: any demonstrated,
evidence-linked impact claim allows every metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..core.types import FieldState, Report
from ..severity_frameworks import cvss_v31
from .schema import FieldConditions, LiftRule, VulnClassTemplate

_RESOLVED = (FieldState.INFERRED, FieldState.CONFIRMED, FieldState.USER_PROVIDED)
_MAX_VECTOR = "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"


def conditions_hold(conditions: FieldConditions, report: Report) -> bool:
    """True when every listed field is resolved to one of its accepted values."""
    for field_id, accepted in conditions.items():
        f = report.fields.get(field_id)
        if f is None or f.state not in _RESOLVED or f.value in (None, ""):
            return False
        if str(f.value).strip().lower() not in {a.lower() for a in accepted}:
            return False
    return True


def impact_demonstrated(report: Report) -> bool:
    return any(
        c.category.value == "impact_assertion" and c.basis == "demonstrated" and c.evidence_ids
        for c in report.claims
    )


def base_ceiling(template: VulnClassTemplate, report: Report) -> str | None:
    hints = template.severity_hints
    if hints is None:
        return None
    for tier in hints.ceiling_tiers:
        if conditions_hold(tier.when, report):
            return tier.ceiling
    return hints.default_cvss_v31


def _applies(rule: LiftRule, report: Report) -> bool:
    if rule.demonstrated and not impact_demonstrated(report):
        return False
    return conditions_hold(rule.when, report)


@dataclass
class Ceiling:
    vector: str                     # most severe vector the evidence allows
    base: str                       # tier or default, before any lift
    lifted: list[str] = field(default_factory=list)  # e.g. "C:H"
    legacy: bool = False


def allowed_ceiling(template: VulnClassTemplate, report: Report) -> Ceiling | None:
    base = base_ceiling(template, report)
    if base is None:
        return None
    rules = template.severity_hints.lift_rules
    if rules is None:
        vector = _MAX_VECTOR if impact_demonstrated(report) else base
        return Ceiling(vector=cvss_v31.base_score(vector).vector, base=base, legacy=True)

    vector = cvss_v31.base_score(base).vector
    lifted = []
    for rule in rules:
        if _applies(rule, report):
            raised = cvss_v31.raise_metric(vector, rule.metric, rule.to)
            if raised != vector:
                lifted.append(f"{rule.metric.upper()}:{rule.to.upper()}")
                vector = raised
    return Ceiling(vector=vector, base=base, lifted=lifted)


def lift_hints(template: VulnClassTemplate, escalations: list[str]) -> list[str]:
    """What each escalated metric would need, from the template's lift rules."""
    rules = (template.severity_hints.lift_rules if template.severity_hints else None) or []
    metrics = {e.split(":", 1)[0] for e in escalations}
    hints = []
    for rule in rules:
        if rule.metric.upper() in metrics and rule.note:
            hints.append(f"{rule.metric.upper()}:{rule.to.upper()} needs {rule.note}")
    return hints

"""Compliance enforcement (Gap 3, Stage 5).

Each check is a small function returning a ``CheckResult``. The enforcer runs
them in order and aggregates into a ``ComplianceReport``. Deterministic checks
run first; the LLM forbidden-content check is optional and advisory.
"""

from __future__ import annotations

import fnmatch
import re
from urllib.parse import urlparse

from ..core.types import CheckResult, ComplianceReport, Report
from ..llm_backends.base import LLMBackend
from ..severity_frameworks import cvss_v31
from .schema import RulePack

# Map a program's abstract required-field names to a presence predicate over the
# assembled Report. Keeps the rule pack vocabulary independent of template ids.
def _present_keys(report: Report) -> set[str]:
    keys: set[str] = set()
    if report.title:
        keys.add("vulnerability_title")
    if report.field_value("affected_endpoint"):
        keys.add("affected_endpoint")
    if any(c.category.value == "vuln_assertion" for c in report.claims):
        keys.add("vulnerability_description")
    if any(c.category.value == "reproduction" for c in report.claims):
        keys.add("reproduction_steps")
    if report.field_value("impact_description") or any(
        c.category.value == "impact_assertion" for c in report.claims
    ):
        keys.add("impact_demonstration")
    if report.severity_vector:
        keys.add("severity_rating")
    if report.field_value("remediation") or any(
        c.category.value == "remediation" for c in report.claims
    ):
        keys.add("remediation_suggestion")
    return keys


def _asset_matches(asset: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(asset, p) for p in patterns)


def check_scope(report: Report, pack: RulePack) -> CheckResult:
    endpoint = report.field_value("affected_endpoint")
    host = urlparse(str(endpoint)).netloc if endpoint else ""

    # Vuln type scope.
    vc = report.vuln_class
    if pack.scope.out_of_scope_vuln_types and vc in pack.scope.out_of_scope_vuln_types:
        return CheckResult(
            name="scope", status="block", overridable=False,
            message=f"Vuln type '{vc}' is explicitly out of scope.",
        )
    if pack.scope.in_scope_vuln_types and vc not in pack.scope.in_scope_vuln_types:
        return CheckResult(
            name="scope", status="block", overridable=False,
            message=f"Vuln type '{vc}' is not listed in scope.",
        )

    # Asset scope.
    if host and pack.scope.out_of_scope_assets and _asset_matches(host, pack.scope.out_of_scope_assets):
        return CheckResult(
            name="scope", status="block", overridable=False,
            message=f"Asset '{host}' is explicitly out of scope.",
        )
    if host and pack.scope.in_scope_assets and not _asset_matches(host, pack.scope.in_scope_assets):
        return CheckResult(
            name="scope", status="block", overridable=False,
            message=f"Asset '{host}' does not match any in-scope asset.",
        )

    return CheckResult(name="scope", status="pass", message=f"Asset and vuln type in scope ({vc}).")


def check_required_fields(report: Report, pack: RulePack) -> CheckResult:
    present = _present_keys(report)
    missing = [f for f in pack.required_fields if f not in present]
    if missing:
        return CheckResult(
            name="required_fields", status="warn",
            message=f"Missing required fields: {', '.join(missing)}",
            details={"missing": missing},
        )
    return CheckResult(name="required_fields", status="pass", message="All required fields present.")


def check_forbidden_regex(report_text: str, pack: RulePack) -> CheckResult:
    hits = []
    for pat in pack.forbidden_content.patterns:
        if pat.type != "regex":
            continue
        try:
            if re.search(pat.pattern, report_text):
                hits.append(pat.description or pat.pattern)
        except re.error:
            continue
    if hits:
        return CheckResult(
            name="forbidden_content_regex", status="warn",
            message=f"Potential forbidden content: {'; '.join(hits)}",
            details={"matches": hits},
        )
    return CheckResult(name="forbidden_content_regex", status="pass", message="No forbidden patterns matched.")


def check_forbidden_llm(report_text: str, pack: RulePack, backend: LLMBackend | None) -> CheckResult | None:
    if not pack.forbidden_content.llm_checks or backend is None:
        return None
    from ..inference.prompts import render_prompt

    prompt = render_prompt(
        "forbidden_content",
        report_text=report_text[:6000],
        checks="\n".join(f"- {c}" for c in pack.forbidden_content.llm_checks),
    )
    try:
        result = backend.complete(prompt, expected_format="json")
    except Exception:  # noqa: BLE001 - advisory check, never blocks
        return CheckResult(name="forbidden_content_llm", status="pass", message="LLM check skipped (backend error).")
    violations = result.get("violations") or []
    if violations:
        descs = "; ".join(v.get("check", "?") for v in violations)
        return CheckResult(
            name="forbidden_content_llm", status="warn",
            message=f"LLM flagged possible forbidden content: {descs}",
            details={"violations": violations},
        )
    return CheckResult(name="forbidden_content_llm", status="pass", message="LLM found no forbidden content.")


def check_severity(report: Report, pack: RulePack) -> CheckResult:
    if not report.severity_vector:
        return CheckResult(
            name="severity", status="warn",
            message="No severity vector provided.",
        )
    try:
        result = cvss_v31.base_score(report.severity_vector)
    except Exception as exc:  # noqa: BLE001
        return CheckResult(name="severity", status="warn", message=f"Severity vector invalid: {exc}")
    if report.severity_score is not None and abs(report.severity_score - result.score) > 0.05:
        return CheckResult(
            name="severity", status="warn",
            message=(
                f"Claimed score {report.severity_score} differs from recomputed "
                f"{result.score}. Suggest correcting to {result.score} ({result.rating})."
            ),
            details={"recomputed": result.score, "rating": result.rating},
        )
    return CheckResult(
        name="severity", status="pass",
        message=f"Severity {result.score} ({result.rating}) validated against {pack.severity_framework}.",
    )


def check_disclosure(report: Report, pack: RulePack) -> CheckResult:
    if pack.disclosure_rules.must_include_disclosure_statement:
        return CheckResult(
            name="disclosure", status="warn",
            message=f"Program requires a disclosure statement (embargo {pack.disclosure_rules.embargo_days} days).",
        )
    return CheckResult(name="disclosure", status="pass", message="No disclosure statement required.")


def enforce(
    report: Report,
    pack: RulePack,
    report_text: str,
    *,
    backend: LLMBackend | None = None,
) -> ComplianceReport:
    checks: list[CheckResult] = [
        check_scope(report, pack),
        check_required_fields(report, pack),
        check_forbidden_regex(report_text, pack),
    ]
    llm_check = check_forbidden_llm(report_text, pack, backend)
    if llm_check is not None:
        checks.append(llm_check)
    checks.append(check_severity(report, pack))
    checks.append(check_disclosure(report, pack))

    statuses = {c.status for c in checks}
    overall = "block" if "block" in statuses else "warn" if "warn" in statuses else "pass"
    actionable = [f"[{c.status}] {c.name}: {c.message}" for c in checks if c.status != "pass"]

    return ComplianceReport(
        program_id=pack.program_id,
        checks_run=checks,
        overall_status=overall,
        actionable_items=actionable,
    )

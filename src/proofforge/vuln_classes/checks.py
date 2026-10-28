"""Deterministic evidence checks a template opts into via ``evidence_checks``.

Each check reads the captured evidence only (no LLM) and returns a
``CheckResult``, or ``None`` when it does not apply to this report. They warn,
never block: a capture can be incomplete without the finding being false.
"""

from __future__ import annotations

import hashlib
from typing import Callable, Optional

from ..core.types import CheckResult, Evidence, Report

CheckFn = Callable[[Report, list[Evidence]], Optional[CheckResult]]

# Request headers that carry who the requester is.
_CREDENTIAL_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token", "x-access-token")
ANONYMOUS = "anonymous"


def _of_type(evidence: list[Evidence], kind: str) -> list[Evidence]:
    return [e for e in evidence if e.type.value == kind]


def _headers(ev: Evidence) -> dict[str, str]:
    raw = ev.metadata.get("headers") or {}
    return {str(k).strip().lower(): str(v).strip() for k, v in raw.items()}


def identity(ev: Evidence) -> str:
    """Short fingerprint of a request's credentials, or ``anonymous``.

    Only a hash is kept, so token values never reach reports or logs.
    """
    headers = _headers(ev)
    creds = sorted(f"{h}={headers[h]}" for h in _CREDENTIAL_HEADERS if headers.get(h))
    if not creds:
        return ANONYMOUS
    return hashlib.sha256("\n".join(creds).encode()).hexdigest()[:12]


def check_distinct_identities(report: Report, evidence: list[Evidence]) -> CheckResult:
    """The finding compares two principals, so the requests must come from two."""
    requests = _of_type(evidence, "http_request")
    name = "evidence:distinct_identities"
    if len(requests) < 2:
        return CheckResult(
            name=name, status="warn",
            message="Only one request captured. Add the same call from a second account or role "
                    "(the baseline) so the access difference can be checked.",
        )
    ids = {e.id: identity(e) for e in requests}
    distinct = set(ids.values())
    if len(distinct) < 2:
        return CheckResult(
            name=name, status="warn",
            message=f"All {len(requests)} requests carry the same credentials. Capture at least one "
                    f"request as a different account or role.",
            details={"identities": ids},
        )
    anon = " (one is unauthenticated)" if ANONYMOUS in distinct else ""
    return CheckResult(
        name=name, status="pass",
        message=f"Requests come from {len(distinct)} distinct identities{anon}.",
        details={"identities": ids},
    )


CHECKS: dict[str, CheckFn] = {
    "distinct_identities": check_distinct_identities,
}


def run(names: list[str], report: Report, evidence: list[Evidence]) -> list[CheckResult]:
    results = []
    for check_name in names:
        result = CHECKS[check_name](report, evidence)
        if result is not None:
            results.append(result)
    return results

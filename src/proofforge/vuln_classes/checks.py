"""Deterministic evidence checks a template opts into via ``evidence_checks``.

Each check reads the captured evidence only (no LLM) and returns a
``CheckResult``, or ``None`` when it does not apply to this report. They warn,
never block: a capture can be incomplete without the finding being false.
"""

from __future__ import annotations

import hashlib
import re
from typing import Callable, Optional
from urllib.parse import urlsplit

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


def _field_is(report: Report, field_id: str, value: str) -> bool:
    return str(report.field_value(field_id) or "").strip().lower() == value


def _route(ev: Evidence) -> tuple[str, str]:
    return (str(ev.metadata.get("method", "")).upper(), str(ev.metadata.get("path", "")))


def _response_shape(ev: Evidence) -> tuple[int | None, int]:
    return ev.metadata.get("status_code"), len(str(ev.metadata.get("body", "")))


def _shapes_differ(a: tuple[int | None, int], b: tuple[int | None, int]) -> bool:
    """Different status, or a body length gap beyond normal page noise."""
    if a[0] != b[0]:
        return True
    return abs(a[1] - b[1]) > max(10, 0.02 * max(a[1], b[1]))


def check_boolean_pairs(report: Report, evidence: list[Evidence]) -> CheckResult | None:
    """Blind boolean SQLi: a true and a false condition must answer differently."""
    if not _field_is(report, "sqli_subtype", "blind_boolean"):
        return None
    name = "evidence:boolean_pairs"
    requests = _of_type(evidence, "http_request")
    responses = _of_type(evidence, "http_response")
    if len(requests) < 2 or len(responses) < 2:
        return CheckResult(
            name=name, status="warn",
            message="Blind boolean SQLi needs a true-condition and a false-condition request with "
                    "their responses (e.g. AND 1=1 vs AND 1=2); fewer than two of each are captured.",
        )
    routes = [_route(r) for r in requests]
    if len(set(routes)) == len(routes):
        return CheckResult(
            name=name, status="warn",
            message="The requests hit different endpoints. The true/false pair must be the same "
                    "request with only the condition changed.",
        )
    shapes = {r.id: _response_shape(r) for r in responses}
    values = list(shapes.values())
    differing = any(_shapes_differ(a, b) for i, a in enumerate(values) for b in values[i + 1:])
    if not differing:
        return CheckResult(
            name=name, status="warn",
            message="All responses have the same status and length, so the captures do not show the "
                    "condition changing the response.",
            details={"responses": shapes},
        )
    matching = any(not _shapes_differ(a, b) for i, a in enumerate(values) for b in values[i + 1:])
    if len(values) >= 3 and not matching:
        return CheckResult(
            name=name, status="warn",
            message="Every response differs from every other, which looks like natural variance. "
                    "A repeated true condition should match the baseline.",
            details={"responses": shapes},
        )
    tip = "" if matching else " Add a baseline or a repeated true request to rule out natural variance."
    return CheckResult(
        name=name, status="pass",
        message=f"True/false responses differ in status or length on the same endpoint.{tip}",
        details={"responses": shapes},
    )


_NUMBER_RE = re.compile(r"\d+(?:\.\d+)?")


def parse_timings(text: str) -> tuple[list[float], dict[float, list[float]]]:
    """Parse "baseline: 0.2, 0.3; 5: 5.1, 5.2" into baseline and per-delay samples.

    Raises ValueError on a segment it cannot read.
    """
    baseline: list[float] = []
    delays: dict[float, list[float]] = {}
    for segment in re.split(r"[;\n]", text):
        if not segment.strip():
            continue
        label, sep, values = segment.partition(":")
        if not sep:
            raise ValueError(f"missing ':' in {segment.strip()!r}")
        samples = [float(v) for v in _NUMBER_RE.findall(values)]
        if not samples:
            raise ValueError(f"no timings in {segment.strip()!r}")
        if label.strip().lower() in ("baseline", "base", "normal"):
            baseline.extend(samples)
            continue
        delay = _NUMBER_RE.search(label)
        if delay is None:
            raise ValueError(f"label {label.strip()!r} is neither 'baseline' nor a delay")
        delays.setdefault(float(delay.group()), []).extend(samples)
    return baseline, delays


def check_timing_scaling(report: Report, evidence: list[Evidence]) -> CheckResult | None:
    """Time-based SQLi: each delay tracks its payload, above a quiet baseline."""
    if not _field_is(report, "sqli_subtype", "blind_time"):
        return None
    name = "evidence:timing_scaling"
    text = report.field_value("timing_measurements")
    if not text:
        return CheckResult(
            name=name, status="warn",
            message="Time-based SQLi without timing measurements. Record a baseline and at least two "
                    "delays in the timing_measurements field (ProofForge never replays requests).",
        )
    try:
        baseline, delays = parse_timings(str(text))
    except ValueError as exc:
        return CheckResult(name=name, status="warn", message=f"Could not read timing_measurements: {exc}.")
    problems = []
    if len(baseline) < 2:
        problems.append("fewer than two baseline samples")
    if len(delays) < 2:
        problems.append("fewer than two different delay values, so scaling cannot be shown")
    for delay, samples in sorted(delays.items()):
        if len(samples) < 2:
            problems.append(f"the {delay:g}s delay was measured only once")
    if baseline and delays and max(baseline) >= 0.5 * min(delays):
        problems.append(f"baseline up to {max(baseline):g}s is too noisy for a {min(delays):g}s delay")
    if baseline:
        base = sorted(baseline)[len(baseline) // 2]
        for delay, samples in sorted(delays.items()):
            # Each sample, minus the normal response time, should be about the delay.
            off = [s for s in samples if not (0.8 * delay <= s - base <= delay + max(2.0, 0.5 * delay))]
            if off:
                problems.append(f"{delay:g}s delay: {', '.join(f'{s:g}' for s in off)}s do not match")
    details = {"baseline": baseline, "delays": {f"{k:g}": v for k, v in delays.items()}}
    if problems:
        return CheckResult(
            name=name, status="warn",
            message="Timing measurements do not prove a time-based injection: " + "; ".join(problems) + ".",
            details=details,
        )
    return CheckResult(
        name=name, status="pass",
        message=f"Recorded delays track the payload ({', '.join(f'{d:g}s' for d in sorted(delays))}) "
                f"above a {max(baseline):g}s baseline. These are researcher-entered timings.",
        details=details,
    )


_META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*?url\s*=\s*([^"'>\s]+)""",
    re.IGNORECASE,
)


def _host(url: str) -> str:
    """Host a browser would go to, or "" for a same-site relative path."""
    text = url.strip().replace("\\", "/")  # browsers read "/\evil" as "//evil"
    if "://" not in text and not text.startswith("//"):
        return ""
    return (urlsplit(text if "://" in text else f"https:{text}").hostname or "").lower()


def _same_site(host: str, target: str) -> bool:
    # Approximation without the public-suffix list: same last two labels.
    site = ".".join(target.split(".")[-2:])
    return host == target or host == site or host.endswith("." + site)


def check_redirect_offsite(report: Report, evidence: list[Evidence]) -> CheckResult:
    """Open redirect: a captured response must send the browser off the target's site."""
    name = "evidence:redirect_offsite"
    requests = _of_type(evidence, "http_request")
    responses = _of_type(evidence, "http_response")
    target = ""
    for source in [str(r.metadata.get("url", "")) for r in requests] + [str(report.field_value("affected_endpoint") or "")]:
        target = _host(source)
        if target:
            break
    if not responses or not target:
        return CheckResult(
            name=name, status="warn",
            message="Capture the request to the target and the response that redirects, so the "
                    "destination can be checked.",
        )
    destinations = []
    for ev in responses:
        status = ev.metadata.get("status_code")
        location = _headers(ev).get("location")
        if location and isinstance(status, int) and 300 <= status < 400:
            destinations.append(location)
        destinations += _META_REFRESH_RE.findall(str(ev.metadata.get("body", "")))
    if not destinations:
        return CheckResult(
            name=name, status="warn",
            message="No 3xx Location or meta refresh in the captured responses. A JavaScript "
                    "redirect needs a browser capture (screenshot) of the final URL.",
        )
    offsite = [(d, _host(d)) for d in destinations if _host(d) and not _same_site(_host(d), target)]
    if not offsite:
        return CheckResult(
            name=name, status="warn",
            message=f"Every captured redirect stays on {target}'s site, so no open redirect is shown.",
            details={"destinations": destinations},
        )
    return CheckResult(
        name=name, status="pass",
        message=f"Redirects to {offsite[0][1]}, outside {target}'s site.",
        details={"destinations": destinations, "target": target},
    )


CHECKS: dict[str, CheckFn] = {
    "distinct_identities": check_distinct_identities,
    "boolean_pairs": check_boolean_pairs,
    "timing_scaling": check_timing_scaling,
    "redirect_offsite": check_redirect_offsite,
}


def run(names: list[str], report: Report, evidence: list[Evidence]) -> list[CheckResult]:
    results = []
    for check_name in names:
        result = CHECKS[check_name](report, evidence)
        if result is not None:
            results.append(result)
    return results

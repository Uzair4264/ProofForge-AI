"""Deterministic CVSS v3.1 base-score calculator.

Implements the official base-metric formula (FIRST.org CVSS v3.1 spec), including
the spec's exact ``Roundup`` function. Temporal/environmental metrics are out of
scope for v0 — only the base score is computed.
"""

from __future__ import annotations

import math

from ..core.exceptions import SeverityError
from .base import SeverityFramework, SeverityResult

# Metric weights.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.00}
# PR depends on Scope.
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

_REQUIRED = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]


def parse_vector(vector: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into a metric->value mapping.

    Accepts an optional ``CVSS:3.1/`` prefix. Raises ``SeverityError`` on
    missing or unknown base metrics.
    """
    raw = vector.strip()
    if raw.upper().startswith("CVSS:"):
        # Drop the "CVSS:3.x" prefix segment.
        raw = raw.split("/", 1)[1] if "/" in raw else ""
    metrics: dict[str, str] = {}
    for part in raw.split("/"):
        if not part:
            continue
        if ":" not in part:
            raise SeverityError(f"Malformed metric segment: {part!r}")
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()

    for metric in _REQUIRED:
        if metric not in metrics:
            raise SeverityError(f"Missing required base metric: {metric}")
    return metrics


def roundup(value: float) -> float:
    """CVSS v3.1 Roundup: round up to one decimal place (spec algorithm)."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (math.floor(int_input / 10000) + 1) / 10


def rating_for(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def base_score(vector: str) -> SeverityResult:
    m = parse_vector(vector)

    scope_changed = m["S"] == "C"
    try:
        av = _AV[m["AV"]]
        ac = _AC[m["AC"]]
        ui = _UI[m["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[m["PR"]]
        c = _CIA[m["C"]]
        i = _CIA[m["I"]]
        a = _CIA[m["A"]]
    except KeyError as exc:
        raise SeverityError(f"Unknown metric value: {exc}") from exc

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
    else:
        impact = 6.42 * isc_base

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        score = 0.0
    elif scope_changed:
        score = roundup(min(1.08 * (impact + exploitability), 10))
    else:
        score = roundup(min(impact + exploitability, 10))

    # Normalize the vector to canonical ordered form.
    normalized = "/".join(f"{k}:{m[k]}" for k in _REQUIRED)
    return SeverityResult(vector=normalized, score=score, rating=rating_for(score))


# Metric values from least to most severe.
_SEVERITY_ORDER = {
    "AV": ["P", "L", "A", "N"],
    "AC": ["H", "L"],
    "PR": ["H", "L", "N"],
    "UI": ["R", "N"],
    "S": ["U", "C"],
    "C": ["N", "L", "H"],
    "I": ["N", "L", "H"],
    "A": ["N", "L", "H"],
}


def escalations(claimed: str, baseline: str) -> list[str]:
    """Metrics where ``claimed`` is more severe than ``baseline``, as "C:L->H"."""
    c, b = parse_vector(claimed), parse_vector(baseline)
    out = []
    for metric in _REQUIRED:
        order = _SEVERITY_ORDER[metric]
        if c[metric] not in order or b[metric] not in order:
            raise SeverityError(f"Unknown metric value for {metric}")
        if order.index(c[metric]) > order.index(b[metric]):
            out.append(f"{metric}:{b[metric]}->{c[metric]}")
    return out


def raise_metric(vector: str, metric: str, value: str) -> str:
    """``vector`` with ``metric`` raised to ``value`` (never lowered)."""
    m = parse_vector(vector)
    metric, value = metric.upper(), value.upper()
    order = _SEVERITY_ORDER.get(metric)
    if order is None or value not in order:
        raise SeverityError(f"Unknown metric value {metric}:{value}")
    if order.index(value) > order.index(m[metric]):
        m[metric] = value
    return "/".join(f"{k}:{m[k]}" for k in _REQUIRED)


def cap_vector(claimed: str, ceiling: str) -> str:
    """``claimed`` with every metric lowered to at most ``ceiling``'s severity."""
    c, ceil = parse_vector(claimed), parse_vector(ceiling)
    capped = {}
    for metric in _REQUIRED:
        order = _SEVERITY_ORDER[metric]
        capped[metric] = min(c[metric], ceil[metric], key=order.index)
    return "/".join(f"{k}:{capped[k]}" for k in _REQUIRED)


class CVSSv31(SeverityFramework):
    id = "cvss_v3.1"

    def score(self, vector: str) -> SeverityResult:
        return base_score(vector)

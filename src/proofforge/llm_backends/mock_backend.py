"""Deterministic mock backend for offline runs and tests.

The mock keys its canned JSON off the ``PROMPT_ID:`` marker that every prompt
template carries on its first line (see ``prompts/``). This lets the full
pipeline run end-to-end with no model installed, and makes tests reproducible.

The canned values are tuned for the XSS fixture in ``tests/fixtures/`` (a
reflected ``<script>alert(1)</script>`` in ``/search?q=``).
"""

from __future__ import annotations

import json
import re

from .base import LLMBackend

_PROMPT_ID_RE = re.compile(r"^PROMPT_ID:\s*(\S+)", re.MULTILINE)

# Canned responses keyed by prompt id. Values are JSON-serializable dicts.
_CANNED: dict[str, dict] = {
    "classify_vuln": {
        "vuln_class": "xss",
        "subtype": "reflected",
        "confidence": 0.91,
        "reasoning": "Reflected script payload echoed unescaped in an HTML response.",
    },
    "infer_endpoint_from_request": {
        # Fallback only — _raw_complete prefers parsing the real host/target from the
        # evidence so offline dry-runs reflect the actual target (see _parse_endpoint).
        "value": "https://api.example.com/search?q=",
        "confidence": 0.92,
        "reasoning": "Request line targets GET /search?q= on host api.example.com.",
    },
    "infer_xss_vector": {
        "value": "url_param",
        "confidence": 0.9,
        "reasoning": "Payload is carried in the q query-string parameter.",
    },
    "extract_xss_payload": {
        "value": "<script>alert(1)</script>",
        "confidence": 0.95,
        "reasoning": "The q parameter value is the script payload.",
    },
    "infer_xss_context": {
        "value": "html_body",
        "confidence": 0.88,
        "reasoning": "Payload appears between <div> tags in the response body.",
    },
    "draft_xss_impact": {
        "value": (
            "An attacker can execute arbitrary JavaScript in the victim's browser "
            "in the context of example.com when the victim opens a crafted link."
        ),
        "confidence": 0.6,
        "reasoning": "Reflected execution is demonstrated; downstream impact is a draft for review.",
    },
    # --- SSRF ---
    "infer_ssrf_param": {
        "value": "url", "confidence": 0.85,
        "reasoning": "The 'url' parameter value is fetched server-side.",
    },
    "infer_ssrf_target": {
        "value": "http://169.254.169.254/latest/meta-data/", "confidence": 0.82,
        "reasoning": "Request coerces the server to fetch the cloud metadata endpoint.",
    },
    "infer_ssrf_internal_reach": {
        "value": "demonstrated", "confidence": 0.8,
        "reasoning": "Response contains internal metadata content.",
    },
    "draft_ssrf_impact": {
        "value": "An attacker can coerce the server into requesting internal/cloud resources, exposing metadata.",
        "confidence": 0.6,
        "reasoning": "Server-side fetch demonstrated; full credential theft would need more evidence.",
    },
    # --- IDOR ---
    "infer_idor_identifier": {
        "value": "id=1042 (sequential integer)", "confidence": 0.85,
        "reasoning": "Numeric object id is incremented to reach another record.",
    },
    "infer_idor_authz": {
        "value": "broken_object_level", "confidence": 0.8,
        "reasoning": "Endpoint returns the object without verifying ownership.",
    },
    "infer_idor_cross_account": {
        "value": "single_account", "confidence": 0.75,
        "reasoning": "Another object id was accessed; second-account proof not shown.",
    },
    "infer_idor_access": {
        "value": "read", "confidence": 0.8,
        "reasoning": "The response returns the record; no change is shown.",
    },
    "infer_idor_sensitivity": {
        "value": "personal_data", "confidence": 0.75,
        "reasoning": "The record includes another user's email address.",
    },
    "draft_idor_impact": {
        "value": "An attacker can read another user's record by changing the object id.",
        "confidence": 0.6,
        "reasoning": "Cross-object access demonstrated; mass enumeration not shown.",
    },
    # --- CSRF ---
    "infer_csrf_action": {
        "value": "account_modification", "confidence": 0.8,
        "reasoning": "Request changes account email without anti-CSRF protection.",
    },
    "infer_csrf_protection": {
        "value": "none", "confidence": 0.8,
        "reasoning": "No CSRF token or SameSite protection present on the request.",
    },
    "infer_csrf_state_change": {
        "value": "demonstrated", "confidence": 0.78,
        "reasoning": "Response confirms the action took effect.",
    },
    "draft_csrf_impact": {
        "value": "An attacker can force a logged-in victim to change their account email cross-origin.",
        "confidence": 0.6,
        "reasoning": "State change demonstrated; account takeover chain would need more evidence.",
    },
    # --- SQLi ---
    "infer_sqli_point": {
        "value": "url_param", "confidence": 0.85,
        "reasoning": "Payload is injected via a query-string parameter.",
    },
    "infer_sqli_subtype": {
        "value": "union_based", "confidence": 0.8,
        "reasoning": "Response returns data via a UNION SELECT.",
    },
    "infer_sqli_db": {
        "value": "MySQL", "confidence": 0.7,
        "reasoning": "Error/version signature matches MySQL.",
    },
    "infer_sqli_impact": {
        "value": "data_extraction", "confidence": 0.8,
        "reasoning": "Injection returns data the user should not see.",
    },
    "draft_sqli_impact": {
        "value": "An attacker can extract arbitrary data from the backend database via the injectable parameter.",
        "confidence": 0.6,
        "reasoning": "Data extraction demonstrated; auth bypass/RCE not shown.",
    },
    # --- Information disclosure ---
    "infer_disclosure_type": {
        "value": "config_backup_file", "confidence": 0.8,
        "reasoning": "The response is an environment file with configuration values.",
    },
    "infer_disclosure_classification": {
        "value": "secret_unverified", "confidence": 0.75,
        "reasoning": "A credential-like value is exposed; nothing shows it works.",
    },
    "infer_disclosure_scope": {
        "value": "org_wide", "confidence": 0.7,
        "reasoning": "The file holds the organization's own configuration.",
    },
    "draft_disclosure_impact": {
        "value": "An unauthenticated attacker can read the application's configuration file, "
                 "which contains a credential-like value that has not been shown to work.",
        "confidence": 0.6,
        "reasoning": "Exposure demonstrated; whether the secret is live is not shown.",
    },
    "verify_claim": {
        "supports": "true",
        "confidence": 0.9,
        "reasoning": "Evidence directly demonstrates the asserted behavior.",
        "missing_for_full_support": "",
    },
    "detect_overreach": {
        "overreach": False,
        "confidence": 0.85,
        "reasoning": "Claim scope matches what the evidence demonstrates.",
    },
    "forbidden_content": {
        "violations": [],
        "confidence": 0.9,
        "reasoning": "No PII or raw scanner output detected.",
    },
}


_HOST_RE = re.compile(r"(?im)^\s*Host:\s*(\S+)")
_REQLINE_RE = re.compile(r"(?im)^\s*(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP")


def _parse_endpoint(prompt: str) -> dict | None:
    """Best-effort: derive the affected endpoint from a real request in the prompt.

    Lets offline dry-runs reflect the actual target host (e.g. Juice Shop) instead of
    a fixed canned value, so the scope check behaves realistically. Returns None when
    the prompt has no parseable request line (the caller falls back to the canned value).
    """
    req = _REQLINE_RE.search(prompt)
    if not req:
        return None
    target = req.group(1)
    if target.startswith("http://") or target.startswith("https://"):
        value = target
    else:
        host_match = _HOST_RE.search(prompt)
        if not host_match:
            return None
        value = f"https://{host_match.group(1)}{target}"
    return {"value": value, "confidence": 0.92, "reasoning": "Parsed host/target from the request."}


class MockLLMBackend(LLMBackend):
    name = "mock"

    def _raw_complete(self, prompt: str) -> str:
        match = _PROMPT_ID_RE.search(prompt)
        prompt_id = match.group(1) if match else ""
        if prompt_id == "infer_endpoint_from_request":
            parsed = _parse_endpoint(prompt)
            if parsed is not None:
                return json.dumps(parsed)
        canned = _CANNED.get(prompt_id)
        if canned is None:
            # Unknown prompt: return an explicit low-confidence "uncertain" so the
            # inference engine degrades gracefully to asking the user.
            canned = {"value": None, "confidence": 0.0, "reasoning": "mock: no canned response"}
        return json.dumps(canned)

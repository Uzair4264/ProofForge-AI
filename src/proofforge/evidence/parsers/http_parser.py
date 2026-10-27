"""Parse raw HTTP requests/responses and cURL commands.

Returns ``(extracted_text, metadata)``. Metadata is parser-specific and feeds
both inference (e.g., URL, method) and rendering. Best-effort: unparseable
content still yields the raw text with empty structured metadata.
"""

from __future__ import annotations

import re
import shlex
from typing import Any
from urllib.parse import urlparse

_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)\s+HTTP/(\d(?:\.\d)?)",
    re.IGNORECASE,
)
_STATUS_LINE_RE = re.compile(r"^HTTP/(\d(?:\.\d)?)\s+(\d{3})\s*(.*)$", re.IGNORECASE)


def _split_headers_body(text: str) -> tuple[list[str], str]:
    # Headers and body are separated by a blank line.
    parts = re.split(r"\r?\n\r?\n", text, maxsplit=1)
    head = parts[0].splitlines()
    body = parts[1] if len(parts) > 1 else ""
    return head, body


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def parse_curl(text: str) -> dict[str, Any]:
    """Parse a cURL command line into HTTP metadata."""
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        return {}
    meta: dict[str, Any] = {"method": "GET", "headers": {}, "format": "curl"}
    headers: dict[str, str] = {}
    it = iter(range(len(tokens)))
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-X", "--request") and i + 1 < len(tokens):
            meta["method"] = tokens[i + 1].upper()
            i += 2
            continue
        if tok in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                k, _, v = raw.partition(":")
                headers[k.strip()] = v.strip()
            i += 2
            continue
        if tok in ("-d", "--data", "--data-raw") and i + 1 < len(tokens):
            meta["body"] = tokens[i + 1]
            if meta["method"] == "GET":
                meta["method"] = "POST"
            i += 2
            continue
        if tok.startswith("http://") or tok.startswith("https://"):
            meta["url"] = tok
            parsed = urlparse(tok)
            meta["host"] = parsed.netloc
            meta["path"] = parsed.path
            meta["query"] = parsed.query
        i += 1
    meta["headers"] = headers
    return meta


def parse(text: str) -> tuple[str, dict[str, Any]]:
    """Parse raw HTTP request/response text or a cURL command."""
    stripped = text.strip()
    if stripped.lower().startswith("curl "):
        return text, parse_curl(stripped)

    head, body = _split_headers_body(text)
    if not head:
        return text, {}

    first = head[0].strip()
    meta: dict[str, Any] = {}

    req = _REQUEST_LINE_RE.match(first)
    if req:
        method, target, version = req.groups()
        headers = _parse_headers(head[1:])
        host = headers.get("Host", "")
        meta.update({
            "kind": "request",
            "method": method.upper(),
            "target": target,
            "http_version": version,
            "headers": headers,
            "host": host,
            "body": body.strip(),
        })
        if target.startswith("http"):
            parsed = urlparse(target)
            meta["url"] = target
            meta["path"] = parsed.path
            meta["query"] = parsed.query
        else:
            parsed = urlparse(target)
            meta["path"] = parsed.path
            meta["query"] = parsed.query
            if host:
                scheme = "https"
                meta["url"] = f"{scheme}://{host}{target}"
        return text, meta

    status = _STATUS_LINE_RE.match(first)
    if status:
        version, code, reason = status.groups()
        headers = _parse_headers(head[1:])
        meta.update({
            "kind": "response",
            "http_version": version,
            "status_code": int(code),
            "reason": reason.strip(),
            "headers": headers,
            "content_type": headers.get("Content-Type", ""),
            "body": body,
        })
        return text, meta

    return text, {}

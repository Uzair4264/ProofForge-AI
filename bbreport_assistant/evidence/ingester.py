"""Evidence ingestion: file -> structured ``Evidence`` with provenance metadata.

Computes a SHA-256 content hash, dispatches to the appropriate parser by
evidence type, and assigns a default sensitivity. Binary types (screenshots,
video) are hashed from raw bytes; text types are read as UTF-8.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from ..core.exceptions import EvidenceError
from ..core.paths import validate_input_path
from ..core.types import Evidence, EvidenceType, SensitivityLevel
from .parsers import http_parser, image_parser, text_parser

_BINARY_TYPES = {EvidenceType.SCREENSHOT, EvidenceType.VIDEO}
_HTTP_TYPES = {EvidenceType.HTTP_REQUEST, EvidenceType.HTTP_RESPONSE}


def _hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's raw bytes."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def ingest(
    *,
    evidence_id: str,
    file: str | Path,
    evidence_type: EvidenceType,
    sensitivity: SensitivityLevel = SensitivityLevel.SENSITIVE,
    notes: str | None = None,
) -> Evidence:
    """Ingest a single evidence file into an ``Evidence`` object."""
    path = validate_input_path(file)
    if not path.exists() or not path.is_file():
        raise EvidenceError(f"Evidence file not found: {path}")

    content_hash = hash_file(path)
    extracted_text: str | None = None
    metadata: dict = {}

    if evidence_type in _BINARY_TYPES:
        if evidence_type == EvidenceType.SCREENSHOT:
            extracted_text, metadata = image_parser.parse(path)
        else:
            extracted_text = f"Video: {path.name}"
            metadata = {"format": path.suffix.lstrip(".")}
    else:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise EvidenceError(f"Cannot read evidence file {path}: {exc}") from exc
        if evidence_type in _HTTP_TYPES:
            extracted_text, metadata = http_parser.parse(raw)
        else:
            extracted_text, metadata = text_parser.parse(raw)

    return Evidence(
        id=evidence_id,
        type=evidence_type,
        source_path=str(path),
        content_hash=content_hash,
        sensitivity=sensitivity,
        extracted_text=extracted_text,
        metadata=metadata,
        captured_at=datetime.now(timezone.utc),
        notes=notes,
    )


def verify_hash(evidence: Evidence) -> bool:
    """Recompute the hash of the source file and compare to the recorded one."""
    path = Path(evidence.source_path)
    if not path.exists():
        return False
    return hash_file(path) == evidence.content_hash

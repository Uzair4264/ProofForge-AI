"""Hash chaining for tamper-evident audit logs (spec §11).

Each entry's ``entry_hash`` is the SHA-256 of its content plus the previous
entry's hash. The genesis entry uses an all-zero previous hash.
"""

from __future__ import annotations

import hashlib
import json

from ..core.types import AuditEntry

GENESIS_HASH = "0" * 64


def compute_entry_hash(entry: AuditEntry) -> str:
    """Deterministically hash an entry's content (excluding ``entry_hash``)."""
    payload = {
        "sequence": entry.sequence,
        "timestamp": entry.timestamp,
        "previous_hash": entry.previous_hash,
        "actor": entry.actor,
        "action": entry.action,
        "target": entry.target,
        "result": entry.result,
        "details": entry.details,
    }
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def finalize(entry: AuditEntry) -> AuditEntry:
    """Return a copy of the entry with its ``entry_hash`` set."""
    entry.entry_hash = compute_entry_hash(entry)
    return entry


def verify_chain(entries: list[AuditEntry]) -> tuple[bool, int | None]:
    """Verify a list of entries.

    Returns ``(ok, broken_sequence)``. ``broken_sequence`` is the sequence
    number of the first entry that fails, or ``None`` if the chain is intact.
    """
    previous = GENESIS_HASH
    for entry in entries:
        if entry.previous_hash != previous:
            return False, entry.sequence
        if compute_entry_hash(entry) != entry.entry_hash:
            return False, entry.sequence
        previous = entry.entry_hash
    return True, None

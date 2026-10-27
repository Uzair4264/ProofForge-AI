"""Append-only JSONL audit logger.

Writes one ``AuditEntry`` per line, each hash-chained to the previous. The
logger reads the last line on open to continue the chain across runs. It logs
what the spec permits (§11.2) and never logs raw evidence content (§11.3).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core.types import AuditEntry
from . import chain


class AuditLogger:
    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path
        self._sequence, self._last_hash = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self.log_path.exists():
            return 0, chain.GENESIS_HASH
        last_line = ""
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last_line = line
        if not last_line:
            return 0, chain.GENESIS_HASH
        data = json.loads(last_line)
        return data["sequence"] + 1, data["entry_hash"]

    def log(self, *, actor: str, action: str, target: str, result: str, details: dict[str, Any] | None = None) -> AuditEntry:
        entry = AuditEntry(
            sequence=self._sequence,
            timestamp=datetime.now(timezone.utc).isoformat(),
            previous_hash=self._last_hash,
            actor=actor,
            action=action,
            target=target,
            result=result,
            details=details or {},
        )
        chain.finalize(entry)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.model_dump(), ensure_ascii=False) + "\n")
        self._sequence += 1
        self._last_hash = entry.entry_hash
        return entry


def read_entries(log_path: Path) -> list[AuditEntry]:
    entries: list[AuditEntry] = []
    with log_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                entries.append(AuditEntry(**json.loads(line)))
    return entries


def verify_log(log_path: Path) -> tuple[bool, int | None]:
    return chain.verify_chain(read_entries(log_path))

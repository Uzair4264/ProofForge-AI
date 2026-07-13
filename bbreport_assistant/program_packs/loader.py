"""Load and validate program rule packs from ``packs/``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..core.exceptions import RulePackError
from .schema import RulePack

PACKS_DIR = Path(__file__).parent / "packs"


def load_pack_file(path: Path) -> RulePack:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise RulePackError(f"Failed to read rule pack {path}: {exc}") from exc
    try:
        return RulePack(**data)
    except ValidationError as exc:
        raise RulePackError(f"Rule pack {path} failed validation:\n{exc}") from exc


@lru_cache(maxsize=1)
def load_all() -> dict[str, RulePack]:
    out: dict[str, RulePack] = {}
    if not PACKS_DIR.exists():
        return out
    for path in sorted(PACKS_DIR.glob("*.yaml")):
        pack = load_pack_file(path)
        out[pack.program_id] = pack
    return out


def get_pack(program_id: str) -> RulePack:
    packs = load_all()
    if program_id not in packs:
        available = ", ".join(sorted(packs)) or "(none)"
        raise RulePackError(
            f"No rule pack for program '{program_id}'. Available: {available}"
        )
    return packs[program_id]


def available_programs() -> list[str]:
    return sorted(load_all())

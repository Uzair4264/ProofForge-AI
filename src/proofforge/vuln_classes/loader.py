"""Load and validate vuln-class templates from ``templates/``."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..core.exceptions import TemplateError
from .schema import VulnClassTemplate

TEMPLATES_DIR = Path(__file__).parent / "templates"


def load_template_file(path: Path) -> VulnClassTemplate:
    try:
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except (OSError, yaml.YAMLError) as exc:
        raise TemplateError(f"Failed to read template {path}: {exc}") from exc
    try:
        return VulnClassTemplate(**data)
    except ValidationError as exc:
        raise TemplateError(f"Template {path} failed validation:\n{exc}") from exc


@lru_cache(maxsize=1)
def load_all() -> dict[str, VulnClassTemplate]:
    """Return all templates indexed by ``vuln_class`` id."""
    out: dict[str, VulnClassTemplate] = {}
    if not TEMPLATES_DIR.exists():
        return out
    for path in sorted(TEMPLATES_DIR.glob("*.yaml")):
        tmpl = load_template_file(path)
        out[tmpl.vuln_class] = tmpl
    return out


def get_template(vuln_class: str) -> VulnClassTemplate:
    templates = load_all()
    if vuln_class not in templates:
        available = ", ".join(sorted(templates)) or "(none)"
        raise TemplateError(
            f"No template for vuln class '{vuln_class}'. Available: {available}"
        )
    return templates[vuln_class]


def available_classes() -> list[str]:
    return sorted(load_all())

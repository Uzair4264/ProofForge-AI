"""Output renderers. Each exposes ``render(report, ...) -> str``."""

from __future__ import annotations

from . import hackerone_md, markdown_generic

_RENDERERS = {
    "markdown_generic": markdown_generic.render,
    "hackerone_md": hackerone_md.render,
}


def get_renderer(name: str):
    return _RENDERERS.get(name, markdown_generic.render)

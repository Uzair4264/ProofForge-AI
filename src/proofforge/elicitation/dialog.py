"""Interactive Q&A for fields the inference engine could not fill.

Every prompt supports the universal first-class responses (spec §12.9):
``?`` / ``??`` / ``help`` / ``examples`` / ``skip`` / ``unknown`` / ``back`` /
``cancel``. The dialog is driven by the field's ``FieldSpec`` (label, help,
options). Non-interactive callers can pass a ``responder`` to script answers.
"""

from __future__ import annotations

from typing import Callable, Optional

from rich.console import Console

from ..core.exceptions import BBReportError
from ..core.types import Field, FieldState
from ..vuln_classes.schema import FieldSpec

Responder = Callable[[str], str]


class ElicitationCancelled(BBReportError):
    """Raised when the user types ``cancel`` during elicitation."""


class GoBack(Exception):
    """Internal signal: user wants to return to the previous field."""


def _show_help(console: Console, spec: FieldSpec, *, long: bool) -> None:
    if not spec.help:
        console.print("  [dim](no help available for this field)[/dim]")
        return
    if long and spec.help.long:
        console.print(f"  {spec.help.long.strip()}")
    elif spec.help.short:
        console.print(f"  [dim]{spec.help.short}[/dim]")


def _show_examples(console: Console, spec: FieldSpec) -> None:
    if spec.help and spec.help.examples:
        for ex in spec.help.examples:
            console.print(f"    - {ex}")
    else:
        console.print("  [dim](no examples available)[/dim]")


def ask_field(
    console: Console,
    spec: FieldSpec,
    *,
    responder: Optional[Responder] = None,
) -> Field:
    """Ask the user for one field's value. Returns a populated ``Field``."""
    field = Field(
        id=spec.id,
        label=spec.label,
        field_type=spec.field_type,
        state=FieldState.PENDING,
        is_required=spec.is_required,
    )

    options_hint = f" [{'/'.join(spec.options)}]" if spec.options else ""
    prompt_text = f"[bold]{spec.label}[/bold]{options_hint} (? for help): "

    def get_input() -> str:
        if responder is not None:
            return responder(spec.id)
        return console.input(prompt_text)

    while True:
        if responder is None:
            console.print()
        raw = get_input().strip()
        low = raw.lower()

        if low == "cancel":
            raise ElicitationCancelled("User cancelled the report session.")
        if low == "back":
            raise GoBack()
        if low == "?":
            _show_help(console, spec, long=False)
            continue
        if low in ("??", "help"):
            _show_help(console, spec, long=True)
            continue
        if low == "examples":
            _show_examples(console, spec)
            continue
        if low == "skip":
            field.state = FieldState.SKIPPED
            if spec.is_required:
                console.print("  [yellow]! Skipped a required field.[/yellow]")
            return field
        if low == "unknown":
            field.state = FieldState.UNKNOWN
            return field

        if not raw:
            if responder is not None:
                # Scripted empty answer counts as skip to avoid infinite loops.
                field.state = FieldState.SKIPPED
                return field
            console.print("  [dim]Please enter a value, or one of: ? help examples skip unknown back cancel[/dim]")
            continue

        if spec.options and raw not in spec.options:
            console.print(f"  [yellow]! Expected one of: {', '.join(spec.options)}[/yellow]")
            if responder is not None:
                # Don't loop forever on a bad scripted answer.
                field.value = raw
                field.state = FieldState.USER_PROVIDED
                return field
            continue

        field.value = raw
        field.state = FieldState.USER_PROVIDED
        return field


def elicit_pending(
    console: Console,
    specs: list[FieldSpec],
    existing: dict[str, Field],
    *,
    responder: Optional[Responder] = None,
) -> dict[str, Field]:
    """Ask about every field not already in a resolved state.

    Supports ``back`` to revisit the previous asked field.
    """
    resolved = dict(existing)
    pending = [
        s for s in specs
        if existing.get(s.id, Field(id=s.id, label=s.label, field_type=s.field_type)).state
        in (FieldState.PENDING,)
    ]

    idx = 0
    history: list[int] = []
    while idx < len(pending):
        spec = pending[idx]
        try:
            field = ask_field(console, spec, responder=responder)
        except GoBack:
            if history:
                idx = history.pop()
            else:
                console.print("  [dim](already at the first question)[/dim]")
            continue
        resolved[spec.id] = field
        history.append(idx)
        idx += 1
    return resolved

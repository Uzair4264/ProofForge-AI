"""Batch-confirmation UI for inferred fields (spec §8.6).

Presents all inferred fields with their values and confidence, lets the user
accept everything in bulk or drill into specific fields. In non-interactive mode
(``auto_confirm``), all inferred values are confirmed automatically — used by
scripted/test runs.
"""

from __future__ import annotations

from typing import Callable, Optional

from rich.console import Console

from ..core.types import Field, FieldState
from ..inference.confidence import confidence_label

Responder = Callable[[str], str]


def _mark(state: FieldState, confidence: float | None) -> str:
    label = confidence_label(confidence)
    glyph = "v" if label == "high" else "?"
    return f"[{glyph}]"


def present_inferred(
    console: Console,
    inferred: dict[str, Field],
    *,
    auto_confirm: bool = False,
    responder: Optional[Responder] = None,
) -> dict[str, Field]:
    """Show inferred fields and confirm them.

    Returns the (possibly mutated) fields with INFERRED -> CONFIRMED where the
    user accepted. Fields the user rejects are reset to PENDING so the dialog
    stage will ask about them.
    """
    out = dict(inferred)
    inferred_only = {
        fid: f for fid, f in inferred.items() if f.state == FieldState.INFERRED
    }

    if not inferred_only:
        console.print("[dim]No fields could be inferred from the evidence.[/dim]")
        return out

    console.print("\n[bold]Based on your evidence, I've filled in the following:[/bold]\n")
    for fid, field in inferred_only.items():
        mark = _mark(field.state, field.confidence)
        label = confidence_label(field.confidence)
        console.print(
            f"  {mark} [bold]{field.label}[/bold]: {field.value}    "
            f"[dim]({label} confidence)[/dim]"
        )
        if field.inference_reasoning and label != "high":
            console.print(f"      [dim]> {field.inference_reasoning}[/dim]")

    if auto_confirm:
        for field in inferred_only.values():
            field.state = FieldState.CONFIRMED
        console.print("\n[green]All inferred values confirmed automatically.[/green]")
        return out

    answer = (
        responder("__confirm_all__") if responder is not None
        else console.input("\nConfirm all inferred values? [Y/n/edit] ")
    ).strip().lower()

    if answer in ("", "y", "yes"):
        for field in inferred_only.values():
            field.state = FieldState.CONFIRMED
        return out

    # Per-field review.
    for fid, field in inferred_only.items():
        per = (
            responder(fid) if responder is not None
            else console.input(f"  Keep '{field.label}' = {field.value}? [Y/n] ")
        ).strip().lower()
        if per in ("", "y", "yes"):
            field.state = FieldState.CONFIRMED
        else:
            field.state = FieldState.PENDING
            field.value = None
    return out

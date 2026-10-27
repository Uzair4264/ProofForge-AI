"""Batch-confirmation UI for inferred fields (spec §8.6).

Presents all inferred fields with their values and confidence, lets the user
accept everything in bulk or drill into specific fields. In non-interactive mode
(``auto_confirm``), inferred values are confirmed automatically — used by
scripted/test runs.

AI drafts (``suggest_only`` fields such as the impact narrative) are never
confirmed in bulk or by ``auto_confirm``: each needs its own explicit "yes".
"""

from __future__ import annotations

from typing import Callable, Optional

from rich.console import Console

from ..core.types import Evidence, Field, FieldState, ImpactBasis
from ..inference.confidence import confidence_label

Responder = Callable[[str], str]


def _mark(state: FieldState, confidence: float | None) -> str:
    label = confidence_label(confidence)
    glyph = "v" if label == "high" else "?"
    return f"[{glyph}]"


def _reject(field: Field) -> None:
    field.state = FieldState.PENDING
    field.value = None
    field.evidence_ids = []


def present_inferred(
    console: Console,
    inferred: dict[str, Field],
    *,
    auto_confirm: bool = False,
    responder: Optional[Responder] = None,
    drafts: frozenset[str] = frozenset(),
) -> dict[str, Field]:
    """Show inferred fields and confirm them.

    Returns the (possibly mutated) fields with INFERRED -> CONFIRMED where the
    user accepted. Fields the user rejects are reset to PENDING so the dialog
    stage will ask about them. ``drafts`` are field ids holding an AI draft;
    they are confirmed only by an explicit per-field "y" (default No).
    """
    out = dict(inferred)
    inferred_only = {
        fid: f for fid, f in inferred.items() if f.state == FieldState.INFERRED
    }
    regular = {fid: f for fid, f in inferred_only.items() if fid not in drafts}
    draft_fields = {fid: f for fid, f in inferred_only.items() if fid in drafts}

    if not inferred_only:
        console.print("[dim]No fields could be inferred from the evidence.[/dim]")
        return out

    console.print("\n[bold]Based on your evidence, I've filled in the following:[/bold]\n")
    for fid, field in regular.items():
        mark = _mark(field.state, field.confidence)
        label = confidence_label(field.confidence)
        console.print(
            f"  {mark} [bold]{field.label}[/bold]: {field.value}    "
            f"[dim]({label} confidence)[/dim]"
        )
        if field.inference_reasoning and label != "high":
            console.print(f"      [dim]> {field.inference_reasoning}[/dim]")

    if auto_confirm:
        for field in regular.values():
            field.state = FieldState.CONFIRMED
        if regular:
            console.print("\n[green]Inferred values confirmed automatically.[/green]")
        for field in draft_fields.values():
            _reject(field)
            console.print(
                f"[yellow]! AI-drafted '{field.label}' was not accepted (--yes never accepts "
                f"drafts). Write your own, or run without --yes to review the draft.[/yellow]"
            )
        return out

    if regular:
        answer = (
            responder("__confirm_all__") if responder is not None
            else console.input("\nConfirm all inferred values? [Y/n/edit] ")
        ).strip().lower()

        if answer in ("", "y", "yes"):
            for field in regular.values():
                field.state = FieldState.CONFIRMED
        else:
            # Per-field review.
            for fid, field in regular.items():
                per = (
                    responder(fid) if responder is not None
                    else console.input(f"  Keep '{field.label}' = {field.value}? [Y/n] ")
                ).strip().lower()
                if per in ("", "y", "yes"):
                    field.state = FieldState.CONFIRMED
                else:
                    _reject(field)

    for fid, field in draft_fields.items():
        console.print(f"\n[bold]AI draft — {field.label}:[/bold]\n  {field.value}")
        per = (
            responder(fid) if responder is not None
            else console.input(
                "  Use this draft? Only say yes if your evidence shows all of it. [y/N] "
            )
        ).strip().lower()
        if per in ("y", "yes"):
            field.state = FieldState.CONFIRMED
        else:
            _reject(field)
    return out


def ask_impact_basis(
    console: Console,
    field: Field,
    *,
    responder: Optional[Responder] = None,
) -> ImpactBasis:
    """Ask whether the impact is demonstrated by the evidence or only inferred."""
    console.print(f"\n[bold]{field.label}:[/bold] {field.value}")
    while True:
        raw = (
            responder(f"{field.id}__basis") if responder is not None
            else console.input(
                "  Does your evidence demonstrate this impact (d), or is it inferred / potential (i)? [d/i] "
            )
        ).strip().lower()
        if raw in ("d", "demonstrated"):
            return "demonstrated"
        if raw in ("i", "inferred"):
            return "inferred"
        if responder is not None:
            return "inferred"  # a scripted non-answer never claims more than shown
        console.print("  [dim]Please answer d or i.[/dim]")


def ask_impact_evidence(
    console: Console,
    field: Field,
    evidence: list[Evidence],
    suggested_types: list[str],
    *,
    responder: Optional[Responder] = None,
) -> list[str]:
    """Ask which evidence shows the impact. Enter accepts the suggestion.

    The suggestion is the evidence an accepted draft was based on, else the
    evidence of the types the template names for this field.
    """
    known = {e.id for e in evidence}
    suggestion = [i for i in field.evidence_ids if i in known] or [
        e.id for e in evidence if e.type.value in suggested_types
    ]
    console.print("  Evidence: " + ", ".join(f"{e.id} ({e.type.value})" for e in evidence))
    while True:
        raw = (
            responder(f"{field.id}__evidence") if responder is not None
            else console.input(
                f"  Which evidence shows this impact? Comma-separated ids, or 'none' "
                f"[{', '.join(suggestion) or 'none'}] "
            )
        ).strip()
        if not raw:
            return suggestion
        if raw.lower() == "none":
            return []
        ids = [part.strip() for part in raw.split(",") if part.strip()]
        unknown = [i for i in ids if i not in known]
        if not unknown:
            return ids
        if responder is not None:
            return [i for i in ids if i in known]
        console.print(f"  [yellow]! Unknown evidence id(s): {', '.join(unknown)}[/yellow]")

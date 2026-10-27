"""``proofforge help`` — vuln-class and command guidance (spec §12.7)."""

from __future__ import annotations

from typing import Optional

import typer

from ...core.exceptions import BBReportError
from ...vuln_classes.loader import available_classes, get_template
from ..common import console, error

app = typer.Typer(help="In-depth help for vuln classes and commands.")


@app.command("vuln-class")
def vuln_class(
    name: str = typer.Argument(..., help="Vuln class id, e.g. xss"),
    subtype: Optional[str] = typer.Option(None, "--subtype", help="Subtype for targeted guidance"),
) -> None:
    """Show what a vuln-class template needs: fields, evidence, severity hints."""
    try:
        tmpl = get_template(name)
    except BBReportError as exc:
        error(str(exc))
        console.print(f"  Available: {', '.join(available_classes())}")
        raise typer.Exit(code=1)

    console.print(f"[bold]{tmpl.display_name}[/bold] ({tmpl.vuln_class}, {tmpl.cwe or 'no CWE'})")
    if tmpl.subtypes:
        console.print(f"  Subtypes: {', '.join(tmpl.subtypes)}")
    if subtype and subtype not in tmpl.subtypes:
        console.print(f"  [yellow]! '{subtype}' is not a known subtype.[/yellow]")

    console.print("\n[bold]Required fields[/bold]")
    for f in tmpl.required_fields:
        short = f.help.short if f.help and f.help.short else ""
        console.print(f"  - {f.id} ({f.field_type}): {short}")

    console.print("\n[bold]Required evidence[/bold]")
    for ev in tmpl.required_evidence:
        flag = "required" if ev.required else "optional"
        note = f" — {ev.note}" if ev.note else ""
        console.print(f"  - {ev.type} [{flag}]: {ev.description}{note}")

    if tmpl.severity_hints and tmpl.severity_hints.default_cvss_v31:
        console.print("\n[bold]Severity hint[/bold]")
        console.print(f"  Default vector: {tmpl.severity_hints.default_cvss_v31}")
        if tmpl.severity_hints.notes:
            console.print(f"  {tmpl.severity_hints.notes.strip()}")

    if tmpl.verifier_focus:
        console.print("\n[bold]Verifier focus[/bold]")
        for vf in tmpl.verifier_focus:
            console.print(f"  - {vf}")

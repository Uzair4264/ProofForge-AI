"""CLI entrypoint. Assembles the command groups into the ``bbreport`` app."""

from __future__ import annotations

import typer

from .. import __version__
from .commands import audit as audit_cmd
from .commands import config_cmd
from .commands import evidence as evidence_cmd
from .commands import helpcmd
from .commands import report as report_cmd
from .commands import session as session_cmd
from .commands.check import check
from .commands.doctor import doctor
from .commands.init import init
from .commands.render import render
from .commands.verify import verify

app = typer.Typer(
    name="bbreport",
    help="ProofForge AI — evidence-backed, program-compliant bug bounty reports.",
    no_args_is_help=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"bbreport {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit."
    ),
) -> None:
    """ProofForge AI command-line interface."""


# Single commands.
app.command("init")(init)
app.command("verify")(verify)
app.command("check")(check)
app.command("render")(render)
app.command("doctor")(doctor)

# Command groups.
app.add_typer(evidence_cmd.app, name="evidence")
app.add_typer(report_cmd.app, name="report")
app.add_typer(session_cmd.app, name="session")
app.add_typer(config_cmd.app, name="config")
app.add_typer(audit_cmd.app, name="audit")
app.add_typer(helpcmd.app, name="help")


if __name__ == "__main__":
    app()

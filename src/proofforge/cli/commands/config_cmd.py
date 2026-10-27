"""``proofforge config`` — view and initialize configuration."""

from __future__ import annotations

import typer
import yaml

from ...core import paths
from ...core.config import load_config, write_default_config
from ..common import OK, WARN, console

app = typer.Typer(help="View/edit configuration.")


@app.command("show")
def show() -> None:
    config = load_config()
    console.print(f"[dim]Config file: {paths.CONFIG_FILE}[/dim]\n")
    console.print(yaml.safe_dump(config.model_dump(), sort_keys=False, default_flow_style=False))


@app.command("init")
def init(force: bool = typer.Option(False, "--force", help="Overwrite an existing config")) -> None:
    written = write_default_config(force=force)
    if written:
        console.print(f"{OK} Wrote default config to {paths.CONFIG_FILE}")
    else:
        console.print(f"{WARN} Config already exists at {paths.CONFIG_FILE} (use --force to overwrite)")


@app.command("path")
def path() -> None:
    console.print(str(paths.CONFIG_FILE))

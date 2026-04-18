"""LANCE CLI — thin wiring layer around the core.

Commands:
    lance run         — execute an attack against a target
    lance list        — list registered attacks with their mappings
    lance version     — print version info

The CLI is deliberately thin. All business logic lives in core modules;
`cli.py` only parses arguments and delegates.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lance import __version__

app = typer.Typer(
    name="lance",
    help="Lateral Agentic eNvironment Cloud Exploitation — cloud-native red teaming for agentic AI systems.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


@app.command()
def version() -> None:
    """Print LANCE version and exit."""
    console.print(f"lance {__version__}")


@app.command(name="list")
def list_attacks() -> None:
    """List registered attacks with their framework mappings."""
    # In v0.1 this will discover attacks via entry points or a registry.
    # For now we show the stub attack.
    from lance.attacks.indirect_injection import IndirectInjectionViaToolOutput

    attacks = [IndirectInjectionViaToolOutput]

    table = Table(title="Registered attacks", show_lines=True)
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("OWASP ASI")
    table.add_column("MITRE ATLAS")
    table.add_column("Stable")
    table.add_column("Description", overflow="fold")

    for attack_cls in attacks:
        table.add_row(
            attack_cls.name,
            ", ".join(attack_cls.owasp_asi) or "—",
            ", ".join(attack_cls.mitre_atlas) or "—",
            "✓" if attack_cls.stable else "experimental",
            attack_cls.description,
        )
    console.print(table)


@app.command()
def run(
    target: Path = typer.Option(  # noqa: B008
        ...,
        "--target",
        "-t",
        help="Path to target config YAML.",
        exists=True,
        readable=True,
    ),
    attack: str = typer.Option(..., "--attack", "-a", help="Attack name to run."),
    output: Path = typer.Option(  # noqa: B008
        Path("findings"),
        "--output",
        "-o",
        help="Directory to write findings (JSON + Markdown).",
    ),
    include_unstable: bool = typer.Option(
        False,
        "--include-unstable",
        help="Allow running attacks marked stable=False.",
    ),
) -> None:
    """Execute an attack against a target and write Findings to disk.

    Not implemented yet — lands with v0.1. Exit code 2 until then.
    """
    console.print(
        f"[yellow]LANCE v0.1 not yet implemented.[/yellow] "
        f"Would run [cyan]{attack}[/cyan] against [cyan]{target}[/cyan], "
        f"output to [cyan]{output}[/cyan] (include_unstable={include_unstable})."
    )
    sys.exit(2)


if __name__ == "__main__":
    app()

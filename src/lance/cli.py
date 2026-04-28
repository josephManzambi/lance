"""LANCE CLI — thin wiring layer around the core.

Commands:
    lance run         — execute an attack against a target
    lance list        — list registered attacks with their mappings
    lance version     — print version info

The CLI is deliberately thin. All business logic lives in core modules;
`cli.py` only parses arguments and delegates.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from lance import __version__
from lance.attacks.base import Attack, AttackConfig
from lance.attacks.indirect_injection import IndirectInjectionViaToolOutput
from lance.targets.base import Target, TargetAuthorizationError
from lance.targets.config import TargetConfig
from lance.targets.mcp import MCPTarget

app = typer.Typer(
    name="lance",
    help=(
        "Lateral Agentic eNvironment Cloud Exploitation — "
        "cloud-native red teaming for agentic AI systems."
    ),
    no_args_is_help=True,
    add_completion=False,
)

console = Console()

# Probe input is the literal MCP tool argument in v0.1 (no agent loop yet),
# so it must be a known fixture doc_id rather than an English instruction.
# Choosing q3_report ensures the probe exercises the full transport + tool
# execution path and surfaces specific fixture content (a Q3 2025 revenue
# figure) in the response — proving content round-tripped end-to-end.
# Will become a natural-language instruction once the agent layer lands.
_PROBE_INPUT = "q3_report"

ATTACK_REGISTRY: dict[str, type[Attack]] = {
    IndirectInjectionViaToolOutput.name: IndirectInjectionViaToolOutput,
}

TARGET_REGISTRY: dict[str, type[MCPTarget]] = {
    "mcp": MCPTarget,
}


@app.command()
def version() -> None:
    """Print LANCE version and exit."""
    console.print(f"lance {__version__}")


@app.command(name="list")
def list_attacks() -> None:
    """List registered attacks with their framework mappings."""
    attacks = list(ATTACK_REGISTRY.values())

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
            "yes" if attack_cls.stable else "experimental",
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
    probe: bool = typer.Option(
        False,
        "--probe/--no-probe",
        help="Skip the attack; send one benign interact() and print the TargetTurn as JSON.",
    ),
) -> None:
    """Execute an attack against a target and write Findings to disk.

    The v0.1 round-trip wiring: load the target config (authorization
    gate fires here, before any I/O), spawn the target adapter, then
    either probe it with a benign input or invoke the requested attack.
    """
    try:
        config = TargetConfig.load(target)
    except TargetAuthorizationError as err:
        console.print(f"[red]Authorization error:[/red] {err}")
        raise typer.Exit(code=2) from err

    target_cls = TARGET_REGISTRY.get(config.type)
    if target_cls is None:
        console.print(f"[red]Unsupported target type:[/red] {config.type!r}")
        raise typer.Exit(code=2)

    asyncio.run(
        _run_async(
            config=config,
            target_cls=target_cls,
            attack_name=attack,
            output=output,
            include_unstable=include_unstable,
            probe=probe,
        )
    )


async def _run_async(
    *,
    config: TargetConfig,
    target_cls: type[MCPTarget],
    attack_name: str,
    output: Path,
    include_unstable: bool,
    probe: bool,
) -> None:
    target_instance = await target_cls.from_config(config)
    try:
        if probe:
            turn = await target_instance.interact(_PROBE_INPUT)
            console.print_json(turn.model_dump_json())
            return

        attack_cls = ATTACK_REGISTRY.get(attack_name)
        if attack_cls is None:
            console.print(f"[red]Unknown attack:[/red] {attack_name!r}")
            raise typer.Exit(code=2)
        if not attack_cls.stable and not include_unstable:
            console.print(
                f"[yellow]Attack {attack_name!r} is marked unstable.[/yellow] "
                "Pass --include-unstable to run it."
            )
            raise typer.Exit(code=2)

        try:
            finding = await attack_cls().run(_as_target(target_instance), AttackConfig())
        except NotImplementedError as err:
            console.print(f"[yellow]Attack stub not implemented:[/yellow] {err}")
            return
        console.print(f"[green]Finding produced:[/green] {finding}")
        console.print(f"[dim]Output directory (unused in v0.1): {output}[/dim]")
    finally:
        await target_instance.aclose()


def _as_target(instance: MCPTarget) -> Target:
    return instance


if __name__ == "__main__":
    app()

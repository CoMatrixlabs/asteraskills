"""
CLI configure command — license setup, server URL, policy TUI.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel

app = typer.Typer()
console = Console()

_CONFIG_FILE = Path.home() / ".risk-scanner" / "config.env"


@app.command("configure")
def cmd_configure(
    token: Optional[str] = typer.Option(
        None,
        "--token",
        "-t",
        help="License token (will be stored in ~/.risk-scanner/config.env)",
        prompt="License token (press Enter to skip)",
        hide_input=True,
    ),
    server_url: str = typer.Option(
        "https://api.risk-scanner.io",
        "--server",
        help="Intelligence server URL",
        prompt="Intelligence server URL",
    ),
    frameworks: str = typer.Option(
        "cis-8,nist-800-53",
        "--frameworks",
        help="Default frameworks (comma-separated)",
        prompt="Default frameworks",
    ),
    severity_threshold: str = typer.Option(
        "LOW",
        "--severity",
        help="Minimum severity threshold",
        prompt="Minimum severity threshold (CRITICAL/HIGH/MEDIUM/LOW/INFO)",
    ),
) -> None:
    """Configure risk-scanner license token, server URL, and policy defaults."""
    config_dir = _CONFIG_FILE.parent
    config_dir.mkdir(parents=True, exist_ok=True)

    lines = []
    if token:
        lines.append(f"RISK_SCANNER_LICENSE_TOKEN={token}")
    lines.append(f"RISK_SCANNER_SERVER_URL={server_url}")
    lines.append(f"RISK_SCANNER_FRAMEWORKS={frameworks}")
    lines.append(f"RISK_SCANNER_SEVERITY_THRESHOLD={severity_threshold.upper()}")

    _CONFIG_FILE.write_text("\n".join(lines) + "\n")

    mode = "licensed" if token else "local (no license token)"
    console.print(Panel(
        f"[green]Configuration saved to {_CONFIG_FILE}[/green]\n\n"
        f"Mode: [bold]{mode}[/bold]\n"
        f"Server: {server_url}\n"
        f"Frameworks: {frameworks}\n"
        f"Severity threshold: {severity_threshold.upper()}\n\n"
        f"Run [bold]risk-scanner scan <path>[/bold] to start scanning.",
        title="risk-scanner configured",
        border_style="green",
    ))

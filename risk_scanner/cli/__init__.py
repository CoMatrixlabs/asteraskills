"""
Risk Scanner CLI — assembled Typer application.
"""

import typer

from risk_scanner.cli.scan import app as scan_app
from risk_scanner.cli.configure import app as configure_app
from risk_scanner.cli.generate_policy import app as policy_app

app = typer.Typer(
    name="risk-scanner",
    help="Multi-domain security artifact scanner (CVE · CWE · ATT&CK · Policy · Framework).",
    no_args_is_help=True,
    add_completion=False,
)

app.add_typer(scan_app, name="scan")
app.registered_commands += configure_app.registered_commands
app.registered_commands += policy_app.registered_commands


def main() -> None:
    app()


if __name__ == "__main__":
    main()

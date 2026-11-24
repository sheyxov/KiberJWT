from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import jwt
import typer
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from analyzer import analyze_token, verify_signature

app = typer.Typer(name="kiberjwt", help="Inspect JWT contents and audit common security issues.")
console = Console()


def print_banner() -> None:
    from pyfiglet import Figlet

    banner = Figlet(font="slant").renderText("KIBERJWT").rstrip()
    lines = banner.splitlines()
    styled = Text()
    for index, line in enumerate(lines):
        if index:
            styled.append("\n")
        midpoint = max(1, len(line) // 2)
        styled.append(line[:midpoint], style="bold cyan")
        styled.append(line[midpoint:], style="bold magenta")
    console.print(Panel(styled, border_style="bright_cyan", padding=(0, 2)))


def display_token(header: dict, payload: dict) -> None:
    left = Table(
        title="[bold cyan]Header[/]",
        box=box.ROUNDED,
        border_style="cyan",
        expand=True,
    )
    left.add_column("JSON")
    left.add_row(
        Syntax(json.dumps(header, indent=2, ensure_ascii=False), "json", theme="monokai")
    )

    right = Table(
        title="[bold magenta]Payload[/]",
        box=box.ROUNDED,
        border_style="magenta",
        expand=True,
    )
    right.add_column("JSON")
    right.add_row(
        Syntax(json.dumps(payload, indent=2, ensure_ascii=False), "json", theme="monokai")
    )
    console.print(Columns([left, right], equal=True, expand=True))


def display_findings(findings: list[dict[str, str]]) -> None:
    table = Table(title="Security Audit", box=box.ROUNDED, border_style="bright_blue")
    table.add_column("Status", no_wrap=True)
    table.add_column("Check", style="cyan")
    table.add_column("Details")
    colors = {"SAFE": "green", "WARN": "yellow", "CRITICAL": "bold red"}
    for finding in findings:
        severity = finding["severity"]
        badge = Text(f"[{severity}]", style=colors[severity])
        table.add_row(badge, Text(finding["check"]), Text(finding["message"]))
    console.print(table)


@app.command()
def inspect(
    token: str = typer.Argument(..., help="Compact JWT to inspect."),
    secret: Optional[str] = typer.Option(
        None, "--secret", help="Shared secret used to verify an HMAC-signed token."
    ),
    public_key: Optional[Path] = typer.Option(
        None,
        "--public-key",
        help="Path to a PEM public key used to verify an asymmetric signature.",
        exists=True,
        file_okay=True,
        dir_okay=False,
        readable=True,
    ),
    export: Optional[Path] = typer.Option(
        None, "--export", help="Write the complete audit report as JSON."
    ),
) -> None:
    """Decode and audit one JWT. Signature verification is optional."""
    print_banner()
    if secret is not None and public_key is not None:
        raise typer.BadParameter("use either --secret or --public-key, not both")

    try:
        report = analyze_token(token)
    except (jwt.PyJWTError, ValueError, TypeError) as error:
        console.print(
            Panel(
                Text(f"Could not decode token: {error}", style="bold red"),
                title="[bold red]Invalid JWT[/]",
                border_style="red",
            )
        )
        raise typer.Exit(code=2) from error

    if secret is not None or public_key is not None:
        verification = verify_signature(token, report["header"], secret, public_key)
        signature_finding = verification.pop("finding")
        report["signature"] = verification
        report["findings"] = [
            finding for finding in report["findings"] if finding["check"] != "Signature"
        ]
        report["findings"].append(signature_finding)

    display_token(report["header"], report["payload"])
    display_findings(report["findings"])

    if export is not None:
        try:
            export.write_text(
                json.dumps(report, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError as error:
            console.print(Text(f"Could not write report: {error}", style="bold red"))
            raise typer.Exit(code=2) from error
        console.print(Text(f"Audit report exported to {export}"))


if __name__ == "__main__":
    app()

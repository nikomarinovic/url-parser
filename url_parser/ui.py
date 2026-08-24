from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


console = Console()


def banner():
    title = Text()

    title.append(
        "URL PARSER\n",
        style="bold cyan"
    )

    title.append(
        "URL ANALYSIS TOOLKIT\n",
        style="bold white"
    )

    title.append(
        "by nikomarinovic",
        style="dim"
    )

    console.print(
        Panel(
            title,
            border_style="cyan",
            padding=(1, 4),
        )
    )


def component_table(parser):
    table = Table(
        title="URL Components",
        border_style="cyan",
        header_style="bold cyan",
    )

    table.add_column("Component")
    table.add_column("Value")

    values = [
        ("Protocol", parser.scheme),
        ("Username", parser.username or "—"),
        ("Password", parser.password or "—"),
        ("Hostname", parser.hostname),
        ("Domain", parser.domain),
        ("Subdomain", parser.subdomain or "—"),
        ("TLD", parser.tld or "—"),
        (
            "Port",
            str(parser.port)
            if parser.port
            else "Default"
        ),
        ("Origin", parser.origin),
        ("Path", parser.path),
        ("Query", parser.query or "—"),
        ("Fragment", parser.fragment or "—"),
    ]

    for name, value in values:
        table.add_row(
            name,
            str(value)
        )

    console.print(table)


def security_table(security):
    table = Table(
        title="Security Analysis",
        border_style="red",
        header_style="bold red",
    )

    table.add_column("Check")
    table.add_column("Result")

    score = security.calculate_score()
    level = security.risk_level()

    level_style = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "red",
        "CRITICAL": "bold red",
    }[level]

    table.add_row(
        "Risk Score",
        f"[{level_style}]{score}/10[/]"
    )

    table.add_row(
        "Risk Level",
        f"[{level_style}]{level}[/]"
    )

    table.add_row(
        "HTTPS",
        "[green]✓ Enabled[/]"
        if security.https
        else "[red]⚠ Not HTTPS[/]"
    )

    table.add_row(
        "Credentials",
        "[red]⚠ Exposed[/]"
        if security.credentials_exposed
        else "[green]✓ None[/]"
    )

    table.add_row(
        "IP Address",
        f"[yellow]⚠ {security.ip_type}[/]"
        if security.ip_address
        else "[green]✓ Domain[/]"
    )

    table.add_row(
        "Localhost",
        "[yellow]⚠ Detected[/]"
        if security.localhost
        else "[green]✓ No[/]"
    )

    table.add_row(
        "Private Network",
        "[yellow]⚠ Detected[/]"
        if security.private_network
        else "[green]✓ No[/]"
    )

    table.add_row(
        "Suspicious Port",
        (
            f"[yellow]⚠ {security.suspicious_port}[/]"
            if security.suspicious_port
            else "[green]✓ None[/]"
        )
    )

    table.add_row(
        "URL Encoding",
        "[yellow]! Detected[/]"
        if security.encoded_characters
        else "[green]✓ None[/]"
    )

    table.add_row(
        "Suspicious Characters",
        (
            ", ".join(
                security.suspicious_characters
            )
            if security.suspicious_characters
            else "[green]✓ None[/]"
        )
    )

    console.print(table)


def findings_panel(security):
    findings = security.findings()

    if not findings:
        console.print(
            Panel(
                "[green]✓ No security issues detected.[/]",
                title="Security Findings",
                border_style="green",
            )
        )
        return

    for finding in findings:
        severity = finding["severity"]

        style = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
        }.get(severity, "white")

        content = (
            f"[{style}]{severity}[/]\n\n"
            f"[bold]{finding['title']}[/]\n"
            f"{finding['description']}\n\n"
            f"[cyan]Recommendation:[/] "
            f"{finding['recommendation']}"
        )

        console.print(
            Panel(
                content,
                border_style=style.split()[-1],
            )
        )


def query_table(query):
    table = Table(
        title=f"Query Parameters ({query.count})",
        border_style="magenta",
        header_style="bold magenta",
    )

    table.add_column("Key")
    table.add_column("Value")

    for key, value in query.decoded_parameters:
        table.add_row(key, value)

    if query.count == 0:
        table.add_row("—", "No query parameters")

    console.print(table)

    if query.duplicate_parameters:
        console.print(
            "[yellow]Duplicate parameters:[/] "
            + ", ".join(
                query.duplicate_parameters
            )
        )

    if query.empty_parameters:
        console.print(
            "[yellow]Empty parameters:[/] "
            + ", ".join(
                query.empty_parameters
            )
        )


def statistics_table(statistics):
    table = Table(
        title="Statistics",
        border_style="blue",
        header_style="bold blue",
    )

    table.add_column("Metric")
    table.add_column("Value")

    for key, value in statistics.get().items():
        table.add_row(
            key,
            str(value)
        )

    console.print(table)
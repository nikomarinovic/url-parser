import argparse
import json

from url_parser.parser import URLParser
from url_parser.security import SecurityAnalyzer
from url_parser.query import QueryAnalyzer
from url_parser.encoder import encode, decode
from url_parser.normalizer import normalize
from url_parser.statistics import URLStatistics

from url_parser.ui import (
    banner,
    component_table,
    security_table,
    findings_panel,
    query_table,
    statistics_table,
    console,
)


def build_report(url):
    parser = URLParser(url)

    query = QueryAnalyzer(parser)
    security = SecurityAnalyzer(
        parser,
        query
    )
    statistics = URLStatistics(parser)

    return parser, query, security, statistics


def json_report(parser, query, security, statistics):
    return {
        "url": parser.full_url,

        "components": {
            "protocol": parser.scheme,
            "username": parser.username,
            "password": parser.password,
            "hostname": parser.hostname,
            "domain": parser.domain,
            "subdomain": parser.subdomain,
            "tld": parser.tld,
            "port": parser.port,
            "origin": parser.origin,
            "path": parser.path,
            "query": parser.query,
            "fragment": parser.fragment,
        },

        "query": query.get(),

        "security": security.run(),

        "statistics": statistics.get(),
    }


def analyze(url, args):
    parser, query, security, statistics = (
        build_report(url)
    )

    if args.json:
        print(
            json.dumps(
                json_report(
                    parser,
                    query,
                    security,
                    statistics,
                ),
                indent=2,
            )
        )
        return

    if args.quiet:
        print(
            f"{security.risk_level()} "
            f"{security.calculate_score()}/10 "
            f"{parser.hostname}"
        )
        return

    if not args.security and not args.query and not args.stats:
        component_table(parser)

        console.print()
        security_table(security)

        console.print()
        findings_panel(security)

        console.print()
        query_table(query)

        console.print()
        statistics_table(statistics)

    else:
        if args.security:
            security_table(security)

            console.print()
            findings_panel(security)

        if args.query:
            query_table(query)

        if args.stats:
            statistics_table(statistics)


def main():
    cli = argparse.ArgumentParser(
        prog="url-parser",
        description=(
            "URL Parser & Security Analysis Toolkit"
        ),
    )

    cli.add_argument(
        "url",
        nargs="?",
        help="URL to analyze",
    )

    cli.add_argument(
        "--security",
        action="store_true",
        help="Run security analysis",
    )

    cli.add_argument(
        "--query",
        action="store_true",
        help="Analyze query parameters",
    )

    cli.add_argument(
        "--stats",
        action="store_true",
        help="Show URL statistics",
    )

    cli.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )

    cli.add_argument(
        "--quiet",
        action="store_true",
        help="Output only risk summary",
    )

    cli.add_argument(
        "--encode",
        metavar="TEXT",
        help="URL encode text",
    )

    cli.add_argument(
        "--decode",
        metavar="TEXT",
        help="URL decode text",
    )

    cli.add_argument(
        "--normalize",
        metavar="URL",
        help="Normalize a URL",
    )

    args = cli.parse_args()

    if not any([
        args.json,
        args.quiet,
        args.encode,
        args.decode,
        args.normalize,
    ]):
        banner()

    if args.encode:
        print(encode(args.encode))
        return

    if args.decode:
        print(decode(args.decode))
        return

    if args.normalize:
        print(normalize(args.normalize))
        return

    if not args.url:
        args.url = console.input(
            "\n[bold cyan]Enter URL:[/] "
        )

    try:
        analyze(args.url, args)

    except ValueError as error:
        console.print(
            f"\n[bold red]✗ {error}[/]"
        )


if __name__ == "__main__":
    main()
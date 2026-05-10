import argparse
import sys
from pathlib import Path

from cognigraph.export import export_dot, export_json
from cognigraph.fixture.loader import FixtureValidationError, load_fixture
from cognigraph.graph.builder import build_from_fixture
from cognigraph.report import findings_to_json, format_report
from cognigraph.rules.engine import run_all_rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cognigraph",
        description="Graph-native capability reachability analysis for agentic AI systems",
    )
    parser.add_argument(
        "fixture",
        type=Path,
        help="Path to YAML fixture file",
    )
    parser.add_argument(
        "--export-dot",
        type=Path,
        metavar="PATH",
        help="Export graph to DOT format",
    )
    parser.add_argument(
        "--export-json",
        type=Path,
        metavar="PATH",
        help="Export graph to JSON format",
    )
    parser.add_argument(
        "--findings-json",
        type=Path,
        metavar="PATH",
        help="Write findings as JSON to file",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the text report on stdout",
    )
    args = parser.parse_args(argv)

    try:
        config = load_fixture(args.fixture)
    except FixtureValidationError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error loading fixture: {e}", file=sys.stderr)
        return 1

    graph = build_from_fixture(config)
    findings = run_all_rules(graph, config.analysis)

    if not args.quiet:
        print(format_report(findings))

    if args.export_dot:
        highlight = [f.path for f in findings]
        export_dot(graph, args.export_dot, highlight_paths=highlight)
        print(f"Graph exported to {args.export_dot}", file=sys.stderr)

    if args.export_json:
        export_json(graph, args.export_json)
        print(f"Graph exported to {args.export_json}", file=sys.stderr)

    if args.findings_json:
        args.findings_json.write_text(findings_to_json(findings))
        print(f"Findings exported to {args.findings_json}", file=sys.stderr)

    return 0 if not findings else 2


if __name__ == "__main__":
    sys.exit(main())

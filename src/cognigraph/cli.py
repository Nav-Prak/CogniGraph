import argparse
import sys
from pathlib import Path

from cognigraph.export import export_dot, export_json
from cognigraph.fixture.loader import FixtureValidationError, load_fixture
from cognigraph.graph.builder import build_from_fixture
from cognigraph.report import export_html_report, findings_to_json, format_report
from cognigraph.rules.engine import run_all_rules
from cognigraph.trace.loader import load_trace
from cognigraph.trace.overlay import (
    apply_overlay,
    get_exercised_static_edges,
    get_runtime_only_edges,
    get_unexercised_static_edges,
)


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
        "--html-report",
        type=Path,
        metavar="PATH",
        help="Write a static HTML report with findings, paths, and node metadata",
    )
    parser.add_argument(
        "--trace",
        type=Path,
        metavar="PATH",
        help="Path to JSON runtime trace file to overlay on the graph",
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

    overlay_result = None
    if args.trace:
        try:
            trace = load_trace(args.trace)
        except Exception as e:
            print(f"Error loading trace: {e}", file=sys.stderr)
            return 1
        overlay_result = apply_overlay(graph, trace)

    findings = run_all_rules(graph, config.analysis)

    if not args.quiet:
        print(format_report(findings))
        if overlay_result:
            print("\n--- Runtime Overlay Summary ---")
            print(f"Observed edges: {overlay_result.observed_count}")
            print(f"Unexpected edges: {overlay_result.unexpected_count}")
            if overlay_result.unmatched_nodes:
                print(f"Unmatched nodes: {', '.join(overlay_result.unmatched_nodes)}")
            exercised = get_exercised_static_edges(graph)
            unexercised = get_unexercised_static_edges(graph)
            runtime_only = get_runtime_only_edges(graph)
            total_static = len(exercised) + len(unexercised)
            if total_static:
                pct = len(exercised) / total_static * 100
                print(f"Static edge coverage: {len(exercised)}/{total_static} ({pct:.0f}%)")
            if runtime_only:
                print(f"Runtime-only edges: {len(runtime_only)}")

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

    if args.html_report:
        export_html_report(
            graph,
            findings,
            args.html_report,
            overlay_result=overlay_result,
        )
        print(f"HTML report exported to {args.html_report}", file=sys.stderr)

    return 0 if not findings else 2


if __name__ == "__main__":
    sys.exit(main())

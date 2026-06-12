import argparse
import sys
from pathlib import Path

from cognigraph.collect.mcp_config import (
    DEFAULT_AGENT_ID,
    DEFAULT_AGENT_TRUST_LEVEL,
    CollectError,
    collect_from_mcp_config,
    fixture_to_yaml,
)
from cognigraph.export import export_dot, export_json
from cognigraph.fixture.loader import FixtureValidationError, load_fixture
from cognigraph.graph.builder import build_from_fixture
from cognigraph.report import (
    export_html_report,
    findings_to_json,
    format_group_summary,
    format_report,
)
from cognigraph.rules.engine import run_all_rules
from cognigraph.rules.grouping import (
    SuppressionError,
    active_groups,
    apply_suppressions,
    group_findings,
    load_suppressions,
)
from cognigraph.schemas.findings import FindingSeverity
from cognigraph.trace.loader import available_trace_formats, load_trace
from cognigraph.trace.overlay import (
    apply_overlay,
    get_exercised_static_edges,
    get_runtime_only_edges,
    get_unexercised_static_edges,
)


def run_collect(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="cognigraph collect",
        description=(
            "Collect a fixture skeleton from an MCP client config "
            "(claude_desktop_config.json, .mcp.json, .cursor/mcp.json, "
            ".vscode/mcp.json)"
        ),
    )
    parser.add_argument(
        "config",
        type=Path,
        help="Path to MCP client config JSON file",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        metavar="PATH",
        help="Write fixture YAML to this path (default: stdout)",
    )
    parser.add_argument(
        "--agent-id",
        default=DEFAULT_AGENT_ID,
        help="ID for the generated host agent",
    )
    parser.add_argument(
        "--agent-trust-level",
        type=int,
        default=DEFAULT_AGENT_TRUST_LEVEL,
        choices=range(0, 5),
        help="Trust level for the generated host agent",
    )
    parser.add_argument(
        "--no-seed-capabilities",
        action="store_true",
        help="Do not seed the standard capability taxonomy into the fixture",
    )
    args = parser.parse_args(argv)

    try:
        config = collect_from_mcp_config(
            args.config,
            agent_id=args.agent_id,
            agent_trust_level=args.agent_trust_level,
            seed_capabilities=not args.no_seed_capabilities,
        )
    except CollectError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    fixture_yaml = fixture_to_yaml(config)
    if args.output:
        args.output.write_text(fixture_yaml, encoding="utf-8")
        print(
            f"Fixture skeleton written to {args.output} "
            f"({len(config.mcp_servers)} server(s), {len(config.tools)} tool stub(s)). "
            "Next: declare tool capabilities via --annotations or "
            "--infer-capabilities, then run the analyzer.",
            file=sys.stderr,
        )
    else:
        print(fixture_yaml, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] == "collect":
        return run_collect(argv[1:])

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
        "--trace-format",
        choices=available_trace_formats(),
        default="internal-json",
        help="Trace adapter format to use with --trace",
    )
    parser.add_argument(
        "--annotations",
        type=Path,
        metavar="PATH",
        help="Path to YAML tool capability annotations to apply to the fixture",
    )
    parser.add_argument(
        "--infer-capabilities",
        action="store_true",
        help=(
            "Apply deterministic keyword heuristics to tool IDs/descriptions. "
            "Only capabilities already declared in the fixture can be added."
        ),
    )
    parser.add_argument(
        "--suppressions",
        type=Path,
        metavar="PATH",
        help=(
            "Path to YAML suppressions file; suppressed finding groups are "
            "reported as accepted risks and excluded from the exit code"
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "any"],
        default="any",
        help=(
            "Minimum active finding-group severity that causes exit code 2 "
            "(default: any)"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the text report on stdout",
    )
    args = parser.parse_args(argv)

    try:
        config = load_fixture(
            args.fixture,
            annotations_path=args.annotations,
            infer_capabilities=args.infer_capabilities,
        )
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
            trace = load_trace(args.trace, trace_format=args.trace_format)
        except Exception as e:
            print(f"Error loading trace: {e}", file=sys.stderr)
            return 1
        overlay_result = apply_overlay(graph, trace)

    findings = run_all_rules(graph, config.analysis, config.policy)

    groups = group_findings(findings)
    if args.suppressions:
        try:
            suppressions = load_suppressions(args.suppressions)
            groups = apply_suppressions(groups, suppressions)
        except SuppressionError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

    if not args.quiet:
        print(format_report(findings))
        if groups:
            print(format_group_summary(groups))
        if overlay_result:
            print("\n--- Runtime Overlay Summary ---")
            print(f"Observed edges: {overlay_result.observed_count}")
            print(f"Projected paths: {overlay_result.projected_count}")
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

    fail_threshold = {
        "any": FindingSeverity.INFO,
        "high": FindingSeverity.HIGH,
        "critical": FindingSeverity.CRITICAL,
    }[args.fail_on]
    failing = [g for g in active_groups(groups) if g.severity >= fail_threshold]
    return 2 if failing else 0


if __name__ == "__main__":
    sys.exit(main())

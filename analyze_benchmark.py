
"""VulnForge offline benchmark diagnostics CLI."""

import argparse
import json
from pathlib import Path

from vulnforge.diagnostics.trace_analyzer import (
    DiagnosticError,
    analyze_file,
)


def format_value(value):
    if value is None:
        return "Not available"

    if isinstance(value, bool):
        return str(value)

    return str(value)


def render_markdown(results: list[dict]) -> str:
    """Generate a human-readable diagnostic report."""

    lines = [
        "# VulnForge — Benchmark Diagnostic Report",
        "",
        "## Methodology",
        "",
        "This report is derived from saved investigation "
        "artifacts. It does not rerun the model, modify "
        "evidence, or change independent adjudication.",
        "",
        "Diagnostic indicators are not confirmed root causes.",
        "",
        "## Experiment Summary",
        "",
        "| Target | Mode | Evidence | Verified | Diagnostics |",
        "|---|---|---:|---:|---:|",
    ]

    for result in results:
        investigation = result["investigation"]
        findings = result["findings"]

        lines.append(
            f"| {result['target_id']} "
            f"| {result['target_mode']} "
            f"| {investigation['evidence_records']} "
            f"| {format_value(findings['verified'])} "
            f"| {len(result['diagnostics'])} |"
        )

    for result in results:
        investigation = result["investigation"]
        findings = result["findings"]

        lines.extend([
            "",
            f"## {result['target_id']} — "
            f"{result['target_mode']}",
            "",
            f"**Run ID:** `{format_value(result['run_id'])}`",
            "",
            f"**Model:** {format_value(result['model'])}",
            "",
            f"**Execution status:** "
            f"{format_value(result['run_status'])}",
            "",
            f"**Source SHA-256:** "
            f"`{format_value(result['source_sha256'])}`",
            "",
            "### Investigation Coverage",
            "",
            f"- Recognized HTTP tool calls: "
            f"{investigation['recognized_http_tool_calls']}",
            f"- Executed HTTP tool steps: "
            f"{investigation['executed_http_tool_steps']}",
            f"- Evidence records: "
            f"{investigation['evidence_records']}",
            f"- Endpoints: "
            f"{', '.join(investigation['unique_endpoints']) or 'None'}",
            f"- Identities: "
            f"{', '.join(investigation['identities']) or 'None'}",
            "",
            "### Finding Classification",
            "",
            f"- Submitted: {findings['submitted']}",
            f"- Categories: "
            f"{', '.join(findings['categories']) or 'None'}",
            f"- Verified: {format_value(findings['verified'])}",
            f"- Unsupported: "
            f"{format_value(findings['unsupported'])}",
            f"- Rejected: {format_value(findings['rejected'])}",
            f"- Unadjudicated: "
            f"{format_value(findings['unadjudicated'])}",
            f"- Seeded weakness discovered: "
            f"{format_value(findings['seeded_discovered'])}",
            "",
            "### Diagnostic Indicators",
            "",
        ])

        if not result["diagnostics"]:
            lines.append(
                "No diagnostic indicators triggered "
                "under the current rule set."
            )

        for item in result["diagnostics"]:
            lines.extend([
                f"**{item['code']}**",
                "",
                item["detail"],
                "",
                f"Evidence basis: `{item['basis']}`",
                "",
            ])

    lines.extend([
        "",
        "## Limitations",
        "",
        "- One run is not a statistical estimate of model capability.",
        "- Text-based tool-intent detection is heuristic.",
        "- Endpoint coverage does not establish exploitability.",
        "- Unadjudicated findings are not confirmed false positives.",
        "- Diagnostic labels do not change benchmark scores.",
        "",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Analyze saved VulnForge investigations"
    )

    parser.add_argument(
        "artifacts",
        nargs="+",
        type=Path,
        help="One or more investigation JSON artifacts",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional Markdown report destination",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print structured diagnostic metadata",
    )

    args = parser.parse_args()

    results = []

    for path in args.artifacts:
        try:
            results.append(analyze_file(path))
        except (DiagnosticError, OSError) as exc:
            parser.error(f"{path}: {exc}")

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        report = render_markdown(results)

        if args.output is None:
            print(report)
        else:
            args.output.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with args.output.open(
                "x",
                encoding="utf-8",
            ) as handle:
                handle.write(report)

            print("Diagnostic report saved:", args.output)


if __name__ == "__main__":
    main()

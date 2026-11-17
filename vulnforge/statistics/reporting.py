
"""Deterministic statistical reporting for VulnForge.

Renders protocol-aware aggregation summaries as Markdown or JSON.
Does not execute experiments, alter evidence, or recompute scores.
"""

import json
import math
from typing import Any


REPORT_SCHEMA = "6.6A-3A"


class ReportingError(ValueError):
    """Raised when a statistical summary cannot be rendered."""


def _percentage(value: float | None) -> str:
    """Format a proportion as a percentage."""

    if value is None:
        return "N/A"

    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not 0 <= value <= 1
    ):
        raise ReportingError("Invalid proportion")

    return f"{value * 100:.1f}%"


def _duration(value: float | None) -> str:
    """Format a mean duration without inventing measurements."""

    if value is None:
        return "N/A"

    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ReportingError("Invalid duration")

    return f"{value:.3f} s"


def _interval(value: dict | None) -> str:
    """Format a Wilson confidence interval."""

    if value is None:
        return "N/A"

    if not isinstance(value, dict):
        raise ReportingError("Invalid confidence interval")

    confidence = value.get("confidence")
    lower = value.get("lower")
    upper = value.get("upper")

    if (
        not isinstance(confidence, (int, float))
        or isinstance(confidence, bool)
        or not math.isfinite(confidence)
        or not 0 < confidence < 1
    ):
        raise ReportingError("Invalid confidence level")

    if (
        not isinstance(lower, (int, float))
        or isinstance(lower, bool)
        or not math.isfinite(lower)
        or not isinstance(upper, (int, float))
        or isinstance(upper, bool)
        or not math.isfinite(upper)
        or not 0 <= lower <= upper <= 1
    ):
        raise ReportingError("Invalid interval bounds")

    return (
        f"{confidence * 100:.0f}% Wilson CI: "
        f"{_percentage(lower)}–{_percentage(upper)}"
    )


def _safe_text(value: Any) -> str:
    """Escape Markdown table separators and line breaks."""

    text = str(value)

    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _validate_summary(summary: dict) -> None:
    """Validate the expected aggregation structure."""

    if not isinstance(summary, dict):
        raise ReportingError("Summary must be an object")

    if summary.get("schema_version") != "6.6A-2":
        raise ReportingError(
            "Unsupported aggregation schema"
        )

    if not isinstance(summary.get("groups"), list):
        raise ReportingError("Missing statistical groups")

    if not isinstance(
        summary.get("excluded_trials"), dict
    ):
        raise ReportingError("Missing exclusion accounting")

    for name in (
        "input_records",
        "unique_run_ids",
        "eligible_trials",
    ):
        value = summary.get(name)

        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
        ):
            raise ReportingError(
                f"Invalid summary count: {name}"
            )


def render_markdown(summary: dict) -> str:
    """Render a statistical aggregation as Markdown."""

    _validate_summary(summary)

    lines = [
        "# VulnForge — Statistical Benchmark Report",
        "",
        "## Methodology",
        "",
        "This report summarizes saved experiment results "
        "using protocol-aware aggregation.",
        "",
        "Only eligible, independently evaluated runs are "
        "included in performance-rate denominators.",
        "",
        "Vulnerable and patched targets are analyzed "
        "separately. Different protocol fingerprints "
        "are never pooled.",
        "",
        "Confidence intervals use the two-sided Wilson "
        "score method.",
        "",
        "## Experiment Accounting",
        "",
        "| Metric | Count |",
        "|---|---:|",
        f"| Input records | {summary['input_records']} |",
        f"| Unique run IDs | {summary['unique_run_ids']} |",
        f"| Eligible trials | {summary['eligible_trials']} |",
        "",
        "## Excluded Experiments",
        "",
    ]

    exclusions = summary["excluded_trials"]

    if exclusions:
        lines.extend([
            "| Reason | Count |",
            "|---|---:|",
        ])

        for reason, count in sorted(exclusions.items()):
            lines.append(
                f"| {_safe_text(reason)} | {count} |"
            )
    else:
        lines.append(
            "No experiment records were excluded."
        )

    lines.extend([
        "",
        "## Statistical Results",
        "",
    ])

    groups = summary["groups"]

    if not groups:
        lines.extend([
            "No eligible protocol-linked experiments "
            "were available for statistical analysis.",
            "",
        ])

    for index, group in enumerate(groups, start=1):
        if not isinstance(group, dict):
            raise ReportingError("Malformed statistical group")

        mode = group.get("target_mode")
        metric = group.get("metric")

        if mode == "vulnerable":
            if metric != "seeded_discovery_rate":
                raise ReportingError(
                    "Invalid vulnerable-target metric"
                )

            successes = group.get("discoveries")
            failures = group.get("misses")
            rate = group.get("discovery_rate")

            metric_name = "Seeded vulnerability discovery"
            success_name = "Discoveries"
            failure_name = "Misses"

        elif mode == "patched":
            if metric != "patched_verified_claim_rate":
                raise ReportingError(
                    "Invalid patched-target metric"
                )

            successes = group.get(
                "runs_with_verified_claims"
            )
            failures = group.get(
                "runs_without_verified_claims"
            )
            rate = group.get("verified_claim_rate")

            metric_name = "Patched-target verified claims"
            success_name = "Runs with verified claims"
            failure_name = "Runs without verified claims"

        else:
            raise ReportingError("Invalid target mode")

        if (
            not isinstance(successes, int)
            or isinstance(successes, bool)
            or not isinstance(failures, int)
            or isinstance(failures, bool)
            or successes < 0
            or failures < 0
            or successes + failures
            != group.get("eligible_trials")
        ):
            raise ReportingError(
                "Inconsistent statistical counts"
            )

        lines.extend([
            f"### {index}. "
            f"{_safe_text(group.get('target_id'))} — "
            f"{_safe_text(mode)}",
            "",
            f"**Model:** {_safe_text(group.get('model'))}",
            "",
            f"**Provider:** "
            f"{_safe_text(group.get('provider'))}",
            "",
            f"**Protocol fingerprint:** "
            f"`{_safe_text(group.get('protocol_fingerprint'))}`",
            "",
            "| Metric | Result |",
            "|---|---:|",
            f"| Eligible trials | {group['eligible_trials']} |",
            f"| {success_name} | {successes} |",
            f"| {failure_name} | {failures} |",
            f"| {metric_name} rate | {_percentage(rate)} |",
            f"| Confidence interval | "
            f"{_interval(group.get('confidence_interval'))} |",
            f"| Mean duration | "
            f"{_duration(group.get('mean_duration_seconds'))} |",
            f"| Duration samples | "
            f"{group.get('duration_samples')} |",
            "",
        ])

        if mode == "patched":
            lines.extend([
                "**Interpretation:** Verified claims on "
                "patched targets are anomaly indicators, "
                "not automatically confirmed false positives.",
                "",
            ])

        run_ids = group.get("run_ids", [])

        if not isinstance(run_ids, list):
            raise ReportingError("Invalid run IDs")

        lines.extend([
            "**Included run IDs:**",
            "",
        ])

        for run_id in run_ids:
            lines.append(
                f"- `{_safe_text(run_id)}`"
            )

        lines.append("")

    lines.extend([
        "## Limitations",
        "",
    ])

    limitations = summary.get("limitations", [])

    if not isinstance(limitations, list):
        raise ReportingError("Invalid limitations")

    for limitation in limitations:
        lines.append(
            f"- {_safe_text(limitation)}"
        )

    lines.extend([
        "- A protocol fingerprint does not prove "
        "bit-for-bit reproducibility.",
        "- Small samples should not be interpreted "
        "as definitive model capability estimates.",
        "- This report does not independently rehash "
        "the underlying evidence artifacts.",
        "",
        "## Reproducibility",
        "",
        f"- Aggregation schema: `{summary['schema_version']}`",
        f"- Reporting schema: `{REPORT_SCHEMA}`",
        "- Source: saved VulnForge experiment result JSON files.",
        "- Historical records without validated protocol "
        "identity are excluded by default.",
        "- No models, containers, or targets are executed "
        "during report generation.",
        "",
    ])

    return "\n".join(lines)


def render_json(summary: dict) -> str:
    """Serialize the validated aggregation without mutation."""

    _validate_summary(summary)

    payload = {
        "report_schema": REPORT_SCHEMA,
        "aggregation": summary,
    }

    try:
        return json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        ) + "\n"
    except (TypeError, ValueError) as exc:
        raise ReportingError(
            "Statistical report is not JSON serializable"
        ) from exc

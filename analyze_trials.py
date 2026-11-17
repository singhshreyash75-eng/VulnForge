
"""VulnForge 6.6A-3B: offline statistical reporting CLI.

Reads saved experiment results and writes JSON and Markdown reports.
Does not run models, start containers, or modify source artifacts.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from uuid import uuid4

from vulnforge.statistics.aggregator import (
    AggregationError,
    aggregate_directory,
)
from vulnforge.statistics.reporting import (
    ReportingError,
    render_json,
    render_markdown,
)


class ReportOutputError(RuntimeError):
    """Raised when report output cannot be safely published."""


def output_paths(base: Path) -> tuple[Path, Path]:
    """Derive report paths from a filename without an extension."""

    base = Path(base)

    if base.suffix:
        raise ReportOutputError(
            "Output must be a basename without an extension"
        )

    if not base.name or base.name in (".", ".."):
        raise ReportOutputError("Invalid output basename")

    return (
        base.with_suffix(".json"),
        base.with_suffix(".md"),
    )


def write_reports(
    base: Path,
    json_content: str,
    markdown_content: str,
) -> tuple[Path, Path]:
    """Publish two reports without overwriting existing files.

    Prepare both temporary files before publication. If ordinary
    publication fails, remove only files created by this invocation.
    """

    json_path, markdown_path = output_paths(base)

    if json_path == markdown_path:
        raise ReportOutputError("Output paths must be distinct")

    for path in (json_path, markdown_path):
        if path.exists() or path.is_symlink():
            raise FileExistsError(
                f"Report already exists: {path}"
            )

    json_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_paths = []
    published_paths = []

    try:
        for destination, content in (
            (json_path, json_content),
            (markdown_path, markdown_content),
        ):
            temporary = destination.with_name(
                f".{destination.name}.{uuid4().hex}.tmp"
            )

            with temporary.open(
                "x", encoding="utf-8"
            ) as handle:
                temporary_paths.append(temporary)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())

        # Hard-link publication refuses to replace existing files.
        for temporary, destination in zip(
            temporary_paths,
            (json_path, markdown_path),
        ):
            os.link(temporary, destination)
            published_paths.append(destination)

    except Exception:
        for path in reversed(published_paths):
            path.unlink(missing_ok=True)
        raise

    finally:
        for temporary in temporary_paths:
            temporary.unlink(missing_ok=True)

    return json_path, markdown_path


def generate_reports(
    results_directory: Path,
    output_base: Path,
) -> dict:
    """Aggregate existing results and publish both report formats."""

    results_directory = Path(results_directory)
    output_base = Path(output_base)

    # Validate output naming before reading the input collection.
    output_paths(output_base)

    summary = aggregate_directory(results_directory)

    # Render both formats before creating any output file.
    json_content = render_json(summary)
    markdown_content = render_markdown(summary)

    json_path, markdown_path = write_reports(
        output_base,
        json_content,
        markdown_content,
    )

    return {
        "input_records": summary["input_records"],
        "eligible_trials": summary["eligible_trials"],
        "excluded_trials": summary["excluded_trials"],
        "groups": len(summary["groups"]),
        "json_path": str(json_path),
        "markdown_path": str(markdown_path),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Generate offline, protocol-aware VulnForge "
            "statistical benchmark reports."
        )
    )

    parser.add_argument(
        "--results",
        type=Path,
        default=Path("artifacts/experiments/results"),
        help="Directory containing executor result JSON files",
    )

    parser.add_argument(
        "--output",
        type=Path,
        default=Path(
            "artifacts/reports/statistical_baseline"
        ),
        help="Output basename without .json or .md extension",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        result = generate_reports(
            args.results,
            args.output,
        )

    except (
        AggregationError,
        ReportingError,
        ReportOutputError,
        FileExistsError,
        OSError,
        ValueError,
    ) as exc:
        print(
            f"VulnForge reporting failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print("\nVULNFORGE - STATISTICAL REPORT")
    print("=" * 55)
    print("Input records:", result["input_records"])
    print("Eligible trials:", result["eligible_trials"])
    print("Excluded:", result["excluded_trials"])
    print("Statistical groups:", result["groups"])
    print("JSON report:", result["json_path"])
    print("Markdown report:", result["markdown_path"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

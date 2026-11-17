
"""Offline regression tests for statistical report rendering."""

import copy
import json

import pytest

from vulnforge.statistics.aggregator import (
    aggregate_results,
)
from vulnforge.statistics.reporting import (
    REPORT_SCHEMA,
    ReportingError,
    render_json,
    render_markdown,
)


FINGERPRINT = "a" * 64
DIGEST = "b" * 64


def experiment(
    run_id="run-1",
    mode="vulnerable",
    discovered=False,
    verified=0,
):
    return {
        "run_id": run_id,
        "target_id": "input-api-v1",
        "status": "completed",
        "config": {
            "target_id": "input-api-v1",
            "target_mode": mode,
            "provider": "ollama",
            "model": "qwen2.5-coder:7b",
        },
        "protocol_fingerprint": FINGERPRINT,
        "protocol_validation": {
            "valid": True,
            "errors": [],
        },
        "target_mode_verified": True,
        "artifact_sha256": DIGEST,
        "duration_seconds": 20.0,
        "benchmark_summary": {
            "run_status": "completed",
            "integrity_valid": True,
            "evaluation": {
                "evaluation_status": "valid",
                "oracle_valid": True,
                "target_mode": mode,
                "verified_findings": verified,
                "seeded_vulnerability_discovered": (
                    discovered
                    if mode == "vulnerable"
                    else False
                ),
                "seeded_vulnerability_missed": (
                    not discovered
                    if mode == "vulnerable"
                    else False
                ),
            },
        },
    }


def summary():
    return aggregate_results([
        experiment("run-1"),
        experiment("run-2", discovered=True),
    ])


def test_reporting_schema():
    assert REPORT_SCHEMA == "6.6A-3A"


def test_markdown_title():
    report = render_markdown(summary())

    assert "# VulnForge" in report
    assert "Statistical Benchmark Report" in report


def test_methodology_present():
    report = render_markdown(summary())

    assert "## Methodology" in report
    assert "Wilson" in report


def test_accounting_present():
    report = render_markdown(summary())

    assert "| Input records | 2 |" in report
    assert "| Eligible trials | 2 |" in report


def test_discovery_rate():
    report = render_markdown(summary())

    assert "50.0%" in report
    assert "Seeded vulnerability discovery" in report


def test_confidence_interval():
    report = render_markdown(summary())

    assert "95% Wilson CI" in report


def test_protocol_fingerprint():
    report = render_markdown(summary())

    assert FINGERPRINT in report


def test_run_ids():
    report = render_markdown(summary())

    assert "`run-1`" in report
    assert "`run-2`" in report


def test_duration():
    report = render_markdown(summary())

    assert "20.000 s" in report


def test_exclusion_reporting():
    records = [
        experiment("run-1"),
        experiment("run-2"),
    ]

    records[1]["status"] = "failed"

    report = render_markdown(
        aggregate_results(records)
    )

    assert "execution_failed" in report


def test_patched_reporting():
    report = render_markdown(
        aggregate_results([
            experiment(
                "patched-1",
                mode="patched",
                verified=1,
            ),
        ])
    )

    assert "Patched-target verified claims" in report
    assert "not automatically confirmed false positives" in report


def test_empty_summary():
    report = render_markdown(
        aggregate_results([])
    )

    assert "No eligible protocol-linked experiments" in report


def test_json_report():
    payload = json.loads(
        render_json(summary())
    )

    assert payload["report_schema"] == REPORT_SCHEMA
    assert payload["aggregation"]["eligible_trials"] == 2


def test_json_deterministic():
    data = summary()

    assert render_json(data) == render_json(data)


def test_markdown_deterministic():
    data = summary()

    assert render_markdown(data) == render_markdown(data)


def test_no_mutation():
    data = summary()
    original = copy.deepcopy(data)

    render_markdown(data)
    render_json(data)

    assert data == original


def test_invalid_summary_rejected():
    with pytest.raises(ReportingError):
        render_markdown(None)


def test_wrong_schema_rejected():
    data = summary()
    data["schema_version"] = "unknown"

    with pytest.raises(ReportingError):
        render_markdown(data)


def test_missing_groups_rejected():
    data = summary()
    del data["groups"]

    with pytest.raises(ReportingError):
        render_markdown(data)


def test_invalid_count_rejected():
    data = summary()
    data["eligible_trials"] = -1

    with pytest.raises(ReportingError):
        render_markdown(data)


def test_invalid_group_mode_rejected():
    data = summary()
    data["groups"][0]["target_mode"] = "production"

    with pytest.raises(ReportingError):
        render_markdown(data)


def test_inconsistent_group_counts_rejected():
    data = summary()
    data["groups"][0]["discoveries"] = 100

    with pytest.raises(ReportingError):
        render_markdown(data)


def test_invalid_confidence_interval_rejected():
    data = summary()

    data["groups"][0]["confidence_interval"]["lower"] = 0.9
    data["groups"][0]["confidence_interval"]["upper"] = 0.1

    with pytest.raises(ReportingError):
        render_markdown(data)


def test_json_nonfinite_rejected():
    data = summary()
    data["groups"][0]["mean_duration_seconds"] = float("nan")

    with pytest.raises(ReportingError):
        render_json(data)


def test_markdown_table_escaping():
    data = summary()
    data["groups"][0]["model"] = "model|unsafe"

    report = render_markdown(data)

    assert "model\\|unsafe" in report


def test_limitations_present():
    report = render_markdown(summary())

    assert "## Limitations" in report
    assert "bit-for-bit reproducibility" in report


def test_reproducibility_present():
    report = render_markdown(summary())

    assert "## Reproducibility" in report
    assert "6.6A-2" in report


def test_missing_exclusions_rejected():
    data = summary()
    del data["excluded_trials"]

    with pytest.raises(ReportingError):
        render_json(data)

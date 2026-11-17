
"""Offline regression tests for VulnForge statistical CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from analyze_trials import (
    ReportOutputError,
    generate_reports,
    main,
    output_paths,
    write_reports,
)


FP = "a" * 64
DIGEST = "b" * 64


def experiment(run_id="test-run", discovered=False):
    return {
        "run_id": run_id,
        "target_id": "input-api-v1",
        "status": "completed",
        "config": {
            "target_id": "input-api-v1",
            "target_mode": "vulnerable",
            "provider": "ollama",
            "model": "qwen2.5-coder:7b",
        },
        "protocol_fingerprint": FP,
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
                "target_mode": "vulnerable",
                "verified_findings": 0,
                "seeded_vulnerability_discovered": discovered,
                "seeded_vulnerability_missed": not discovered,
            },
        },
    }


def make_results(tmp_path):
    directory = tmp_path / "results"
    directory.mkdir()

    for index, discovered in enumerate((False, True)):
        path = directory / f"run-{index}.json"
        path.write_text(
            json.dumps(
                experiment(
                    run_id=f"run-{index}",
                    discovered=discovered,
                )
            ),
            encoding="utf-8",
        )

    return directory


def test_output_paths(tmp_path):
    base = tmp_path / "report"

    assert output_paths(base) == (
        tmp_path / "report.json",
        tmp_path / "report.md",
    )


def test_extension_rejected(tmp_path):
    with pytest.raises(ReportOutputError):
        output_paths(tmp_path / "report.json")


def test_write_reports(tmp_path):
    base = tmp_path / "report"

    json_path, markdown_path = write_reports(
        base,
        '{"valid":true}\n',
        "# Report\n",
    )

    assert json_path.read_text() == '{"valid":true}\n'
    assert markdown_path.read_text() == "# Report\n"


def test_existing_json_not_overwritten(tmp_path):
    base = tmp_path / "report"
    existing = tmp_path / "report.json"
    existing.write_text("original")

    with pytest.raises(FileExistsError):
        write_reports(base, "new", "new")

    assert existing.read_text() == "original"
    assert not (tmp_path / "report.md").exists()


def test_existing_markdown_not_overwritten(tmp_path):
    base = tmp_path / "report"
    existing = tmp_path / "report.md"
    existing.write_text("original")

    with pytest.raises(FileExistsError):
        write_reports(base, "new", "new")

    assert existing.read_text() == "original"
    assert not (tmp_path / "report.json").exists()


def test_report_generation(tmp_path):
    results = make_results(tmp_path)
    output = tmp_path / "reports" / "baseline"

    generated = generate_reports(results, output)

    assert generated["input_records"] == 2
    assert generated["eligible_trials"] == 2
    assert generated["groups"] == 1

    json_report = json.loads(
        (tmp_path / "reports" / "baseline.json").read_text()
    )

    assert (
        json_report["aggregation"]["groups"][0][
            "discovery_rate"
        ] == 0.5
    )

    markdown = (
        tmp_path / "reports" / "baseline.md"
    ).read_text()

    assert "Statistical Benchmark Report" in markdown


def test_no_overwrite_on_second_run(tmp_path):
    results = make_results(tmp_path)
    output = tmp_path / "baseline"

    generate_reports(results, output)

    with pytest.raises(FileExistsError):
        generate_reports(results, output)


def test_missing_result_directory(tmp_path):
    with pytest.raises(ValueError):
        generate_reports(
            tmp_path / "missing",
            tmp_path / "report",
        )


def test_invalid_json_no_outputs(tmp_path):
    results = tmp_path / "results"
    results.mkdir()

    (results / "bad.json").write_text("{invalid")

    output = tmp_path / "report"

    with pytest.raises(ValueError):
        generate_reports(results, output)

    assert not output.with_suffix(".json").exists()
    assert not output.with_suffix(".md").exists()


def test_empty_results_directory(tmp_path):
    results = tmp_path / "results"
    results.mkdir()

    output = tmp_path / "report"

    generated = generate_reports(results, output)

    assert generated["eligible_trials"] == 0
    assert generated["groups"] == 0


def test_main_success(tmp_path, capsys):
    results = make_results(tmp_path)
    output = tmp_path / "baseline"

    code = main([
        "--results", str(results),
        "--output", str(output),
    ])

    assert code == 0
    assert "Eligible trials: 2" in capsys.readouterr().out


def test_main_failure(tmp_path, capsys):
    code = main([
        "--results", str(tmp_path / "missing"),
        "--output", str(tmp_path / "report"),
    ])

    assert code == 1
    assert "reporting failed" in capsys.readouterr().err


def test_cli_help():
    project_root = Path(__file__).resolve().parents[1]

    process = subprocess.run(
        [
            sys.executable,
            str(project_root / "analyze_trials.py"),
            "--help",
        ],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert process.returncode == 0
    assert "--results" in process.stdout
    assert "--output" in process.stdout


def test_cli_subprocess(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    results = make_results(tmp_path)
    output = tmp_path / "subprocess-report"

    process = subprocess.run(
        [
            sys.executable,
            str(project_root / "analyze_trials.py"),
            "--results",
            str(results),
            "--output",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )

    assert process.returncode == 0, process.stderr
    assert output.with_suffix(".json").is_file()
    assert output.with_suffix(".md").is_file()


def test_source_results_unchanged(tmp_path):
    results = make_results(tmp_path)

    before = {
        path.name: path.read_bytes()
        for path in results.glob("*.json")
    }

    generate_reports(
        results,
        tmp_path / "report",
    )

    after = {
        path.name: path.read_bytes()
        for path in results.glob("*.json")
    }

    assert before == after


def test_no_temporary_files_left(tmp_path):
    base = tmp_path / "report"

    write_reports(base, "{}", "# Report")

    assert list(tmp_path.glob("*.tmp")) == []
    assert list(tmp_path.glob(".*.tmp")) == []


def test_symlink_output_rejected(tmp_path):
    destination = tmp_path / "destination.txt"
    destination.write_text("protected")

    symlink = tmp_path / "report.json"
    symlink.symlink_to(destination)

    with pytest.raises(FileExistsError):
        write_reports(
            tmp_path / "report",
            "{}",
            "# Report",
        )

    assert destination.read_text() == "protected"

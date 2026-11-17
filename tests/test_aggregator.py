
"""Offline tests for VulnForge statistical aggregation."""

import copy
import json

import pytest

from vulnforge.statistics.aggregator import (
    AggregationError,
    aggregate_directory,
    aggregate_results,
    classify_result,
    load_result_files,
)


FP_A = "a" * 64
FP_B = "b" * 64
DIGEST = "c" * 64


def result(
    run_id="run-1",
    target="input-api-v1",
    mode="vulnerable",
    fingerprint=FP_A,
    discovered=False,
    status="completed",
    verified=0,
):
    evaluation = {
        "evaluation_status": "valid",
        "oracle_valid": True,
        "target_mode": mode,
        "verified_findings": verified,
        "seeded_vulnerability_discovered": (
            discovered if mode == "vulnerable" else False
        ),
        "seeded_vulnerability_missed": (
            not discovered if mode == "vulnerable" else False
        ),
    }

    return {
        "run_id": run_id,
        "target_id": target,
        "status": status,
        "config": {
            "target_id": target,
            "target_mode": mode,
            "provider": "ollama",
            "model": "qwen2.5-coder:7b",
        },
        "protocol_fingerprint": fingerprint,
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
            "evaluation": evaluation,
        },
    }


def test_valid_vulnerable_result():
    classification = classify_result(result())

    assert classification["eligible"]
    assert classification["outcome"] == "missed"


def test_discovery_classification():
    classification = classify_result(
        result(discovered=True)
    )

    assert classification["outcome"] == "discovered"


def test_zero_of_three():
    records = [
        result(run_id=f"run-{i}")
        for i in range(3)
    ]

    group = aggregate_results(records)["groups"][0]

    assert group["discoveries"] == 0
    assert group["misses"] == 3
    assert group["discovery_rate"] == 0
    assert group["confidence_interval"]["upper"] > 0


def test_one_of_three():
    records = [
        result("run-1", discovered=True),
        result("run-2"),
        result("run-3"),
    ]

    group = aggregate_results(records)["groups"][0]

    assert group["discoveries"] == 1
    assert group["misses"] == 2
    assert group["discovery_rate"] == pytest.approx(1 / 3)


def test_all_discovered():
    records = [
        result(f"run-{i}", discovered=True)
        for i in range(3)
    ]

    group = aggregate_results(records)["groups"][0]

    assert group["discovery_rate"] == 1


def test_failed_excluded():
    records = [
        result("run-1"),
        result("run-2", status="failed"),
    ]

    summary = aggregate_results(records)

    assert summary["eligible_trials"] == 1
    assert summary["excluded_trials"]["execution_failed"] == 1


def test_invalid_excluded():
    summary = aggregate_results([
        result(status="invalid")
    ])

    assert summary["eligible_trials"] == 0
    assert summary["excluded_trials"]["execution_invalid"] == 1


def test_missing_protocol_excluded():
    record = result()
    record["protocol_fingerprint"] = None

    summary = aggregate_results([record])

    assert summary["eligible_trials"] == 0


def test_invalid_protocol_excluded():
    record = result()
    record["protocol_validation"]["valid"] = False

    assert not classify_result(record)["eligible"]


def test_missing_artifact_digest_excluded():
    record = result()
    record["artifact_sha256"] = None

    assert not classify_result(record)["eligible"]


def test_target_mode_unverified():
    record = result()
    record["target_mode_verified"] = False

    assert not classify_result(record)["eligible"]


def test_missing_evaluation():
    record = result()
    record["benchmark_summary"]["evaluation"] = None

    assert not classify_result(record)["eligible"]


def test_missing_discovery_not_a_miss():
    record = result()
    del record["benchmark_summary"]["evaluation"][
        "seeded_vulnerability_discovered"
    ]

    summary = aggregate_results([record])

    assert summary["eligible_trials"] == 0
    assert summary["groups"] == []


def test_contradictory_discovery_rejected():
    record = result()
    record["benchmark_summary"]["evaluation"][
        "seeded_vulnerability_missed"
    ] = False

    assert not classify_result(record)["eligible"]


def test_patched_separate():
    records = [
        result("v1", mode="vulnerable"),
        result("p1", mode="patched"),
    ]

    summary = aggregate_results(records)

    assert len(summary["groups"]) == 2
    assert {
        group["metric"] for group in summary["groups"]
    } == {
        "seeded_discovery_rate",
        "patched_verified_claim_rate",
    }


def test_patched_verified_claim():
    group = aggregate_results([
        result("p1", mode="patched", verified=1),
        result("p2", mode="patched", verified=0),
    ])["groups"][0]

    assert group["runs_with_verified_claims"] == 1
    assert group["verified_claim_rate"] == 0.5


def test_protocols_never_pooled():
    summary = aggregate_results([
        result("a1", fingerprint=FP_A),
        result("b1", fingerprint=FP_B),
    ])

    assert len(summary["groups"]) == 2


def test_targets_never_pooled():
    summary = aggregate_results([
        result("a1", target="input-api-v1"),
        result("b1", target="document-api-v1"),
    ])

    assert len(summary["groups"]) == 2


def test_models_never_pooled():
    first = result("a1")
    second = result("b1")
    second["config"]["model"] = "another-model"

    summary = aggregate_results([first, second])

    assert len(summary["groups"]) == 2


def test_duplicate_identical_run_excluded():
    record = result()

    summary = aggregate_results([
        record,
        copy.deepcopy(record),
    ])

    assert summary["eligible_trials"] == 1
    assert summary["excluded_trials"]["duplicate_run_id"] == 1


def test_conflicting_duplicate_rejected():
    first = result()
    second = result(discovered=True)

    with pytest.raises(AggregationError):
        aggregate_results([first, second])


def test_missing_run_id_excluded():
    record = result()
    del record["run_id"]

    summary = aggregate_results([record])

    assert summary["eligible_trials"] == 0
    assert summary["excluded_trials"]["missing_run_id"] == 1


def test_mean_duration():
    first = result("a1")
    second = result("a2")
    second["duration_seconds"] = 40.0

    group = aggregate_results([first, second])["groups"][0]

    assert group["mean_duration_seconds"] == 30.0


def test_nonfinite_duration_ignored():
    record = result()
    record["duration_seconds"] = float("nan")

    group = aggregate_results([record])["groups"][0]

    assert group["mean_duration_seconds"] is None
    assert group["duration_samples"] == 0


def test_input_not_mutated():
    records = [result()]
    original = copy.deepcopy(records)

    aggregate_results(records)

    assert records == original


def test_empty_results():
    summary = aggregate_results([])

    assert summary["eligible_trials"] == 0
    assert summary["groups"] == []


def test_invalid_collection_rejected():
    with pytest.raises(AggregationError):
        aggregate_results(None)


def test_load_files(tmp_path):
    path = tmp_path / "result.json"
    record = result()
    path.write_text(json.dumps(record))

    loaded = load_result_files([path])

    assert loaded == [record]


def test_invalid_json_rejected(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{invalid")

    with pytest.raises(AggregationError):
        load_result_files([path])


def test_directory_aggregation(tmp_path):
    for i in range(3):
        path = tmp_path / f"{i}.json"
        path.write_text(
            json.dumps(result(run_id=f"run-{i}"))
        )

    summary = aggregate_directory(tmp_path)

    assert summary["eligible_trials"] == 3


def test_missing_directory_rejected(tmp_path):
    with pytest.raises(AggregationError):
        aggregate_directory(tmp_path / "missing")

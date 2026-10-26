
"""Offline tests for repeated-trial orchestration."""

import json
from unittest.mock import AsyncMock

import pytest

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments import trials


def make_config(**kwargs):
    values = {
        "target_mode": "vulnerable",
        "model": "qwen2.5-coder:7b",
    }
    values.update(kwargs)
    return ExperimentConfig(**values)


def result(
    status="completed",
    discovered=False,
    missed=False,
):
    return {
        "status": status,
        "duration_seconds": 10.0,
        "benchmark_summary": {
            "evaluation": {
                "evaluation_status": "valid",
                "seeded_vulnerability_discovered": discovered,
                "seeded_vulnerability_missed": missed,
                "verified_findings": int(discovered),
                "unsupported_findings": 0,
                "rejected_findings": 0,
                "inconclusive_findings": 0,
                "unadjudicated_findings": 0,
            }
        } if status == "completed" else None,
    }


def test_empty_summary():
    summary = trials.summarize_trials([])
    assert summary["total_trials"] == 0
    assert summary["discovery_rate_among_valid_evaluations"] is None


def test_all_missed():
    summary = trials.summarize_trials([
        result(missed=True),
        result(missed=True),
        result(missed=True),
    ])

    assert summary["completed_trials"] == 3
    assert summary["seeded_misses"] == 3
    assert summary["seeded_discoveries"] == 0


def test_partial_discovery():
    summary = trials.summarize_trials([
        result(discovered=True),
        result(missed=True),
        result(discovered=True),
    ])

    assert summary["seeded_discoveries"] == 2
    assert summary["discovery_rate_among_valid_evaluations"] == (
        pytest.approx(2 / 3, abs=0.0001)
    )


def test_failed_trial_not_counted_as_discovery():
    summary = trials.summarize_trials([
        result(discovered=True),
        result(status="failed"),
    ])

    assert summary["failed_trials"] == 1
    assert summary["valid_evaluations"] == 1
    assert summary["seeded_discoveries"] == 1


def test_invalid_trial_separate():
    summary = trials.summarize_trials([
        result(status="invalid"),
        result(missed=True),
    ])

    assert summary["invalid_trials"] == 1
    assert summary["seeded_misses"] == 1


def test_mean_duration():
    summary = trials.summarize_trials([
        result(),
        result(),
    ])

    assert summary["mean_completed_duration_seconds"] == 10.0


def test_batch_file_roundtrip(tmp_path):
    payload = {
        "batch_id": "test-batch",
        "summary": {"completed_trials": 2},
    }

    path = trials.save_batch(payload, tmp_path)
    loaded = json.loads(path.read_text())

    assert loaded["batch_id"] == "test-batch"


def test_batch_file_no_overwrite(tmp_path):
    payload = {"batch_id": "same-id"}

    trials.save_batch(payload, tmp_path)

    with pytest.raises(FileExistsError):
        trials.save_batch(payload, tmp_path)


@pytest.mark.asyncio
async def test_sequential_execution(tmp_path, monkeypatch):
    calls = []

    async def fake_execute(config, timeout, cleanup):
        calls.append(config.trial_number)
        return result(missed=True)

    monkeypatch.setattr(
        trials,
        "execute_experiment",
        fake_execute,
    )

    batch = await trials.run_trial_batch(
        make_config(),
        trials=3,
        directory=tmp_path,
    )

    assert calls == [1, 2, 3]
    assert batch["summary"]["completed_trials"] == 3
    assert batch["summary"]["seeded_misses"] == 3


@pytest.mark.asyncio
async def test_execution_exception_recorded(tmp_path, monkeypatch):
    async def fake_execute(config, timeout, cleanup):
        raise RuntimeError("Simulated failure")

    monkeypatch.setattr(
        trials,
        "execute_experiment",
        fake_execute,
    )

    batch = await trials.run_trial_batch(
        make_config(),
        trials=2,
        directory=tmp_path,
    )

    assert batch["summary"]["failed_trials"] == 2
    assert len(batch["trials"]) == 2


@pytest.mark.asyncio
async def test_invalid_trial_count(tmp_path):
    with pytest.raises(ValueError):
        await trials.run_trial_batch(
            make_config(),
            trials=0,
            directory=tmp_path,
        )


@pytest.mark.asyncio
async def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        await trials.run_trial_batch(
            make_config(),
            trials=2,
            timeout=0,
            directory=tmp_path,
        )

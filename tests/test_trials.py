
"""Offline tests for reliable repeated-trial orchestration."""

import copy
import json

from unittest.mock import AsyncMock

import pytest

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments import trials


FP = "a" * 64


def make_config(**kwargs):
    values = {
        "target_id": "document-api-v1",
        "target_mode": "vulnerable",
        "model": "qwen2.5-coder:7b",
    }
    values.update(kwargs)
    return ExperimentConfig(**values)


def result(
    status="completed",
    discovered=False,
    missed=True,
    mode="vulnerable",
    fingerprint=FP,
    verified=0,
):
    return {
        "status": status,
        "target_id": "document-api-v1",
        "config": {
            "target_id": "document-api-v1",
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
        "duration_seconds": 10.0,
        "benchmark_summary": (
            {
                "run_status": "completed",
                "integrity_valid": True,
                "evaluation": {
                    "evaluation_status": "valid",
                    "oracle_valid": True,
                    "target_mode": mode,
                    "seeded_vulnerability_discovered": (
                        discovered
                    ),
                    "seeded_vulnerability_missed": missed,
                    "verified_findings": verified,
                    "unsupported_findings": 0,
                    "rejected_findings": 0,
                    "inconclusive_findings": 0,
                    "unadjudicated_findings": 0,
                },
            }
            if status == "completed" else None
        ),
    }


def test_empty_summary():
    summary = trials.summarize_trials([])

    assert summary["total_trials"] == 0
    assert summary["valid_evaluations"] == 0
    assert summary["discovery_rate_among_valid_evaluations"] is None


def test_all_missed():
    summary = trials.summarize_trials([
        result(),
        result(),
        result(),
    ])

    assert summary["completed_trials"] == 3
    assert summary["seeded_misses"] == 3
    assert summary["seeded_discoveries"] == 0
    assert summary["eligible_vulnerable_trials"] == 3


def test_partial_discovery():
    summary = trials.summarize_trials([
        result(discovered=True, missed=False),
        result(),
        result(discovered=True, missed=False),
    ])

    assert summary["seeded_discoveries"] == 2
    assert summary["discovery_rate_among_valid_evaluations"] == (
        pytest.approx(2 / 3, abs=0.0001)
    )


def test_failed_not_scored():
    summary = trials.summarize_trials([
        result(),
        result(status="failed"),
    ])

    assert summary["failed_trials"] == 1
    assert summary["eligible_vulnerable_trials"] == 1


def test_invalid_separate():
    summary = trials.summarize_trials([
        result(status="invalid"),
        result(),
    ])

    assert summary["invalid_trials"] == 1
    assert summary["seeded_misses"] == 1


def test_patched_not_discovery_denominator():
    summary = trials.summarize_trials([
        result(
            mode="patched",
            discovered=False,
            missed=False,
        ),
    ])

    assert summary["eligible_patched_trials"] == 1
    assert summary["eligible_vulnerable_trials"] == 0
    assert summary["discovery_rate_among_valid_evaluations"] is None
    assert summary["patched_verified_claim_rate"] == 0


def test_patched_verified_claim_rate():
    summary = trials.summarize_trials([
        result(
            mode="patched",
            missed=False,
            verified=1,
        ),
        result(
            mode="patched",
            missed=False,
            verified=0,
        ),
    ])

    assert summary["patched_verified_claim_rate"] == 0.5


def test_missing_protocol_excluded():
    record = result()
    record["protocol_fingerprint"] = None

    summary = trials.summarize_trials([record])

    assert summary["valid_evaluations"] == 0
    assert summary["excluded_from_scoring"][
        "protocol_not_validated"
    ] == 1


def test_invalid_protocol_excluded():
    record = result()
    record["protocol_validation"]["valid"] = False

    summary = trials.summarize_trials([record])

    assert summary["valid_evaluations"] == 0


def test_mixed_protocol_no_pooled_rate():
    summary = trials.summarize_trials([
        result(fingerprint="a" * 64),
        result(fingerprint="b" * 64),
    ])

    assert summary["protocol_compatible"] is False
    assert summary["discovery_rate_among_valid_evaluations"] is None


def test_ambiguous_outcome_excluded():
    summary = trials.summarize_trials([
        result(discovered=False, missed=False),
    ])

    assert summary["valid_evaluations"] == 0
    assert summary["excluded_from_scoring"][
        "ambiguous_discovery"
    ] == 1


def test_mean_duration():
    summary = trials.summarize_trials([
        result(),
        result(),
    ])

    assert summary["mean_completed_duration_seconds"] == 10.0


def test_summary_does_not_mutate():
    records = [result()]
    original = copy.deepcopy(records)

    trials.summarize_trials(records)

    assert records == original


def test_batch_file_roundtrip(tmp_path):
    payload = {
        "batch_id": "test-batch",
        "summary": {"completed_trials": 2},
    }

    path = trials.save_batch(payload, tmp_path)

    assert json.loads(path.read_text()) == payload


def test_batch_file_no_overwrite(tmp_path):
    payload = {"batch_id": "same-id"}

    trials.save_batch(payload, tmp_path)

    with pytest.raises(FileExistsError):
        trials.save_batch(payload, tmp_path)


def test_checkpoint_updates_batch(tmp_path):
    payload = {"batch_id": "checkpoint", "state": "running"}
    path = trials.save_batch(payload, tmp_path)

    payload["state"] = "completed"
    trials.checkpoint_batch(payload, path)

    assert json.loads(path.read_text())["state"] == "completed"


@pytest.mark.asyncio
async def test_sequential_execution(tmp_path, monkeypatch):
    calls = []
    active = 0

    async def fake_execute(config, timeout, cleanup):
        nonlocal active

        assert active == 0
        active += 1
        calls.append(config.trial_number)
        active -= 1

        return result()

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
    assert batch["state"] == "completed"
    assert batch["summary"]["seeded_misses"] == 3
    assert batch["completed_attempts"] == 3


@pytest.mark.asyncio
async def test_checkpoint_after_each_trial(
    tmp_path,
    monkeypatch,
):
    checkpoints = []
    original = trials.checkpoint_batch

    def capture(payload, path):
        checkpoints.append(payload["completed_attempts"])
        original(payload, path)

    monkeypatch.setattr(
        trials,
        "checkpoint_batch",
        capture,
    )

    monkeypatch.setattr(
        trials,
        "execute_experiment",
        AsyncMock(return_value=result()),
    )

    await trials.run_trial_batch(
        make_config(),
        trials=3,
        directory=tmp_path,
    )

    assert checkpoints == [1, 2, 3, 3]


@pytest.mark.asyncio
async def test_execution_exception_recorded(
    tmp_path,
    monkeypatch,
):
    async def fail(config, timeout, cleanup):
        raise RuntimeError("Simulated failure")

    monkeypatch.setattr(
        trials,
        "execute_experiment",
        fail,
    )

    batch = await trials.run_trial_batch(
        make_config(),
        trials=2,
        directory=tmp_path,
    )

    assert batch["summary"]["failed_trials"] == 2
    assert len(batch["trials"]) == 2


@pytest.mark.asyncio
async def test_interruption_checkpoint(
    tmp_path,
    monkeypatch,
):
    calls = 0

    async def fake_execute(config, timeout, cleanup):
        nonlocal calls
        calls += 1

        if calls == 2:
            raise KeyboardInterrupt()

        return result()

    monkeypatch.setattr(
        trials,
        "execute_experiment",
        fake_execute,
    )

    with pytest.raises(KeyboardInterrupt):
        await trials.run_trial_batch(
            make_config(),
            trials=3,
            directory=tmp_path,
        )

    paths = list(tmp_path.glob("*.json"))
    assert len(paths) == 1

    saved = json.loads(paths[0].read_text())
    assert saved["state"] == "interrupted"
    assert saved["completed_attempts"] == 1


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

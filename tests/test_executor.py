
"""Offline regression tests for registry-backed execution."""

import json
from unittest.mock import AsyncMock

import pytest

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments import executor


def config(**overrides):
    values = {
        "target_mode": "vulnerable",
        "model": "qwen2.5-coder:7b",
    }
    values.update(overrides)
    return ExperimentConfig(**values)


def test_default_config_supported():
    executor.validate_runner_config(config())


def test_wrong_model_rejected():
    with pytest.raises(ValueError):
        executor.validate_runner_config(
            config(model="other-model")
        )


def test_unsupported_budget_rejected():
    with pytest.raises(ValueError):
        executor.validate_runner_config(
            config(max_rounds=10)
        )


def test_sampling_override_rejected():
    with pytest.raises(ValueError):
        executor.validate_runner_config(
            config(temperature=0.5)
        )


@pytest.mark.asyncio
async def test_nonpositive_timeout_rejected():
    with pytest.raises(ValueError):
        await executor.execute_experiment(
            config(),
            timeout=0,
        )


def test_atomic_result_no_overwrite(tmp_path):
    path = tmp_path / "result.json"

    executor.atomic_json(path, {"status": "completed"})

    with pytest.raises(FileExistsError):
        executor.atomic_json(path, {"status": "failed"})


def test_artifact_selection(tmp_path, monkeypatch):
    monkeypatch.setattr(
        executor,
        "INVESTIGATION_DIR",
        tmp_path,
    )

    (tmp_path / "qwen_vulnerable_new.json").write_text("{}")

    selected = executor.find_new_artifact(
        set(),
        "vulnerable",
    )

    assert selected is not None
    assert selected.name == "qwen_vulnerable_new.json"


def test_ambiguous_artifacts_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(
        executor,
        "INVESTIGATION_DIR",
        tmp_path,
    )

    (tmp_path / "qwen_vulnerable_a.json").write_text("{}")
    (tmp_path / "qwen_vulnerable_b.json").write_text("{}")

    assert executor.find_new_artifact(
        set(),
        "vulnerable",
    ) is None


def setup_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(
        executor,
        "RESULT_DIR",
        tmp_path / "experiments",
    )

    monkeypatch.setattr(
        executor,
        "INVESTIGATION_DIR",
        tmp_path / "investigations",
    )

    executor.INVESTIGATION_DIR.mkdir()


def mock_manager():
    manager = AsyncMock()
    manager.target.target_id = "document-api-v1"
    return manager


@pytest.mark.asyncio
async def test_successful_execution(tmp_path, monkeypatch):
    setup_paths(tmp_path, monkeypatch)

    async def fake_investigation(mode, timeout):
        artifact = (
            executor.INVESTIGATION_DIR
            / "qwen_vulnerable_test.json"
        )

        artifact.write_text(
            json.dumps({
                "target_id": "document-api-v1",
                "target_mode": "vulnerable",
                "provider": "ollama",
                "model": "qwen2.5-coder:7b",
                "run_status": "completed",
                "integrity_valid": True,
                "trace_matches_evidence": True,
                "submission_valid": True,
                "evaluation": {
                    "evaluation_status": "valid",
                    "oracle_valid": True,
                    "seeded_vulnerability_discovered": False,
                    "seeded_vulnerability_missed": True,
                    "verified_findings": 0,
                    "unadjudicated_findings": 1,
                },
                "deduplication": {
                    "unique_verified_vulnerabilities": 0,
                },
            }),
            encoding="utf-8",
        )

        return {
            "exit_code": 0,
            "stdout": "completed",
            "stderr": "",
        }

    monkeypatch.setattr(
        executor,
        "run_investigation",
        fake_investigation,
    )

    manager = mock_manager()

    result = await executor.execute_experiment(
        config(),
        manager=manager,
    )

    assert result["status"] == "completed"
    assert result["target_mode_verified"] is True
    assert result["corpus_fingerprint"]
    assert len(result["artifact_sha256"]) == 64
    assert result["benchmark_summary"] is not None

    manager.reset.assert_awaited_once_with("vulnerable")
    manager.verify_mode.assert_awaited_once_with("vulnerable")
    manager.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_failure_is_recorded(tmp_path, monkeypatch):
    setup_paths(tmp_path, monkeypatch)

    manager = mock_manager()
    manager.reset.side_effect = RuntimeError(
        "Docker unavailable"
    )

    result = await executor.execute_experiment(
        config(),
        manager=manager,
    )

    assert result["status"] == "failed"
    assert "Docker unavailable" in result["error"]
    assert result["target_mode_verified"] is False

    saved = list(
        (tmp_path / "experiments" / "results").glob("*.json")
    )

    assert len(saved) == 1
    manager.verify_mode.assert_not_awaited()
    manager.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_mode_verification_failure(tmp_path, monkeypatch):
    setup_paths(tmp_path, monkeypatch)

    manager = mock_manager()
    manager.verify_mode.side_effect = RuntimeError(
        "Incorrect target mode"
    )

    investigation = AsyncMock()
    monkeypatch.setattr(
        executor,
        "run_investigation",
        investigation,
    )

    result = await executor.execute_experiment(
        config(),
        manager=manager,
    )

    assert result["status"] == "failed"
    assert result["target_mode_verified"] is False
    investigation.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_artifact_rejected(tmp_path, monkeypatch):
    setup_paths(tmp_path, monkeypatch)

    async def fake_investigation(mode, timeout):
        artifact = (
            executor.INVESTIGATION_DIR
            / "qwen_vulnerable_invalid.json"
        )

        artifact.write_text(
            json.dumps({
                "target_id": "document-api-v1",
                "target_mode": "vulnerable",
                "provider": "ollama",
                "model": "qwen2.5-coder:7b",
                "run_status": "completed",
                "integrity_valid": False,
                "trace_matches_evidence": False,
                "submission_valid": True,
                "evaluation": {
                    "evaluation_status": "valid",
                    "oracle_valid": True,
                },
            }),
            encoding="utf-8",
        )

        return {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }

    monkeypatch.setattr(
        executor,
        "run_investigation",
        fake_investigation,
    )

    result = await executor.execute_experiment(
        config(),
        manager=mock_manager(),
    )

    assert result["status"] == "invalid"
    assert result["error"] == "benchmark_validation_failed"


def test_benchmark_validation_rejects_wrong_target():
    payload = {
        "target_id": "another-target",
        "target_mode": "vulnerable",
        "provider": "ollama",
        "model": "qwen2.5-coder:7b",
        "run_status": "completed",
        "integrity_valid": True,
        "trace_matches_evidence": True,
        "submission_valid": True,
        "evaluation": {
            "evaluation_status": "valid",
            "oracle_valid": True,
        },
    }

    assert not executor.benchmark_is_valid(
        payload,
        config(),
    )

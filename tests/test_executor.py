
"""Offline tests for the VulnForge experiment executor."""

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
            config(
                max_rounds=10,
                max_tool_calls=20,
                max_http_requests=20,
            )
        )


def test_sampling_override_rejected():
    with pytest.raises(ValueError):
        executor.validate_runner_config(
            config(temperature=0.5)
        )


def test_nonpositive_timeout_rejected():
    with pytest.raises(ValueError):
        asyncio_run_invalid_timeout()


def asyncio_run_invalid_timeout():
    import asyncio

    return asyncio.run(
        executor.execute_experiment(
            config(),
            timeout=0,
        )
    )


def test_atomic_result_no_overwrite(tmp_path):
    path = tmp_path / "result.json"

    executor.atomic_json(
        path,
        {"status": "completed"},
    )

    with pytest.raises(FileExistsError):
        executor.atomic_json(
            path,
            {"status": "failed"},
        )


def test_artifact_selection(tmp_path, monkeypatch):
    monkeypatch.setattr(
        executor,
        "INVESTIGATION_DIR",
        tmp_path,
    )

    (
        tmp_path / "qwen_vulnerable_new.json"
    ).write_text("{}")

    selected = executor.find_new_artifact(
        set(),
        "vulnerable",
    )

    assert selected is not None
    assert selected.name == "qwen_vulnerable_new.json"


def test_ambiguous_artifacts_rejected(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setattr(
        executor,
        "INVESTIGATION_DIR",
        tmp_path,
    )

    (
        tmp_path / "qwen_vulnerable_a.json"
    ).write_text("{}")

    (
        tmp_path / "qwen_vulnerable_b.json"
    ).write_text("{}")

    assert executor.find_new_artifact(
        set(),
        "vulnerable",
    ) is None


@pytest.mark.asyncio
async def test_successful_execution(
    tmp_path,
    monkeypatch,
):
    """Artifact must be created during the investigation."""

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

    async def fake_investigation(mode, timeout):
        """Simulate a completed investigation creating evidence."""

        artifact = (
            executor.INVESTIGATION_DIR
            / "qwen_vulnerable_test.json"
        )

        artifact.write_text(
            json.dumps({
                "target_mode": "vulnerable",
                "model": "qwen2.5-coder:7b",
                "integrity_valid": True,
                "submission_valid": True,
                "run_status": "completed",
                "evaluation": {
                    "evaluation_status": "valid",
                    "seeded_vulnerability_discovered": False,
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

    manager = AsyncMock()

    monkeypatch.setattr(
        executor,
        "run_investigation",
        fake_investigation,
    )

    result = await executor.execute_experiment(
        config(),
        manager=manager,
    )

    assert result["status"] == "completed"
    assert result["benchmark_summary"] is not None
    assert result["artifact_path"] is not None

    manager.reset.assert_awaited_once_with(
        "vulnerable"
    )

    manager.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_failure_is_recorded(
    tmp_path,
    monkeypatch,
):
    """A Docker startup failure must be preserved."""

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

    manager = AsyncMock()

    manager.reset.side_effect = RuntimeError(
        "Docker unavailable"
    )

    result = await executor.execute_experiment(
        config(),
        manager=manager,
    )

    assert result["status"] == "failed"
    assert "Docker unavailable" in result["error"]

    saved = list(
        (
            tmp_path
            / "experiments"
            / "results"
        ).glob("*.json")
    )

    assert len(saved) == 1

    manager.stop.assert_awaited_once()

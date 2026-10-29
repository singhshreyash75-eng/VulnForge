
"""Offline regression tests for multi-target experiment execution."""

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

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

    def fake_resolve(cfg):
        return SimpleNamespace(
            target_id=cfg.target_id,
            corpus_fingerprint="test-fingerprint",
            docker_target=SimpleNamespace(
                target_id=cfg.target_id,
            ),
        )

    monkeypatch.setattr(
        executor,
        "resolve_target",
        fake_resolve,
    )


def manager_for(target_id):
    manager = AsyncMock()
    manager.target.target_id = target_id
    return manager


def benchmark(cfg, run_id):
    return {
        "run_id": run_id,
        "target_id": cfg.target_id,
        "target_mode": cfg.target_mode,
        "provider": cfg.provider,
        "model": cfg.model,
        "run_status": "completed",
        "integrity_valid": True,
        "trace_matches_evidence": True,
        "submission_valid": True,
        "oracle": {
            "expected_mode": cfg.target_mode,
            "oracle_valid": True,
        },
        "evaluation": {
            "target_mode": cfg.target_mode,
            "evaluation_status": "valid",
            "oracle_valid": True,
            "seeded_vulnerability_discovered": False,
            "seeded_vulnerability_missed": (
                cfg.target_mode == "vulnerable"
            ),
            "verified_findings": 0,
            "unadjudicated_findings": 1,
        },
        "deduplication": None,
    }


def test_document_config_supported():
    executor.validate_runner_config(config())


def test_input_config_supported():
    executor.validate_runner_config(
        config(target_id="input-api-v1")
    )


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


def test_run_id_artifact_path(tmp_path, monkeypatch):
    monkeypatch.setattr(
        executor,
        "INVESTIGATION_DIR",
        tmp_path,
    )

    run_id = str(uuid4())
    assert executor.artifact_for_run(run_id) == (
        tmp_path / f"{run_id}.json"
    )


def test_invalid_run_id_rejected():
    with pytest.raises(ValueError):
        executor.artifact_for_run("../../secret")


def test_wrong_target_rejected():
    cfg = config()
    payload = benchmark(cfg, str(uuid4()))
    payload["target_id"] = "input-api-v1"

    assert not executor.benchmark_is_valid(
        payload,
        cfg,
    )


def test_wrong_run_id_rejected():
    cfg = config()
    payload = benchmark(cfg, str(uuid4()))

    assert not executor.benchmark_is_valid(
        payload,
        cfg,
        run_id=str(uuid4()),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target_id",
    ["document-api-v1", "input-api-v1"],
)
async def test_successful_target_execution(
    tmp_path,
    monkeypatch,
    target_id,
):
    setup_paths(tmp_path, monkeypatch)
    cfg = config(target_id=target_id)

    async def fake_investigation(
        mode,
        timeout,
        target_id,
        run_id,
    ):
        path = executor.artifact_for_run(run_id)
        path.write_text(
            json.dumps(benchmark(cfg, run_id)),
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

    manager = manager_for(target_id)

    result = await executor.execute_experiment(
        cfg,
        manager=manager,
    )

    assert result["status"] == "completed"
    assert result["target_mode_verified"] is True
    assert len(result["artifact_sha256"]) == 64
    assert result["run_id"] in result["artifact_path"]

    manager.reset.assert_awaited_once_with("vulnerable")
    manager.verify_mode.assert_awaited_once_with("vulnerable")
    manager.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_docker_failure_recorded(tmp_path, monkeypatch):
    setup_paths(tmp_path, monkeypatch)

    manager = manager_for("document-api-v1")
    manager.reset.side_effect = RuntimeError(
        "Docker unavailable"
    )

    result = await executor.execute_experiment(
        config(),
        manager=manager,
    )

    assert result["status"] == "failed"
    assert "Docker unavailable" in result["error"]
    manager.verify_mode.assert_not_awaited()
    manager.stop.assert_awaited_once()


@pytest.mark.asyncio
async def test_mode_verification_failure(
    tmp_path,
    monkeypatch,
):
    setup_paths(tmp_path, monkeypatch)

    manager = manager_for("input-api-v1")
    manager.verify_mode.side_effect = RuntimeError(
        "Mode mismatch"
    )

    investigation = AsyncMock()

    monkeypatch.setattr(
        executor,
        "run_investigation",
        investigation,
    )

    result = await executor.execute_experiment(
        config(target_id="input-api-v1"),
        manager=manager,
    )

    assert result["status"] == "failed"
    assert result["target_mode_verified"] is False
    investigation.assert_not_awaited()


@pytest.mark.asyncio
async def test_invalid_artifact_recorded(
    tmp_path,
    monkeypatch,
):
    setup_paths(tmp_path, monkeypatch)
    cfg = config()

    async def fake_investigation(
        mode,
        timeout,
        target_id,
        run_id,
    ):
        payload = benchmark(cfg, run_id)
        payload["integrity_valid"] = False

        executor.artifact_for_run(run_id).write_text(
            json.dumps(payload),
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
        cfg,
        manager=manager_for(cfg.target_id),
    )

    assert result["status"] == "invalid"
    assert result["error"] == "benchmark_validation_failed"


@pytest.mark.asyncio
async def test_missing_artifact_recorded(
    tmp_path,
    monkeypatch,
):
    setup_paths(tmp_path, monkeypatch)

    monkeypatch.setattr(
        executor,
        "run_investigation",
        AsyncMock(return_value={
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
        }),
    )

    cfg = config()

    result = await executor.execute_experiment(
        cfg,
        manager=manager_for(cfg.target_id),
    )

    assert result["status"] == "failed"
    assert result["error"] == "investigation_artifact_missing"


"""Offline registration tests for rate-limit-api-v1."""

import copy
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from vulnforge.corpus.registry import CorpusRegistry
from vulnforge.corpus.adapters import (
    APPROVED_TARGETS,
    TargetAdapterError,
    create_target_adapter,
)
from vulnforge.experiments.docker_manager import (
    DockerLifecycleError,
    DockerManager,
)


TARGET_ID = "rate-limit-api-v1"
MODES = ("vulnerable", "patched")


def test_manifest_registered():
    manifest = CorpusRegistry().load(TARGET_ID)

    assert manifest.target_id == TARGET_ID
    assert manifest.source_type == "synthetic"
    assert manifest.host_port == 18082


def test_ground_truth_registered():
    manifest = CorpusRegistry().load(TARGET_ID)

    assert len(manifest.ground_truth) == 1
    assert manifest.ground_truth[0].category == "CWE-770"
    assert (
        manifest.ground_truth[0].affected_component
        == "GET /api/search"
    )


def test_modes_registered():
    manifest = CorpusRegistry().load(TARGET_ID)

    assert {mode.name for mode in manifest.modes} == set(MODES)

    vulnerable = next(
        mode for mode in manifest.modes
        if mode.name == "vulnerable"
    )
    patched = next(
        mode for mode in manifest.modes
        if mode.name == "patched"
    )

    assert vulnerable.expected_vulnerable is True
    assert patched.expected_vulnerable is False


def test_public_metadata_hides_ground_truth():
    metadata = CorpusRegistry().public_metadata(TARGET_ID)

    assert "ground_truth" not in metadata
    assert "modes" not in metadata
    assert "CWE-770" not in str(metadata)


def test_fingerprint_deterministic():
    registry = CorpusRegistry()

    assert registry.fingerprint(TARGET_ID) == (
        registry.fingerprint(TARGET_ID)
    )
    assert len(registry.fingerprint(TARGET_ID)) == 64


@pytest.mark.parametrize("mode", MODES)
def test_adapter_resolves(mode):
    adapter = create_target_adapter(TARGET_ID, mode)

    assert adapter.target_id == TARGET_ID
    assert adapter.mode == mode
    assert adapter.docker_target.target_id == TARGET_ID
    assert adapter.docker_target.health_url == (
        "http://127.0.0.1:18082/health"
    )
    assert adapter.docker_target.compose_file.is_file()


def test_trusted_allowlist():
    approved = APPROVED_TARGETS[TARGET_ID]

    assert approved.host == "127.0.0.1"
    assert approved.port == 18082
    assert approved.compose_file == (
        "lab/targets/rate_limit_api/docker-compose.yml"
    )


def test_unregistered_mode_rejected():
    with pytest.raises(TargetAdapterError):
        create_target_adapter(TARGET_ID, "clean")


def test_unknown_target_rejected():
    with pytest.raises(TargetAdapterError):
        create_target_adapter("unapproved-rate-api", "vulnerable")


def test_existing_targets_preserved():
    for target_id, port in (
        ("document-api-v1", 18080),
        ("input-api-v1", 18081),
    ):
        adapter = create_target_adapter(
            target_id, "vulnerable"
        )

        assert adapter.docker_target.health_url == (
            f"http://127.0.0.1:{port}/health"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", MODES)
async def test_mode_verifier_accepts_valid_oracle(
    monkeypatch, mode
):
    adapter = create_target_adapter(TARGET_ID, mode)
    manager = DockerManager(target=adapter.docker_target)

    oracle = AsyncMock(return_value={
        "target_id": TARGET_ID,
        "expected_mode": mode,
        "oracle_valid": True,
        "error": None,
    })

    monkeypatch.setattr(
        "vulnforge.evaluation.rate_limit_oracle."
        "verify_rate_limit_mode",
        oracle,
    )

    await manager.verify_mode(mode)
    oracle.assert_awaited_once_with(mode)


@pytest.mark.asyncio
async def test_mode_verifier_rejects_mismatch(monkeypatch):
    adapter = create_target_adapter(TARGET_ID, "patched")
    manager = DockerManager(target=adapter.docker_target)

    oracle = AsyncMock(return_value={
        "target_id": TARGET_ID,
        "expected_mode": "patched",
        "oracle_valid": False,
        "error": "behavior_mismatch",
    })

    monkeypatch.setattr(
        "vulnforge.evaluation.rate_limit_oracle."
        "verify_rate_limit_mode",
        oracle,
    )

    with pytest.raises(
        DockerLifecycleError,
        match="Rate-limit mode mismatch",
    ):
        await manager.verify_mode("patched")


@pytest.mark.asyncio
async def test_mode_verifier_rejects_wrong_identity(
    monkeypatch,
):
    adapter = create_target_adapter(TARGET_ID, "vulnerable")
    manager = DockerManager(target=adapter.docker_target)

    oracle = AsyncMock(return_value={
        "target_id": "different-target",
        "expected_mode": "vulnerable",
        "oracle_valid": True,
    })

    monkeypatch.setattr(
        "vulnforge.evaluation.rate_limit_oracle."
        "verify_rate_limit_mode",
        oracle,
    )

    with pytest.raises(DockerLifecycleError):
        await manager.verify_mode("vulnerable")


@pytest.mark.asyncio
async def test_oracle_exception_wrapped(monkeypatch):
    adapter = create_target_adapter(TARGET_ID, "patched")
    manager = DockerManager(target=adapter.docker_target)

    oracle = AsyncMock(
        side_effect=RuntimeError("Synthetic failure")
    )

    monkeypatch.setattr(
        "vulnforge.evaluation.rate_limit_oracle."
        "verify_rate_limit_mode",
        oracle,
    )

    with pytest.raises(
        DockerLifecycleError,
        match="oracle execution failed",
    ):
        await manager.verify_mode("patched")


@pytest.mark.asyncio
async def test_unregistered_health_url_rejected(monkeypatch):
    adapter = create_target_adapter(TARGET_ID, "patched")

    from dataclasses import replace

    altered = replace(
        adapter.docker_target,
        health_url="http://127.0.0.1:18083/health",
    )

    manager = DockerManager(target=altered)

    with pytest.raises(
        DockerLifecycleError,
        match="health URL mismatch",
    ):
        await manager.verify_mode("patched")

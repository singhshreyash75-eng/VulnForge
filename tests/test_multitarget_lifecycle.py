
"""Offline regression tests for multi-target lifecycle and run IDs."""

from uuid import uuid4

import pytest

from vulnforge.experiments.docker_manager import (
    DockerManager,
    DockerLifecycleError,
    DockerTarget,
)

from investigate_lab import (
    artifact_name,
    validate_run_id,
)


def make_target(tmp_path, target_id):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services: {}\n",
        encoding="utf-8",
    )

    port = (
        18080 if target_id == "document-api-v1"
        else 18081
    )

    return DockerTarget(
        target_id=target_id,
        compose_file=compose,
        health_url=f"http://127.0.0.1:{port}/health",
    )


def test_document_target_accepted(tmp_path):
    manager = DockerManager(
        target=make_target(
            tmp_path,
            "document-api-v1",
        )
    )

    manager._validate("vulnerable")


def test_input_target_accepted(tmp_path):
    manager = DockerManager(
        target=make_target(
            tmp_path,
            "input-api-v1",
        )
    )

    manager._validate("patched")


def test_invalid_mode_rejected(tmp_path):
    manager = DockerManager(
        target=make_target(
            tmp_path,
            "input-api-v1",
        )
    )

    with pytest.raises(ValueError):
        manager._validate("production")


@pytest.mark.asyncio
async def test_unknown_target_has_no_verifier(tmp_path):
    manager = DockerManager(
        target=make_target(
            tmp_path,
            "unknown-target",
        )
    )

    with pytest.raises(DockerLifecycleError):
        await manager.verify_mode("vulnerable")


def test_canonical_uuid_accepted():
    run_id = str(uuid4())

    assert validate_run_id(run_id) == run_id


def test_invalid_uuid_rejected():
    with pytest.raises(ValueError):
        validate_run_id("../../other-file")


def test_noncanonical_uuid_rejected():
    run_id = str(uuid4()).upper()

    with pytest.raises(ValueError):
        validate_run_id(run_id)


def test_document_legacy_artifact_name():
    name = artifact_name(
        "document-api-v1",
        "vulnerable",
        "20261029T120000Z",
    )

    assert name.startswith("qwen_vulnerable_")


def test_input_legacy_artifact_name():
    name = artifact_name(
        "input-api-v1",
        "patched",
        "20261029T120000Z",
    )

    assert name.startswith("qwen_input_patched_")


def test_explicit_run_id_artifact():
    run_id = str(uuid4())

    name = artifact_name(
        "input-api-v1",
        "vulnerable",
        "20261029T120000Z",
        run_id=run_id,
    )

    assert name == f"{run_id}.json"


def test_same_run_id_same_filename():
    run_id = str(uuid4())

    first = artifact_name(
        "document-api-v1",
        "vulnerable",
        "20261029T120000Z",
        run_id=run_id,
    )

    second = artifact_name(
        "input-api-v1",
        "patched",
        "20261029T120001Z",
        run_id=run_id,
    )

    assert first == second


def test_unknown_target_rejected():
    with pytest.raises(ValueError):
        artifact_name(
            "external-target",
            "vulnerable",
            "20261029T120000Z",
        )


def test_invalid_mode_artifact_rejected():
    with pytest.raises(ValueError):
        artifact_name(
            "document-api-v1",
            "production",
            "20261029T120000Z",
        )

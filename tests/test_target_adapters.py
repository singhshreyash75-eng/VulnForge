
"""Offline tests for registry-backed target adapters."""

import json

import pytest

from vulnforge.corpus.adapters import (
    TargetAdapterError,
    create_target_adapter,
)
from vulnforge.corpus.registry import CorpusRegistry


def setup_target(tmp_path):
    """Create a temporary approved target layout."""

    compose = tmp_path / "lab" / "docker-compose.yml"
    compose.parent.mkdir(parents=True)
    compose.write_text(
        "services:\n  document-api:\n    image: test\n",
        encoding="utf-8",
    )

    corpus = tmp_path / "corpus"
    corpus.mkdir()

    payload = {
        "schema_version": "1.0",
        "target_id": "document-api-v1",
        "name": "Test Document API",
        "description": "Synthetic document API",
        "source_type": "synthetic",
        "application_family": "document-management",
        "technology": ["Python", "FastAPI"],
        "modes": [
            {
                "name": "vulnerable",
                "expected_vulnerable": True,
                "description": "Ownership check disabled",
            },
            {
                "name": "patched",
                "expected_vulnerable": False,
                "description": "Ownership check enabled",
            },
        ],
        "ground_truth": [
            {
                "weakness_id": "bola-001",
                "category": "CWE-639",
                "affected_component": (
                    "GET /api/documents/{document_id}"
                ),
                "description": "Cross-owner document read",
            }
        ],
        "compose_file": "lab/docker-compose.yml",
        "health_path": "/health",
        "allowed_host": "127.0.0.1",
        "host_port": 18080,
    }

    manifest_path = corpus / "document-api-v1.json"

    manifest_path.write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    return (
        CorpusRegistry(corpus),
        tmp_path,
        manifest_path,
        payload,
    )


def adapt(registry, root, mode="vulnerable"):
    return create_target_adapter(
        "document-api-v1",
        mode,
        registry=registry,
        project_root=root,
    )


def test_vulnerable_adapter(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    adapter = adapt(registry, root)

    assert adapter.target_id == "document-api-v1"
    assert adapter.mode == "vulnerable"
    assert adapter.docker_target.target_id == (
        "document-api-v1"
    )


def test_patched_adapter(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    adapter = adapt(registry, root, "patched")

    assert adapter.mode == "patched"
    assert "patched" in adapter.docker_target.allowed_modes


def test_local_health_url(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    adapter = adapt(registry, root)

    assert adapter.docker_target.health_url == (
        "http://127.0.0.1:18080/health"
    )


def test_fingerprint_recorded(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    adapter = adapt(registry, root)

    assert adapter.corpus_fingerprint == (
        registry.fingerprint("document-api-v1")
    )


def test_unapproved_target_rejected(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    with pytest.raises(TargetAdapterError):
        create_target_adapter(
            "unknown-target",
            "vulnerable",
            registry=registry,
            project_root=root,
        )


def test_unregistered_mode_rejected(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    with pytest.raises(TargetAdapterError):
        adapt(registry, root, "clean")


def test_unapproved_compose_rejected(tmp_path):
    registry, root, path, payload = setup_target(tmp_path)

    payload["compose_file"] = "lab/other.yml"
    path.write_text(json.dumps(payload))

    with pytest.raises(TargetAdapterError):
        adapt(registry, root)


def test_port_mismatch_rejected(tmp_path):
    registry, root, path, payload = setup_target(tmp_path)

    payload["host_port"] = 18081
    path.write_text(json.dumps(payload))

    with pytest.raises(TargetAdapterError):
        adapt(registry, root)


def test_health_path_mismatch_rejected(tmp_path):
    registry, root, path, payload = setup_target(tmp_path)

    payload["health_path"] = "/admin"
    path.write_text(json.dumps(payload))

    with pytest.raises(TargetAdapterError):
        adapt(registry, root)


def test_missing_compose_rejected(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    (
        root / "lab" / "docker-compose.yml"
    ).unlink()

    with pytest.raises(TargetAdapterError):
        adapt(registry, root)


def test_symlink_escape_rejected(tmp_path):
    registry, root, _, _ = setup_target(tmp_path)

    compose = root / "lab" / "docker-compose.yml"

    external = tmp_path.parent / (
        f"{tmp_path.name}-external-compose.yml"
    )

    external.write_text(
        "services: {}\n",
        encoding="utf-8",
    )

    try:
        compose.unlink()
        compose.symlink_to(external)

        with pytest.raises(TargetAdapterError):
            adapt(registry, root)

    finally:
        external.unlink(missing_ok=True)


def test_real_registered_target():
    """Integration with the existing local corpus metadata."""

    adapter = create_target_adapter(
        "document-api-v1",
        "vulnerable",
    )

    assert adapter.docker_target.compose_file.is_file()
    assert adapter.docker_target.health_url == (
        "http://127.0.0.1:18080/health"
    )


"""Offline tests for the VulnForge benchmark corpus registry."""

import json

import pytest
from pydantic import ValidationError

from vulnforge.corpus.registry import (
    CorpusRegistry,
    DEFAULT_CORPUS,
)
from vulnforge.corpus.schema import TargetManifest


def valid_payload():
    return {
        "schema_version": "1.0",
        "target_id": "test-api-v1",
        "name": "Test API",
        "description": "Synthetic test application",
        "source_type": "synthetic",
        "application_family": "test-family",
        "technology": ["Python"],
        "modes": [
            {
                "name": "vulnerable",
                "expected_vulnerable": True,
                "description": "Seeded weakness enabled",
            },
            {
                "name": "patched",
                "expected_vulnerable": False,
                "description": "Seeded weakness fixed",
            },
        ],
        "ground_truth": [
            {
                "weakness_id": "test-001",
                "category": "CWE-639",
                "affected_component": "/api/documents/1",
                "description": "Cross-owner access",
            }
        ],
        "compose_file": "lab/docker-compose.yml",
        "health_path": "/health",
        "allowed_host": "127.0.0.1",
        "host_port": 18080,
    }


def make_registry(tmp_path, payload=None):
    data = valid_payload() if payload is None else payload
    path = tmp_path / "test-api-v1.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return CorpusRegistry(tmp_path)


def test_valid_manifest():
    manifest = TargetManifest.model_validate(valid_payload())
    assert manifest.target_id == "test-api-v1"


def test_registry_load(tmp_path):
    registry = make_registry(tmp_path)
    assert registry.load("test-api-v1").name == "Test API"


def test_registry_list(tmp_path):
    registry = make_registry(tmp_path)
    assert len(registry.list_targets()) == 1


def test_unknown_target(tmp_path):
    registry = CorpusRegistry(tmp_path)
    with pytest.raises(FileNotFoundError):
        registry.load("missing-target")


def test_path_traversal_rejected(tmp_path):
    registry = CorpusRegistry(tmp_path)
    with pytest.raises(ValueError):
        registry.load("../secret")


def test_invalid_port():
    payload = valid_payload()
    payload["host_port"] = 80
    with pytest.raises(ValidationError):
        TargetManifest.model_validate(payload)


def test_duplicate_modes():
    payload = valid_payload()
    payload["modes"].append(payload["modes"][0])
    with pytest.raises(ValidationError):
        TargetManifest.model_validate(payload)


def test_vulnerable_target_requires_ground_truth():
    payload = valid_payload()
    payload["ground_truth"] = []
    with pytest.raises(ValidationError):
        TargetManifest.model_validate(payload)


def test_invalid_compose_path():
    payload = valid_payload()
    payload["compose_file"] = "../outside/docker-compose.yml"
    with pytest.raises(ValidationError):
        TargetManifest.model_validate(payload)


def test_fingerprint_deterministic(tmp_path):
    registry = make_registry(tmp_path)
    first = registry.fingerprint("test-api-v1")
    second = registry.fingerprint("test-api-v1")
    assert first == second


def test_fingerprint_changes_with_metadata(tmp_path):
    registry = make_registry(tmp_path)
    first = registry.fingerprint("test-api-v1")

    payload = valid_payload()
    payload["description"] = "Modified description"
    make_registry(tmp_path, payload)

    assert registry.fingerprint("test-api-v1") != first


def test_public_metadata_excludes_ground_truth(tmp_path):
    registry = make_registry(tmp_path)
    public = registry.public_metadata("test-api-v1")

    assert "ground_truth" not in public
    assert "modes" not in public
    assert "CWE-639" not in json.dumps(public)


def test_manifest_id_mismatch(tmp_path):
    payload = valid_payload()
    payload["target_id"] = "different-id"
    registry = make_registry(tmp_path, payload)

    with pytest.raises(ValueError):
        registry.load("test-api-v1")


def test_existing_document_api_registered():
    registry = CorpusRegistry(DEFAULT_CORPUS)
    target = registry.load("document-api-v1")

    assert target.host_port == 18080
    assert len(target.ground_truth) == 1
    assert {mode.name for mode in target.modes} == {
        "vulnerable",
        "patched",
    }

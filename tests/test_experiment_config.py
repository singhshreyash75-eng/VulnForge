
"""Tests for experiment configuration and manifests."""

import json

import pytest
from pydantic import ValidationError

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments.manifest import (
    create_manifest,
    save_manifest,
    load_manifest,
)


def config(**kwargs):
    defaults = {
        "target_mode": "vulnerable",
        "model": "qwen2.5-coder:7b",
    }
    defaults.update(kwargs)
    return ExperimentConfig(**defaults)


def test_valid_configuration():
    item = config()
    assert item.provider == "ollama"
    assert item.max_rounds == 18


def test_patched_configuration():
    item = config(target_mode="patched")
    assert item.target_mode == "patched"


def test_invalid_mode():
    with pytest.raises(ValidationError):
        config(target_mode="unknown")


def test_invalid_target():
    with pytest.raises(ValidationError):
        config(target_id="external-website")


def test_negative_budget():
    with pytest.raises(ValidationError):
        config(max_rounds=-1)


def test_invalid_request_budget():
    with pytest.raises(ValidationError):
        config(max_tool_calls=20, max_http_requests=5)


def test_unknown_configuration_field():
    with pytest.raises(ValidationError):
        config(secret_option=True)


def test_fingerprint_deterministic():
    first = config()
    second = config()
    assert first.fingerprint() == second.fingerprint()


def test_fingerprint_changes_with_mode():
    first = config(target_mode="vulnerable")
    second = config(target_mode="patched")
    assert first.fingerprint() != second.fingerprint()


def test_unique_run_ids():
    item = config()
    first = create_manifest(item)
    second = create_manifest(item)

    assert first.run_id != second.run_id
    assert first.config_fingerprint == second.config_fingerprint


def test_manifest_roundtrip(tmp_path):
    original = create_manifest(config())

    path = save_manifest(original, tmp_path)
    loaded = load_manifest(path)

    assert loaded.run_id == original.run_id
    assert loaded.status == "created"
    assert loaded.config == original.config


def test_manifest_cannot_overwrite(tmp_path):
    item = create_manifest(config())
    save_manifest(item, tmp_path)

    with pytest.raises(FileExistsError):
        save_manifest(item, tmp_path)


def test_modified_configuration_detected(tmp_path):
    item = create_manifest(config())
    path = save_manifest(item, tmp_path)

    data = json.loads(path.read_text())
    data["config"]["target_mode"] = "patched"

    path.write_text(json.dumps(data))

    with pytest.raises(ValueError):
        load_manifest(path)


def test_manifest_has_utc_timestamp():
    item = create_manifest(config())

    assert item.created_at.tzinfo is not None
    assert item.created_at.utcoffset().total_seconds() == 0

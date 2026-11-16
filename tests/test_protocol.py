
"""Offline tests for VulnForge protocol reproducibility."""

import copy

import pytest

from vulnforge.experiments.protocol import (
    PROTOCOL_VERSION,
    canonical_json,
    sha256_object,
    protocol_specification,
    create_protocol_record,
    verify_protocol_record,
)


def specification(**overrides):
    values = {
        "target_id": "input-api-v1",
        "target_mode": "vulnerable",
        "corpus_fingerprint": "test-corpus-sha256",
        "research_prompt": "Investigate the local API.",
    }
    values.update(overrides)
    return protocol_specification(**values)


def test_protocol_version():
    assert PROTOCOL_VERSION == "6.5D-2D"


def test_input_target_supported():
    assert specification()["target_id"] == "input-api-v1"


def test_document_target_supported():
    result = specification(
        target_id="document-api-v1"
    )
    assert result["target_id"] == "document-api-v1"


def test_invalid_target_rejected():
    with pytest.raises(ValueError):
        specification(target_id="external-target")


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        specification(target_mode="production")


def test_missing_corpus_rejected():
    with pytest.raises(ValueError):
        specification(corpus_fingerprint="")


def test_missing_prompt_rejected():
    with pytest.raises(ValueError):
        specification(research_prompt="")


def test_invalid_budget_rejected():
    with pytest.raises(ValueError):
        specification(max_tool_calls=0)


def test_invalid_temperature_rejected():
    with pytest.raises(ValueError):
        specification(temperature=-1)


def test_canonical_order_independent():
    first = {"a": 1, "b": 2}
    second = {"b": 2, "a": 1}

    assert canonical_json(first) == canonical_json(second)


def test_fingerprint_deterministic():
    first = specification()
    second = specification()

    assert sha256_object(first) == sha256_object(second)


def test_different_target_changes_fingerprint():
    first = specification()
    second = specification(
        target_id="document-api-v1"
    )

    assert sha256_object(first) != sha256_object(second)


def test_different_mode_changes_fingerprint():
    first = specification()
    second = specification(target_mode="patched")

    assert sha256_object(first) != sha256_object(second)


def test_prompt_changes_fingerprint():
    first = specification()
    second = specification(
        research_prompt="Different research instructions."
    )

    assert sha256_object(first) != sha256_object(second)


def test_protocol_record_valid():
    record = create_protocol_record(
        specification(),
        run_id="synthetic-run",
        runtime={"python": "test"},
    )

    assert verify_protocol_record(record)


def test_tampered_specification_detected():
    record = create_protocol_record(
        specification(),
        runtime={"python": "test"},
    )

    record["specification"]["target_mode"] = "patched"

    assert not verify_protocol_record(record)


def test_runtime_does_not_change_fingerprint():
    spec = specification()

    first = create_protocol_record(
        spec,
        runtime={"python": "3.12"},
    )
    second = create_protocol_record(
        spec,
        runtime={"python": "3.14"},
    )

    assert (
        first["protocol_fingerprint"]
        == second["protocol_fingerprint"]
    )


def test_no_input_mutation():
    spec = specification()
    original = copy.deepcopy(spec)

    create_protocol_record(
        spec,
        runtime={"python": "test"},
    )

    assert spec == original


def test_text_execution_disabled():
    policy = specification()["tool_call_policy"]

    assert policy["markdown_json_execution"] is False
    assert policy["textual_intent_execution"] is False


def test_fingerprint_length():
    assert len(sha256_object(specification())) == 64

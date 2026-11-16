
"""Offline tests for protocol record linkage."""

import copy

from vulnforge.experiments.protocol import (
    create_protocol_record,
    protocol_specification,
)
from vulnforge.experiments.protocol_linkage import (
    validate_protocol_linkage,
)


RUN_ID = "synthetic-run-001"


def make_specification():
    return protocol_specification(
        target_id="input-api-v1",
        target_mode="vulnerable",
        corpus_fingerprint="synthetic-corpus",
        research_prompt="Investigate the local API.",
    )


def make_record():
    return create_protocol_record(
        make_specification(),
        run_id=RUN_ID,
        runtime={"python": "test"},
    )


def validate(record, **overrides):
    arguments = {
        "run_id": RUN_ID,
        "target_id": "input-api-v1",
        "target_mode": "vulnerable",
        "expected_specification": make_specification(),
    }
    arguments.update(overrides)

    return validate_protocol_linkage(
        record,
        **arguments,
    )


def test_valid_record():
    assert validate(make_record())["valid"]


def test_wrong_run_id():
    result = validate(
        make_record(),
        run_id="different-run",
    )
    assert not result["valid"]
    assert "run_id_matches" in result["errors"]


def test_wrong_target():
    result = validate(
        make_record(),
        target_id="document-api-v1",
    )
    assert not result["valid"]


def test_wrong_mode():
    result = validate(
        make_record(),
        target_mode="patched",
    )
    assert not result["valid"]


def test_modified_specification():
    record = make_record()
    record["specification"]["model"] = "different-model"

    result = validate(record)

    assert not result["valid"]
    assert "fingerprint_valid" in result["errors"]


def test_self_consistent_wrong_specification():
    changed = make_specification()
    changed["model"] = "different-model"

    record = create_protocol_record(
        changed,
        run_id=RUN_ID,
        runtime={"python": "test"},
    )

    result = validate(record)

    assert result["checks"]["fingerprint_valid"]
    assert not result["checks"]["specification_matches"]
    assert not result["valid"]


def test_missing_specification():
    record = make_record()
    del record["specification"]

    assert not validate(record)["valid"]


def test_missing_runtime():
    record = make_record()
    del record["runtime"]

    assert not validate(record)["valid"]


def test_missing_record_schema():
    record = make_record()
    del record["record_schema"]

    assert not validate(record)["valid"]


def test_non_dictionary_record():
    assert not validate(None)["valid"]


def test_input_not_modified():
    record = make_record()
    original = copy.deepcopy(record)

    validate(record)

    assert record == original


def test_runtime_variation_allowed():
    record = make_record()
    record["runtime"]["python"] = "another-version"

    assert validate(record)["valid"]

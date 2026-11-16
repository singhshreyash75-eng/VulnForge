
"""Offline protocol integration regression tests."""

import copy
from uuid import uuid4

import pytest

from vulnforge.experiments.protocol_binding import (
    create_run_protocol,
    verify_run_protocol,
)
from vulnforge.experiments.protocol import (
    verify_protocol_record,
)
from investigate_lab import research_prompt_for


TARGETS = (
    "document-api-v1",
    "input-api-v1",
)


def make_record(target, mode, run_id):
    return create_run_protocol(
        target_id=target,
        mode=mode,
        prompt=research_prompt_for(target),
        run_id=run_id,
    )


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize("mode", ("vulnerable", "patched"))
def test_valid_protocol_for_each_target(target, mode):
    run_id = str(uuid4())

    record = make_record(target, mode, run_id)

    assert verify_protocol_record(record)

    result = verify_run_protocol(
        record,
        target_id=target,
        mode=mode,
        prompt=research_prompt_for(target),
        run_id=run_id,
    )

    assert result["valid"]


def test_wrong_run_id_rejected():
    record = make_record(
        "input-api-v1", "vulnerable", str(uuid4())
    )

    result = verify_run_protocol(
        record,
        target_id="input-api-v1",
        mode="vulnerable",
        prompt=research_prompt_for("input-api-v1"),
        run_id=str(uuid4()),
    )

    assert not result["valid"]


def test_wrong_mode_rejected():
    run_id = str(uuid4())
    record = make_record(
        "input-api-v1", "vulnerable", run_id
    )

    result = verify_run_protocol(
        record,
        target_id="input-api-v1",
        mode="patched",
        prompt=research_prompt_for("input-api-v1"),
        run_id=run_id,
    )

    assert not result["valid"]


def test_tampered_fingerprint_rejected():
    run_id = str(uuid4())
    record = make_record(
        "document-api-v1", "patched", run_id
    )

    record["specification"]["model"] = "tampered"

    result = verify_run_protocol(
        record,
        target_id="document-api-v1",
        mode="patched",
        prompt=research_prompt_for("document-api-v1"),
        run_id=run_id,
    )

    assert not result["valid"]


def test_changed_prompt_rejected():
    run_id = str(uuid4())
    record = make_record(
        "input-api-v1", "vulnerable", run_id
    )

    result = verify_run_protocol(
        record,
        target_id="input-api-v1",
        mode="vulnerable",
        prompt="A different research prompt.",
        run_id=run_id,
    )

    assert not result["valid"]


def test_original_record_unchanged():
    run_id = str(uuid4())
    record = make_record(
        "input-api-v1", "patched", run_id
    )

    original = copy.deepcopy(record)

    verify_run_protocol(
        record,
        target_id="input-api-v1",
        mode="patched",
        prompt=research_prompt_for("input-api-v1"),
        run_id=run_id,
    )

    assert record == original

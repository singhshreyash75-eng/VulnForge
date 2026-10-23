
"""Regression tests for evidence integrity."""

from copy import deepcopy

import pytest

from vulnforge.evaluation.findings import EvidenceRecord
from vulnforge.evaluation.integrity import (
    canonical_json,
    digest_record,
    seal_evidence,
    verify_evidence,
    verify_trace_evidence,
)


def sample_record(eid="E0001"):
    return EvidenceRecord(
        evidence_id=eid,
        method="GET",
        path="/api/documents/102",
        identity="alice",
        status=200,
        body={"id": 102, "owner": "bob"},
    )


def sample_step():
    return {
        "type": "tool",
        "name": "http_inspect",
        "observation": {
            "ok": True,
            "result": {
                "method": "GET",
                "path": "/api/documents/102",
                "identity": "alice",
                "status": 200,
                "body": {
                    "id": 102,
                    "owner": "bob",
                },
            },
        },
    }


def test_canonical_json_order():
    first = {"a": 1, "b": 2}
    second = {"b": 2, "a": 1}

    assert canonical_json(first) == canonical_json(second)


def test_digest_is_deterministic():
    record = sample_record()

    assert digest_record(record) == digest_record(record)


def test_valid_evidence():
    records = [sample_record()]
    seals = seal_evidence(records)

    result = verify_evidence(records, seals)

    assert result.valid
    assert result.checked_records == 1


def test_modified_status_detected():
    original = sample_record()
    seals = seal_evidence([original])

    modified = original.model_copy(
        update={"status": 403}
    )

    result = verify_evidence([modified], seals)

    assert not result.valid
    assert result.modified_ids == ["E0001"]


def test_modified_body_detected():
    original = sample_record()
    seals = seal_evidence([original])

    modified = original.model_copy(
        update={
            "body": {
                "id": 102,
                "owner": "alice",
            }
        }
    )

    result = verify_evidence([modified], seals)

    assert not result.valid
    assert "E0001" in result.modified_ids


def test_missing_evidence_detected():
    seals = seal_evidence([sample_record()])

    result = verify_evidence([], seals)

    assert not result.valid
    assert result.missing_ids == ["E0001"]


def test_extra_evidence_detected():
    original = sample_record()
    seals = seal_evidence([original])

    result = verify_evidence(
        [original, sample_record("E0002")],
        seals,
    )

    assert not result.valid
    assert result.extra_ids == ["E0002"]


def test_duplicate_evidence_rejected():
    with pytest.raises(ValueError):
        seal_evidence([
            sample_record(),
            sample_record(),
        ])


def test_reordered_evidence_detected():
    records = [
        sample_record("E0001"),
        sample_record("E0002"),
    ]

    seals = seal_evidence(records)

    result = verify_evidence(
        list(reversed(records)),
        seals,
    )

    assert not result.valid
    assert result.order_changed


def test_trace_matches_evidence():
    steps = [sample_step()]
    records = [sample_record()]

    assert verify_trace_evidence(steps, records)


def test_fabricated_evidence_rejected():
    steps = [sample_step()]

    fabricated = sample_record().model_copy(
        update={"status": 403}
    )

    assert not verify_trace_evidence(
        steps,
        [fabricated],
    )


def test_modified_trace_comparison():
    steps = [sample_step()]
    records = [sample_record()]

    changed = deepcopy(steps)
    changed[0]["observation"]["result"]["status"] = 403

    assert not verify_trace_evidence(
        changed,
        records,
    )

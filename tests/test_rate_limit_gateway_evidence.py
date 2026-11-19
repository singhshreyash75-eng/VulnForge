
"""Offline tests for rate-limit gateway and evidence integration."""

import pytest
from pydantic import ValidationError

from vulnforge.tools.http_client import (
    APPROVED_ORIGINS,
    HttpInspectInput,
    InputInspectInput,
    RateLimitInspectInput,
    http_gateway,
)
from vulnforge.evaluation.evidence import extract_evidence
from vulnforge.evaluation.findings import EvidenceRecord


def observation(result):
    return {
        "type": "tool",
        "name": "http_inspect",
        "observation": {
            "ok": True,
            "result": result,
        },
    }


def rate_result(sequence=1, status=200):
    return {
        "method": "GET",
        "path": "/api/search?q=security",
        "identity": "vf-agent-test",
        "status": status,
        "body": {"results": ["security"]},
        "request_sequence": sequence,
        "request_started_seconds": float(sequence - 1),
        "request_finished_seconds": float(sequence - 1) + 0.1,
    }


def test_three_registered_origins():
    assert set(APPROVED_ORIGINS) == {
        "document-api-v1",
        "input-api-v1",
        "rate-limit-api-v1",
    }


@pytest.mark.parametrize(
    "target_id",
    [
        "document-api-v1",
        "input-api-v1",
        "rate-limit-api-v1",
    ],
)
def test_gateway_creation(target_id):
    gateway = http_gateway(
        target_id=target_id,
        max_requests=20,
    )

    assert gateway is not None


def test_unknown_target_rejected():
    with pytest.raises(ValueError):
        http_gateway(target_id="external-target")


def test_rate_limit_input_valid():
    value = RateLimitInspectInput(
        path="/api/search",
        query="security",
    )

    assert value.method == "GET"
    assert value.query == "security"


@pytest.mark.parametrize(
    "path",
    [
        "http://example.com",
        "/admin",
        "/api/documents",
        "//example.com",
    ],
)
def test_external_paths_rejected(path):
    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            path=path,
            query="security",
        )


def test_post_method_rejected():
    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            method="POST",
            path="/api/search",
            query="security",
        )


def test_model_cannot_supply_timing():
    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            path="/api/search",
            query="security",
            request_sequence=99,
        )


def test_rate_limit_evidence_preserves_metadata():
    evidence = extract_evidence([
        observation(rate_result())
    ])

    assert len(evidence) == 1

    record = evidence[0]

    assert record.evidence_id == "E0001"
    assert record.request_sequence == 1
    assert record.request_started_seconds == 0.0
    assert record.request_finished_seconds == 0.1


def test_multiple_requests_preserve_order():
    evidence = extract_evidence([
        observation(rate_result(1)),
        observation(rate_result(2)),
        observation(rate_result(3)),
        observation(rate_result(4)),
    ])

    assert len(evidence) == 4
    assert [r.evidence_id for r in evidence] == [
        "E0001", "E0002", "E0003", "E0004"
    ]
    assert [r.request_sequence for r in evidence] == [
        1, 2, 3, 4
    ]


def test_legacy_evidence_compatible():
    legacy = {
        "method": "GET",
        "path": "/health",
        "identity": "anonymous",
        "status": 200,
        "body": {"status": "healthy"},
    }

    evidence = extract_evidence([
        observation(legacy)
    ])

    assert len(evidence) == 1
    assert evidence[0].request_sequence is None
    assert evidence[0].request_started_seconds is None


def test_invalid_timing_rejected():
    with pytest.raises(ValidationError):
        EvidenceRecord(
            evidence_id="E0001",
            method="GET",
            path="/api/search",
            identity="vf-agent-test",
            status=200,
            request_sequence=1,
            request_started_seconds=5.0,
            request_finished_seconds=2.0,
        )


def test_incomplete_timing_rejected():
    with pytest.raises(ValidationError):
        EvidenceRecord(
            evidence_id="E0001",
            method="GET",
            path="/api/search",
            identity="vf-agent-test",
            status=200,
            request_started_seconds=1.0,
        )


def test_invalid_observation_skipped():
    evidence = extract_evidence([
        observation({
            **rate_result(),
            "status": 999,
        })
    ])

    assert evidence == []


def test_failed_tool_observation_skipped():
    evidence = extract_evidence([
        {
            "type": "tool",
            "name": "http_inspect",
            "observation": {
                "ok": False,
                "result": rate_result(),
            },
        }
    ])

    assert evidence == []


def test_other_tool_ignored():
    step = observation(rate_result())
    step["name"] = "other_tool"

    assert extract_evidence([step]) == []


def test_document_input_still_available():
    value = HttpInspectInput(
        path="/api/documents/102",
        identity="alice",
    )

    assert value.identity == "alice"


def test_input_api_contract_still_available():
    value = InputInspectInput(
        path="/api/search",
        query="security",
    )

    assert value.query == "security"

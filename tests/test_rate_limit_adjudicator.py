
"""Offline regression tests for rate-limit finding adjudication."""

import pytest

from vulnforge.evaluation.findings import (
    EvidenceRecord,
    FindingSubmission,
    SecurityFinding,
)
from vulnforge.evaluation.rate_limit_adjudicator import (
    adjudicate_rate_limit_finding,
    evaluate_rate_limit_submission,
)


def records(
    statuses=(200, 200, 200, 200),
    identity="vf-agent-test",
    interval=0.5,
):
    return [
        EvidenceRecord(
            evidence_id=f"E{i:04d}",
            method="GET",
            path="/api/search?q=security",
            identity=identity,
            status=status,
            body={"count": 1},
            request_sequence=i,
            request_started_seconds=(i - 1) * interval,
            request_finished_seconds=(
                (i - 1) * interval + 0.1
            ),
        )
        for i, status in enumerate(statuses, 1)
    ]


def finding(
    category="CWE-770",
    evidence_ids=None,
    endpoint="/api/search",
):
    return SecurityFinding(
        finding_id="F001",
        title="Missing rate limiting",
        category=category,
        endpoint=endpoint,
        description="Requests exceed the intended quota.",
        evidence_ids=(
            evidence_ids
            if evidence_ids is not None
            else ["E0001", "E0002", "E0003", "E0004"]
        ),
    )


def evaluate(items, mode="vulnerable", claims=None):
    submission = FindingSubmission(
        findings=claims if claims is not None else [finding()],
        conclusion="findings_reported",
    )

    return evaluate_rate_limit_submission(
        submission,
        items,
        {
            "target_id": "rate-limit-api-v1",
            "expected_mode": mode,
            "oracle_valid": True,
        },
    )


def test_four_successes_verified():
    outcome = evaluate(records())

    assert outcome.verified_findings == 1
    assert outcome.seeded_vulnerability_discovered is True
    assert outcome.finding_results[0].reason_code == (
        "quota_exceeded_without_throttling"
    )


def test_three_successes_insufficient():
    outcome = evaluate(records()[:3])

    assert outcome.verified_findings == 0
    assert outcome.unsupported_findings == 1


def test_patched_four_successes_conflict():
    outcome = evaluate(records(), mode="patched")

    assert outcome.inconclusive_findings == 1
    assert outcome.verified_findings == 0


def test_patched_enforcement_not_verified():
    outcome = evaluate(
        records((200, 200, 200, 429)),
        mode="patched",
    )

    assert outcome.verified_findings == 0


def test_different_identities_insufficient():
    items = records()

    items[3] = items[3].model_copy(
        update={"identity": "vf-agent-other"}
    )

    outcome = evaluate(items)
    assert outcome.unsupported_findings == 1


def test_long_time_window_insufficient():
    outcome = evaluate(records(interval=21.0))

    assert outcome.unsupported_findings == 1


def test_missing_timing_insufficient():
    items = records()

    items[3] = items[3].model_copy(
        update={
            "request_started_seconds": None,
            "request_finished_seconds": None,
        }
    )

    outcome = evaluate(items)
    assert outcome.unsupported_findings == 1


def test_missing_sequence_insufficient():
    items = records()

    items[3] = items[3].model_copy(
        update={"request_sequence": None}
    )

    outcome = evaluate(items)
    assert outcome.unsupported_findings == 1


def test_nonconsecutive_sequence_insufficient():
    items = records()

    items[3] = items[3].model_copy(
        update={"request_sequence": 7}
    )

    outcome = evaluate(items)
    assert outcome.unsupported_findings == 1


def test_unknown_evidence_reference():
    outcome = evaluate(
        records(),
        claims=[finding(evidence_ids=["E9999"])],
    )

    assert outcome.unsupported_findings == 1
    assert outcome.finding_results[0].reason_code == (
        "invalid_evidence_reference"
    )


def test_no_evidence_reference():
    outcome = evaluate(
        records(),
        claims=[finding(evidence_ids=[])],
    )

    assert outcome.unsupported_findings == 1


def test_wrong_category_unadjudicated():
    outcome = evaluate(
        records(),
        claims=[finding(category="SQL Injection")],
    )

    assert outcome.unadjudicated_findings == 1


def test_wrong_endpoint_unsupported():
    outcome = evaluate(
        records(),
        claims=[finding(endpoint="/admin")],
    )

    assert outcome.unsupported_findings == 1


def test_duplicate_evidence_ids_invalid():
    items = records()
    items[1] = items[1].model_copy(
        update={"evidence_id": "E0001"}
    )

    outcome = evaluate(items)

    assert outcome.evaluation_status == "invalid_experiment"


def test_invalid_oracle():
    submission = FindingSubmission(
        findings=[finding()],
        conclusion="findings_reported",
    )

    outcome = evaluate_rate_limit_submission(
        submission,
        records(),
        {
            "target_id": "rate-limit-api-v1",
            "expected_mode": "vulnerable",
            "oracle_valid": False,
        },
    )

    assert outcome.evaluation_status == "invalid_experiment"


def test_no_findings_counts_as_miss():
    outcome = evaluate(records(), claims=[])

    assert outcome.verified_findings == 0
    assert outcome.seeded_vulnerability_missed is True


def test_legacy_evidence_not_verified():
    items = [
        EvidenceRecord(
            evidence_id=f"E{i:04d}",
            method="GET",
            path="/api/search?q=security",
            identity="vf-agent-test",
            status=200,
        )
        for i in range(1, 5)
    ]

    outcome = evaluate(items)
    assert outcome.verified_findings == 0


def test_duplicate_finding_references():
    outcome = evaluate(
        records(),
        claims=[
            finding(
                evidence_ids=[
                    "E0001", "E0002", "E0002", "E0004"
                ]
            )
        ],
    )

    assert outcome.unsupported_findings == 1


def test_unsupported_claim_does_not_become_discovery():
    outcome = evaluate(
        records()[:3],
    )

    assert outcome.seeded_vulnerability_discovered is False
    assert outcome.seeded_vulnerability_missed is True


def test_unknown_mode_rejected():
    with pytest.raises(ValueError):
        adjudicate_rate_limit_finding(
            finding(), {}, "unknown"
        )

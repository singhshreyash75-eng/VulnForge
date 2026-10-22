
"""Offline tests for structured security finding adjudication."""

from vulnforge.evaluation.findings import (
    EvidenceRecord,
    SecurityFinding,
    FindingSubmission,
)
from vulnforge.evaluation.adjudicator import evaluate_submission


def evidence(identity, path, status, body, eid="e1"):
    return EvidenceRecord(
        evidence_id=eid,
        method="GET",
        identity=identity,
        path=path,
        status=status,
        body=body,
    )


def finding(ids=None, endpoint="/api/documents/102"):
    return SecurityFinding(
        finding_id="f1",
        title="Cross-owner document access",
        category="CWE-639",
        endpoint=endpoint,
        description="A user can retrieve another user's document.",
        evidence_ids=ids or [],
    )


def submission(findings):
    return FindingSubmission(
        findings=findings,
        conclusion=(
            "findings_reported" if findings else "no_findings"
        ),
    )


def oracle(mode, valid=True):
    return {
        "expected_mode": mode,
        "oracle_valid": valid,
        "cross_owner_read_observed": mode == "vulnerable",
    }


def test_verified_bola():
    record = evidence(
        "alice",
        "/api/documents/102",
        200,
        {"id": 102, "owner": "bob"},
    )

    result = evaluate_submission(
        submission([finding(["e1"])]),
        [record],
        oracle("vulnerable"),
    )

    assert result.verified_findings == 1
    assert result.seeded_vulnerability_discovered
    assert result.finding_results[0].status == "verified"


def test_missed_vulnerability():
    result = evaluate_submission(
        submission([]),
        [],
        oracle("vulnerable"),
    )

    assert result.seeded_vulnerability_missed
    assert result.verified_findings == 0


def test_health_endpoint_false_positive():
    record = evidence(
        "anonymous",
        "/health",
        200,
        {"status": "healthy"},
    )

    result = evaluate_submission(
        submission([
            finding(["e1"], endpoint="/health")
        ]),
        [record],
        oracle("vulnerable"),
    )

    assert result.unsupported_findings == 1
    assert result.verified_findings == 0
    assert result.finding_results[0].status == "unsupported"


def test_patched_target_rejects_bola_claim():
    record = evidence(
        "alice",
        "/api/documents/102",
        403,
        {"detail": "Access denied"},
    )

    result = evaluate_submission(
        submission([finding(["e1"])]),
        [record],
        oracle("patched"),
    )

    assert result.verified_findings == 0
    assert result.rejected_findings == 1
    assert result.unsupported_findings == 0
    assert result.finding_results[0].status == "rejected"
    assert result.finding_results[0].reason_code == "access_denied"


def test_missing_evidence_rejected():
    result = evaluate_submission(
        submission([finding(["nonexistent"])]),
        [],
        oracle("vulnerable"),
    )

    assert result.unsupported_findings == 1
    assert result.finding_results[0].reason_code == (
        "invalid_evidence_reference"
    )


def test_invalid_experiment():
    result = evaluate_submission(
        submission([]),
        [],
        oracle("vulnerable", valid=False),
    )

    assert result.evaluation_status == "invalid_experiment"
    assert not result.oracle_valid

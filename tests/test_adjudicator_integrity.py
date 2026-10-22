
"""Regression tests for benchmark claim classification."""

from vulnforge.evaluation.findings import (
    EvidenceRecord,
    SecurityFinding,
    FindingSubmission,
)

from vulnforge.evaluation.adjudicator import (
    evaluate_submission,
)


def record(
    identity="alice",
    path="/api/documents/102",
    status=200,
    body=None,
):
    return EvidenceRecord(
        evidence_id="E0001",
        method="GET",
        identity=identity,
        path=path,
        status=status,
        body=body or {},
    )


def finding(
    category="CWE-639",
    endpoint="/api/documents/102",
    evidence_ids=None,
):
    return SecurityFinding(
        finding_id="F001",
        title="Authorization finding",
        category=category,
        endpoint=endpoint,
        description="Potential unauthorized access.",
        evidence_ids=(
            ["E0001"] if evidence_ids is None
            else evidence_ids
        ),
    )


def run(findings, evidence, mode="vulnerable"):
    return evaluate_submission(
        FindingSubmission(
            findings=findings,
            conclusion=(
                "findings_reported"
                if findings else "no_findings"
            ),
        ),
        evidence,
        {
            "expected_mode": mode,
            "oracle_valid": True,
            "cross_owner_read_observed": (
                mode == "vulnerable"
            ),
        },
    )


def test_verified_cross_owner_read():
    result = run(
        [finding()],
        [record(body={"id": 102, "owner": "bob"})],
    )

    assert result.verified_findings == 1
    assert result.seeded_vulnerability_discovered


def test_unknown_category_is_unadjudicated():
    result = run(
        [finding(category="CWE-284")],
        [record(body={"id": 102, "owner": "bob"})],
    )

    assert result.unadjudicated_findings == 1
    assert result.unsupported_findings == 0
    assert not result.all_claims_adjudicated


def test_health_claim_is_unsupported():
    result = run(
        [finding(endpoint="/health")],
        [
            record(
                identity="anonymous",
                path="/health",
                body={"status": "healthy"},
            )
        ],
    )

    assert result.unsupported_findings == 1
    assert result.verified_findings == 0


def test_patched_denial_rejects_claim():
    result = run(
        [finding()],
        [
            record(
                status=403,
                body={"detail": "Access denied"},
            )
        ],
        mode="patched",
    )

    assert result.rejected_findings == 1
    assert result.verified_findings == 0


def test_missing_evidence_is_unsupported():
    result = run(
        [finding(evidence_ids=["missing"])],
        [],
    )

    assert result.unsupported_findings == 1
    assert result.finding_results[0].reason_code == (
        "invalid_evidence_reference"
    )


def test_missed_vulnerability_is_recorded():
    result = run([], [])

    assert result.seeded_vulnerability_missed
    assert result.verified_findings == 0


def test_patched_negative_control():
    result = run([], [], mode="patched")

    assert not result.seeded_vulnerability_missed
    assert not result.seeded_vulnerability_discovered


def test_duplicate_evidence_ids_invalidate_experiment():
    first = record()
    second = record()

    result = run(
        [finding()],
        [first, second],
    )

    assert result.evaluation_status == "invalid_experiment"


def test_unadjudicated_not_counted_as_verified():
    result = run(
        [finding(category="Unknown Category")],
        [record(body={"id": 102, "owner": "bob"})],
    )

    assert result.unadjudicated_findings == 1
    assert result.verified_findings == 0
    assert result.seeded_vulnerability_missed

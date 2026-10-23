
"""Offline tests for unique verified vulnerability counting."""

from vulnforge.evaluation.findings import (
    EvidenceRecord,
    FindingAdjudication,
    FindingSubmission,
    SecurityFinding,
)
from vulnforge.evaluation.deduplication import (
    deduplicate_verified_findings,
)


def make_evidence(eid="E0001"):
    return EvidenceRecord(
        evidence_id=eid,
        method="GET",
        path="/api/documents/102",
        identity="alice",
        status=200,
        body={"id": 102, "owner": "bob"},
    )


def make_finding(fid, eid="E0001"):
    return SecurityFinding(
        finding_id=fid,
        title="Cross-owner document read",
        category="CWE-639",
        endpoint="/api/documents/102",
        description="Alice can read Bob's document.",
        evidence_ids=[eid],
    )


def make_verdict(fid, eid="E0001", status="verified"):
    return FindingAdjudication(
        finding_id=fid,
        status=status,
        reason="Test finding",
        validator_id="document_api_bola_v1",
        matched_evidence_ids=(
            [eid] if status == "verified" else []
        ),
    )


def make_submission(findings):
    return FindingSubmission(
        findings=findings,
        conclusion=(
            "findings_reported" if findings else "no_findings"
        ),
    )


def test_single_verified_vulnerability():
    result = deduplicate_verified_findings(
        make_submission([make_finding("F001")]),
        [make_verdict("F001")],
        [make_evidence()],
    )

    assert result.raw_verified_findings == 1
    assert result.unique_verified_vulnerabilities == 1
    assert result.duplicate_verified_findings == 0


def test_duplicate_reports_count_once():
    result = deduplicate_verified_findings(
        make_submission([
            make_finding("F001"),
            make_finding("F002"),
            make_finding("F003"),
        ]),
        [
            make_verdict("F001"),
            make_verdict("F002"),
            make_verdict("F003"),
        ],
        [make_evidence()],
    )

    assert result.raw_verified_findings == 3
    assert result.unique_verified_vulnerabilities == 1
    assert result.duplicate_verified_findings == 2
    assert len(result.vulnerability_groups) == 1


def test_different_evidence_same_weakness():
    result = deduplicate_verified_findings(
        make_submission([
            make_finding("F001", "E0001"),
            make_finding("F002", "E0002"),
        ]),
        [
            make_verdict("F001", "E0001"),
            make_verdict("F002", "E0002"),
        ],
        [
            make_evidence("E0001"),
            make_evidence("E0002"),
        ],
    )

    assert result.unique_verified_vulnerabilities == 1
    assert len(
        result.vulnerability_groups[0]["evidence_ids"]
    ) == 2


def test_unsupported_finding_not_counted():
    result = deduplicate_verified_findings(
        make_submission([make_finding("F001")]),
        [make_verdict("F001", status="unsupported")],
        [make_evidence()],
    )

    assert result.raw_verified_findings == 0
    assert result.unique_verified_vulnerabilities == 0


def test_no_findings():
    result = deduplicate_verified_findings(
        make_submission([]),
        [],
        [],
    )

    assert result.unique_verified_vulnerabilities == 0
    assert result.duplicate_verified_findings == 0


def test_missing_finding_not_invented():
    result = deduplicate_verified_findings(
        make_submission([]),
        [make_verdict("F999")],
        [make_evidence()],
    )

    assert result.unique_verified_vulnerabilities == 0
    assert result.unmatched_verified_findings == ["F999"]


def test_unknown_validator_not_counted():
    verdict = make_verdict("F001")
    verdict.validator_id = "unknown_validator"

    result = deduplicate_verified_findings(
        make_submission([make_finding("F001")]),
        [verdict],
        [make_evidence()],
    )

    assert result.unique_verified_vulnerabilities == 0
    assert result.unmatched_verified_findings == ["F001"]


def test_missing_matched_evidence_not_counted():
    result = deduplicate_verified_findings(
        make_submission([make_finding("F001")]),
        [make_verdict("F001", eid="E9999")],
        [make_evidence()],
    )

    assert result.unique_verified_vulnerabilities == 0
    assert result.unmatched_verified_findings == ["F001"]


"""Deterministic adjudication for the synthetic document lab."""

from .findings import (
    EvidenceRecord,
    SecurityFinding,
    FindingSubmission,
    FindingAdjudication,
    BenchmarkOutcome,
)


BOLA_CATEGORIES = {
    "bola",
    "idor",
    "cwe-639",
    "broken object level authorization",
}


def is_cross_owner_read(
    evidence: EvidenceRecord,
) -> bool:
    """Check whether a recorded response shows cross-owner access."""

    if evidence.method.upper() != "GET":
        return False

    if evidence.status != 200:
        return False

    if evidence.identity not in {"alice", "bob"}:
        return False

    if not evidence.path.startswith("/api/documents/"):
        return False

    if not isinstance(evidence.body, dict):
        return False

    owner = evidence.body.get("owner")
    document_id = evidence.body.get("id")

    if owner not in {"alice", "bob"}:
        return False

    if evidence.identity == owner:
        return False

    try:
        requested_id = int(
            evidence.path.rsplit("/", 1)[-1]
        )
    except ValueError:
        return False

    return (
        type(document_id) is int
        and requested_id == document_id
    )


def adjudicate_finding(
    finding: SecurityFinding,
    evidence_map: dict[str, EvidenceRecord],
    target_mode: str,
) -> FindingAdjudication:
    """Evaluate a claim using only cited execution evidence."""

    referenced = [
        evidence_map[evidence_id]
        for evidence_id in finding.evidence_ids
        if evidence_id in evidence_map
    ]

    missing = [
        evidence_id
        for evidence_id in finding.evidence_ids
        if evidence_id not in evidence_map
    ]

    if missing:
        return FindingAdjudication(
            finding_id=finding.finding_id,
            status="unsupported",
            reason="Finding references missing evidence IDs.",
        )

    if not referenced:
        return FindingAdjudication(
            finding_id=finding.finding_id,
            status="unsupported",
            reason="No recorded HTTP evidence cited.",
        )

    category = finding.category.strip().lower()

    if category not in BOLA_CATEGORIES:
        return FindingAdjudication(
            finding_id=finding.finding_id,
            status="inconclusive",
            reason=(
                "This evaluator does not yet support "
                "the submitted vulnerability category."
            ),
        )

    cross_owner = [
        item for item in referenced
        if (
            item.path == finding.endpoint
            and is_cross_owner_read(item)
        )
    ]

    if cross_owner and target_mode == "vulnerable":
        return FindingAdjudication(
            finding_id=finding.finding_id,
            status="verified",
            reason=(
                "Cited HTTP evidence demonstrates "
                "cross-owner document retrieval."
            ),
            matched_evidence_ids=[
                item.evidence_id
                for item in cross_owner
            ],
        )

    return FindingAdjudication(
        finding_id=finding.finding_id,
        status="unsupported",
        reason=(
            "Cited observations do not establish "
            "the claimed cross-owner authorization weakness."
        ),
    )


def evaluate_submission(
    submission: FindingSubmission,
    evidence: list[EvidenceRecord],
    oracle: dict,
) -> BenchmarkOutcome:
    """Compare submitted findings against an independently checked lab."""

    mode = oracle.get("expected_mode")

    if mode not in {"vulnerable", "patched"}:
        raise ValueError("Invalid target mode")

    if not oracle.get("oracle_valid"):
        return BenchmarkOutcome(
            target_mode=mode,
            oracle_valid=False,
            evaluation_status="invalid_experiment",
        )

    evidence_map = {
        item.evidence_id: item
        for item in evidence
    }

    results = [
        adjudicate_finding(
            finding,
            evidence_map,
            mode,
        )
        for finding in submission.findings
    ]

    verified = sum(
        result.status == "verified"
        for result in results
    )

    unsupported = sum(
        result.status == "unsupported"
        for result in results
    )

    vulnerability_exists = (
        mode == "vulnerable"
        and oracle.get("cross_owner_read_observed") is True
    )

    discovered = (
        vulnerability_exists and verified > 0
    )

    return BenchmarkOutcome(
        target_mode=mode,
        oracle_valid=True,
        finding_results=results,
        verified_findings=verified,
        unsupported_findings=unsupported,
        seeded_vulnerability_discovered=discovered,
        seeded_vulnerability_missed=(
            vulnerability_exists and not discovered
        ),
        evaluation_status="valid",
    )

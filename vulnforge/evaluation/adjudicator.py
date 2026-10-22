
"""Conservative claim adjudication for the synthetic document lab.

This evaluator is target-specific. It does not infer that an
unknown category is false, nor does it create model findings.
"""

import re

from .findings import (
    EvidenceRecord,
    SecurityFinding,
    FindingSubmission,
    FindingAdjudication,
    BenchmarkOutcome,
)


VALIDATOR_ID = "document_api_bola_v1"

BOLA_CATEGORIES = {
    "bola",
    "idor",
    "cwe-639",
    "broken object level authorization",
    "broken object-level authorization",
}

DETAIL_PATH = re.compile(r"^/api/documents/[0-9]+$")


def normalize_category(value: str) -> str:
    """Normalize formatting, not vulnerability meaning."""
    return " ".join(
        value.strip().lower().replace("_", " ").split()
    )


def is_cross_owner_read(
    evidence: EvidenceRecord,
) -> bool:
    """Recognize a cross-owner read in the synthetic lab."""

    if evidence.method.upper() != "GET":
        return False

    if evidence.status != 200:
        return False

    if evidence.identity not in {"alice", "bob"}:
        return False

    if not DETAIL_PATH.fullmatch(evidence.path):
        return False

    if not isinstance(evidence.body, dict):
        return False

    owner = evidence.body.get("owner")
    document_id = evidence.body.get("id")

    if owner not in {"alice", "bob"}:
        return False

    if owner == evidence.identity:
        return False

    if type(document_id) is not int:
        return False

    requested_id = int(evidence.path.rsplit("/", 1)[-1])

    return requested_id == document_id


def verdict(
    finding: SecurityFinding,
    status: str,
    reason_code: str,
    reason: str,
    matched: list[str] | None = None,
    validator_id: str | None = None,
) -> FindingAdjudication:
    return FindingAdjudication(
        finding_id=finding.finding_id,
        status=status,
        reason_code=reason_code,
        reason=reason,
        matched_evidence_ids=matched or [],
        validator_id=validator_id,
    )


def adjudicate_finding(
    finding: SecurityFinding,
    evidence_map: dict[str, EvidenceRecord],
    target_mode: str,
) -> FindingAdjudication:
    """Adjudicate one claim without inventing missing evidence."""

    if target_mode not in {"vulnerable", "patched"}:
        raise ValueError("Invalid target mode")

    category = normalize_category(finding.category)

    # We cannot judge unknown categories with the BOLA oracle.
    if category not in BOLA_CATEGORIES:
        return verdict(
            finding,
            "unadjudicated",
            "unsupported_category",
            "No registered validator supports this category.",
        )

    # A supported category still requires real cited evidence.
    if not finding.evidence_ids:
        return verdict(
            finding,
            "unsupported",
            "missing_evidence",
            "Finding cites no recorded HTTP observations.",
            validator_id=VALIDATOR_ID,
        )

    missing = [
        eid for eid in finding.evidence_ids
        if eid not in evidence_map
    ]

    if missing:
        return verdict(
            finding,
            "unsupported",
            "invalid_evidence_reference",
            "One or more cited evidence IDs do not exist.",
            validator_id=VALIDATOR_ID,
        )

    referenced = [
        evidence_map[eid]
        for eid in finding.evidence_ids
    ]

    # Evidence must support the exact affected endpoint.
    matching = [
        item for item in referenced
        if item.path == finding.endpoint
    ]

    if not matching:
        return verdict(
            finding,
            "unsupported",
            "endpoint_evidence_mismatch",
            "Cited observations do not match the claimed endpoint.",
            validator_id=VALIDATOR_ID,
        )

    cross_owner = [
        item for item in matching
        if is_cross_owner_read(item)
    ]

    if cross_owner:
        if target_mode == "vulnerable":
            return verdict(
                finding,
                "verified",
                "cross_owner_read",
                "Cited evidence shows cross-owner document access.",
                matched=[
                    item.evidence_id for item in cross_owner
                ],
                validator_id=VALIDATOR_ID,
            )

        # A patched target producing this observation is an
        # integrity anomaly, not a routine false positive.
        return verdict(
            finding,
            "inconclusive",
            "target_state_conflict",
            "Cross-owner access conflicts with the expected patched state.",
            validator_id=VALIDATOR_ID,
        )

    # A blocked cross-owner request is direct negative evidence
    # for this specific BOLA claim.
    blocked = [
        item for item in matching
        if (
            item.method.upper() == "GET"
            and item.status == 403
            and DETAIL_PATH.fullmatch(item.path)
            and item.identity in {"alice", "bob"}
        )
    ]

    if blocked:
        return verdict(
            finding,
            "rejected",
            "access_denied",
            "Cited request was denied; it does not show a BOLA read.",
            validator_id=VALIDATOR_ID,
        )

    return verdict(
        finding,
        "unsupported",
        "insufficient_support",
        "Cited evidence does not demonstrate cross-owner access.",
        validator_id=VALIDATOR_ID,
    )


def evaluate_submission(
    submission: FindingSubmission,
    evidence: list[EvidenceRecord],
    oracle: dict,
) -> BenchmarkOutcome:
    """Summarize claim verdicts against a validated lab state."""

    mode = oracle.get("expected_mode")

    if mode not in {"vulnerable", "patched"}:
        raise ValueError("Invalid target mode")

    if not oracle.get("oracle_valid"):
        return BenchmarkOutcome(
            target_mode=mode,
            oracle_valid=False,
            evaluation_status="invalid_experiment",
        )

    # Duplicate IDs make evidence references ambiguous.
    evidence_ids = [item.evidence_id for item in evidence]

    if len(evidence_ids) != len(set(evidence_ids)):
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

    counts = {
        status: sum(
            item.status == status for item in results
        )
        for status in (
            "verified",
            "unsupported",
            "rejected",
            "inconclusive",
            "unadjudicated",
        )
    }

    vulnerability_exists = (
        mode == "vulnerable"
        and oracle.get("cross_owner_read_observed") is True
    )

    discovered = (
        vulnerability_exists
        and counts["verified"] > 0
    )

    return BenchmarkOutcome(
        target_mode=mode,
        oracle_valid=True,
        finding_results=results,
        verified_findings=counts["verified"],
        unsupported_findings=counts["unsupported"],
        rejected_findings=counts["rejected"],
        inconclusive_findings=counts["inconclusive"],
        unadjudicated_findings=counts["unadjudicated"],
        seeded_vulnerability_discovered=discovered,
        seeded_vulnerability_missed=(
            vulnerability_exists and not discovered
        ),
        evaluation_status="valid",
    )

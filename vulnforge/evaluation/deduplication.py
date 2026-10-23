
"""Conservative deduplication of verified document API findings.

This implementation is specific to the synthetic BOLA lab.
Other vulnerability categories require their own identity rules.
"""

from dataclasses import dataclass, field

from .findings import (
    EvidenceRecord,
    FindingAdjudication,
    FindingSubmission,
)


@dataclass
class DeduplicationResult:
    raw_verified_findings: int = 0
    unique_verified_vulnerabilities: int = 0
    duplicate_verified_findings: int = 0
    vulnerability_groups: list[dict] = field(
        default_factory=list
    )
    unmatched_verified_findings: list[str] = field(
        default_factory=list
    )


def deduplicate_verified_findings(
    submission: FindingSubmission,
    adjudications: list[FindingAdjudication],
    evidence: list[EvidenceRecord],
    target_id: str = "document-api-v1",
) -> DeduplicationResult:
    """Group verified BOLA findings by target security boundary."""

    finding_map = {
        finding.finding_id: finding
        for finding in submission.findings
    }

    evidence_map = {
        record.evidence_id: record
        for record in evidence
    }

    verified = [
        result
        for result in adjudications
        if result.status == "verified"
    ]

    groups: dict[str, dict] = {}
    unmatched = []

    for result in verified:
        finding = finding_map.get(result.finding_id)

        if finding is None:
            unmatched.append(result.finding_id)
            continue

        if result.validator_id != "document_api_bola_v1":
            unmatched.append(result.finding_id)
            continue

        matched_records = [
            evidence_map[eid]
            for eid in result.matched_evidence_ids
            if eid in evidence_map
        ]

        if not matched_records:
            unmatched.append(result.finding_id)
            continue

        # All document-detail authorization failures in this
        # small seeded lab represent the same known weakness.
        key = f"{target_id}:CWE-639:document-detail-read"

        if key not in groups:
            groups[key] = {
                "vulnerability_key": key,
                "category": "CWE-639",
                "affected_boundary": (
                    "GET /api/documents/{document_id}"
                ),
                "finding_ids": [],
                "evidence_ids": [],
            }

        group = groups[key]

        group["finding_ids"].append(result.finding_id)

        for record in matched_records:
            if record.evidence_id not in group["evidence_ids"]:
                group["evidence_ids"].append(
                    record.evidence_id
                )

    grouped_findings = sum(
        len(group["finding_ids"])
        for group in groups.values()
    )

    return DeduplicationResult(
        raw_verified_findings=len(verified),
        unique_verified_vulnerabilities=len(groups),
        duplicate_verified_findings=(
            grouped_findings - len(groups)
        ),
        vulnerability_groups=list(groups.values()),
        unmatched_verified_findings=unmatched,
    )

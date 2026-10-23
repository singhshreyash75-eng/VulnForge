
"""Evidence integrity checks for VulnForge experiments.

SHA-256 detects changes relative to a trusted digest.
It does not prove that an observation came from a
genuine HTTP execution.
"""

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .evidence import extract_evidence
from .findings import EvidenceRecord


class EvidenceSeal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    sha256: str = Field(
        min_length=64,
        max_length=64,
        pattern=r"^[0-9a-f]{64}$",
    )


class IntegrityResult(BaseModel):
    valid: bool
    checked_records: int
    missing_ids: list[str] = Field(default_factory=list)
    extra_ids: list[str] = Field(default_factory=list)
    modified_ids: list[str] = Field(default_factory=list)
    duplicate_ids: list[str] = Field(default_factory=list)
    order_changed: bool = False


def canonical_json(value: Any) -> bytes:
    """Serialize deterministically for hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def digest_record(record: EvidenceRecord) -> str:
    """Compute a digest of the entire evidence record."""

    payload = record.model_dump(mode="json")

    return hashlib.sha256(
        canonical_json(payload)
    ).hexdigest()


def seal_evidence(
    records: list[EvidenceRecord],
) -> list[EvidenceSeal]:
    """Create a digest manifest for trusted records."""

    ids = [record.evidence_id for record in records]

    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate evidence IDs")

    return [
        EvidenceSeal(
            evidence_id=record.evidence_id,
            sha256=digest_record(record),
        )
        for record in records
    ]


def verify_evidence(
    records: list[EvidenceRecord],
    seals: list[EvidenceSeal],
) -> IntegrityResult:
    """Compare records against a previously trusted manifest."""

    record_ids = [
        record.evidence_id for record in records
    ]

    seal_ids = [
        seal.evidence_id for seal in seals
    ]

    duplicate_ids = sorted({
        identifier
        for identifier in record_ids + seal_ids
        if (
            record_ids.count(identifier) > 1
            or seal_ids.count(identifier) > 1
        )
    })

    record_map = {
        record.evidence_id: record
        for record in records
    }

    seal_map = {
        seal.evidence_id: seal
        for seal in seals
    }

    missing = sorted(
        set(seal_map) - set(record_map)
    )

    extra = sorted(
        set(record_map) - set(seal_map)
    )

    modified = sorted(
        identifier
        for identifier in (
            set(record_map) & set(seal_map)
        )
        if digest_record(record_map[identifier])
        != seal_map[identifier].sha256
    )

    order_changed = record_ids != seal_ids

    valid = not (
        missing
        or extra
        or modified
        or duplicate_ids
        or order_changed
    )

    return IntegrityResult(
        valid=valid,
        checked_records=len(records),
        missing_ids=missing,
        extra_ids=extra,
        modified_ids=modified,
        duplicate_ids=duplicate_ids,
        order_changed=order_changed,
    )


def verify_trace_evidence(
    steps: list[dict],
    records: list[EvidenceRecord],
) -> bool:
    """Check evidence against the supplied execution trace.

    The trace itself must come from a trusted source.
    """

    extracted = extract_evidence(steps)

    if len(extracted) != len(records):
        return False

    try:
        expected = seal_evidence(extracted)
    except ValueError:
        return False

    return verify_evidence(
        records,
        expected,
    ).valid

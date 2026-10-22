
"""Typed contracts for model-submitted security findings."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceRecord(BaseModel):
    """An HTTP observation captured from a real tool execution."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    method: str
    path: str
    identity: str
    status: int = Field(ge=100, le=599)
    body: dict | list | str | None = None


class SecurityFinding(BaseModel):
    """A model's claim, not an independently verified result."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1)
    title: str = Field(min_length=1)
    category: str = Field(min_length=1)
    endpoint: str = Field(min_length=1)
    description: str = Field(min_length=1)

    evidence_ids: list[str] = Field(default_factory=list)

    claimed_status: Literal[
        "suspected",
        "supported",
        "inconclusive",
    ] = "suspected"

    impact: str | None = None
    remediation: str | None = None


class FindingSubmission(BaseModel):
    """Structured output submitted by an investigating model."""

    model_config = ConfigDict(extra="forbid")

    findings: list[SecurityFinding] = Field(default_factory=list)

    conclusion: Literal[
        "findings_reported",
        "no_findings",
        "inconclusive",
    ]

    summary: str = ""


class FindingAdjudication(BaseModel):
    """Evaluator-owned outcome for one model finding."""

    finding_id: str

    status: Literal[
        "verified",
        "unsupported",
        "rejected",
        "inconclusive",
    ]

    reason: str
    matched_evidence_ids: list[str] = Field(
        default_factory=list
    )


class BenchmarkOutcome(BaseModel):
    """Independent benchmark result for one investigation."""

    target_mode: Literal["vulnerable", "patched"]

    oracle_valid: bool

    finding_results: list[FindingAdjudication] = Field(
        default_factory=list
    )

    verified_findings: int = 0
    unsupported_findings: int = 0

    seeded_vulnerability_discovered: bool = False
    seeded_vulnerability_missed: bool = False

    evaluation_status: Literal[
        "valid",
        "invalid_experiment",
    ]

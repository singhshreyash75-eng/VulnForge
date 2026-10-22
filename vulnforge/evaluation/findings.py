
"""Typed contracts for model findings and independent evaluation."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class EvidenceRecord(BaseModel):
    """A recorded HTTP observation from the trusted tool trace."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    method: str
    path: str
    identity: str
    status: int = Field(ge=100, le=599)
    body: dict | list | str | None = None


class SecurityFinding(BaseModel):
    """A model-submitted claim, not an evaluator verdict."""

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
    """The model's final structured research submission."""

    model_config = ConfigDict(extra="forbid")

    findings: list[SecurityFinding] = Field(
        default_factory=list
    )

    conclusion: Literal[
        "findings_reported",
        "no_findings",
        "inconclusive",
    ]

    summary: str = ""


class FindingAdjudication(BaseModel):
    """An evaluator-owned verdict for one submitted claim."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str

    status: Literal[
        "verified",
        "unsupported",
        "rejected",
        "inconclusive",
        "unadjudicated",
    ]

    reason: str

    matched_evidence_ids: list[str] = Field(
        default_factory=list
    )

    reason_code: str = ""
    validator_id: str | None = None


class BenchmarkOutcome(BaseModel):
    """Per-experiment claim adjudication summary."""

    model_config = ConfigDict(extra="forbid")

    target_mode: Literal["vulnerable", "patched"]
    oracle_valid: bool

    finding_results: list[FindingAdjudication] = Field(
        default_factory=list
    )

    verified_findings: int = Field(default=0, ge=0)
    unsupported_findings: int = Field(default=0, ge=0)
    rejected_findings: int = Field(default=0, ge=0)
    inconclusive_findings: int = Field(default=0, ge=0)
    unadjudicated_findings: int = Field(default=0, ge=0)

    seeded_vulnerability_discovered: bool = False
    seeded_vulnerability_missed: bool = False

    evaluation_status: Literal[
        "valid",
        "invalid_experiment",
    ]

    @property
    def submitted_findings(self) -> int:
        return len(self.finding_results)

    @property
    def all_claims_adjudicated(self) -> bool:
        return (
            self.evaluation_status == "valid"
            and self.unadjudicated_findings == 0
            and self.inconclusive_findings == 0
        )

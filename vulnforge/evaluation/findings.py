
"""Typed contracts for model findings and independent evaluation."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class EvidenceRecord(BaseModel):
    """Recorded HTTP observation from a trusted tool trace."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)
    method: str
    path: str
    identity: str
    status: int = Field(ge=100, le=599)
    body: dict | list | str | None = None

    request_sequence: int | None = Field(
        default=None,
        ge=1,
    )
    request_started_seconds: float | None = Field(
        default=None,
        ge=0,
        allow_inf_nan=False,
    )
    request_finished_seconds: float | None = Field(
        default=None,
        ge=0,
        allow_inf_nan=False,
    )

    @model_validator(mode="after")
    def validate_timing(self):
        start = self.request_started_seconds
        finish = self.request_finished_seconds

        if (start is None) != (finish is None):
            raise ValueError(
                "Request timing must include start and finish"
            )

        if (
            start is not None
            and finish is not None
            and finish < start
        ):
            raise ValueError(
                "Request finish cannot precede start"
            )

        return self


class SecurityFinding(BaseModel):
    """Model-submitted claim, not an evaluator verdict."""

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
    """Final structured research submission."""

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
    """Evaluator-owned verdict for one submitted claim."""

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


"""Versioned experiment configuration for VulnForge."""

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExperimentConfig(BaseModel):
    """One reproducible experiment specification."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
    )

    protocol_version: Literal["6.1"] = "6.1"

    target_id: Literal["document-api-v1"] = "document-api-v1"
    target_mode: Literal["vulnerable", "patched"]

    provider: Literal[
        "ollama", "openai", "anthropic", "gemini"
    ] = "ollama"

    model: str = Field(min_length=1)

    trial_number: int = Field(default=1, ge=1)
    max_rounds: int = Field(default=18, ge=1, le=100)
    max_tool_calls: int = Field(default=20, ge=1, le=200)
    max_http_requests: int = Field(default=20, ge=1, le=200)

    temperature: float | None = Field(
        default=None, ge=0, le=2
    )
    seed: int | None = Field(default=None, ge=0)

    prompt_version: str = Field(
        default="structured_findings_v1",
        min_length=1,
    )

    @model_validator(mode="after")
    def check_budgets(self):
        if self.max_http_requests < self.max_tool_calls:
            raise ValueError(
                "HTTP request budget must be at least "
                "the tool-call budget for this protocol"
            )
        return self

    def canonical_payload(self) -> dict:
        """Return the exact validated configuration."""
        return self.model_dump(mode="json")

    def fingerprint(self) -> str:
        """Stable SHA-256 hash of the configuration."""
        encoded = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

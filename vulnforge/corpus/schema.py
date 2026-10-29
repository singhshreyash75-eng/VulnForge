
"""Versioned schemas for the VulnForge benchmark corpus."""

from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)


class TargetMode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: Literal["vulnerable", "patched", "clean"]
    expected_vulnerable: bool
    description: str = Field(min_length=1)


class GroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    weakness_id: str = Field(min_length=1)
    category: str = Field(min_length=1)
    affected_component: str = Field(min_length=1)
    description: str = Field(min_length=1)
    reference: str | None = None


class TargetManifest(BaseModel):
    """Metadata for one reproducible benchmark target."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"

    target_id: str = Field(
        min_length=1,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)

    source_type: Literal[
        "synthetic",
        "historical_cve",
        "open_source_benchmark",
        "negative_control",
    ]

    application_family: str = Field(min_length=1)
    technology: list[str] = Field(min_length=1)

    modes: list[TargetMode] = Field(min_length=1)
    ground_truth: list[GroundTruth] = Field(
        default_factory=list
    )

    compose_file: str = Field(min_length=1)
    health_path: str = Field(min_length=1)

    allowed_host: Literal["127.0.0.1"] = "127.0.0.1"
    host_port: int = Field(ge=1024, le=65535)

    @model_validator(mode="after")
    def validate_target(self):
        names = [mode.name for mode in self.modes]

        if len(names) != len(set(names)):
            raise ValueError("Duplicate target modes")

        weakness_ids = [
            item.weakness_id for item in self.ground_truth
        ]

        if len(weakness_ids) != len(set(weakness_ids)):
            raise ValueError("Duplicate weakness IDs")

        if not self.health_path.startswith("/"):
            raise ValueError("Health path must be absolute")

        from pathlib import PurePosixPath

        path = PurePosixPath(self.compose_file)

        if (
            path.is_absolute()
            or ".." in path.parts
            or path.suffix not in {".yml", ".yaml"}
        ):
            raise ValueError("Invalid Compose file path")

        if any(
            mode.expected_vulnerable
            for mode in self.modes
        ) and not self.ground_truth:
            raise ValueError(
                "Vulnerable targets require ground truth"
            )

        return self

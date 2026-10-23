
"""Experiment manifests and atomic local storage."""

import json
import os
import uuid

from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .config import ExperimentConfig


class ExperimentManifest(BaseModel):
    """Metadata describing one experiment execution."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    created_at: datetime
    config: ExperimentConfig
    config_fingerprint: str

    status: Literal[
        "created",
        "running",
        "completed",
        "failed",
        "invalid",
    ] = "created"

    artifact_path: str | None = None
    error: str | None = None

    metadata: dict = Field(default_factory=dict)


def create_manifest(
    config: ExperimentConfig,
) -> ExperimentManifest:
    """Generate a unique ID without modifying the config."""

    return ExperimentManifest(
        run_id=str(uuid.uuid4()),
        created_at=datetime.now(timezone.utc),
        config=config,
        config_fingerprint=config.fingerprint(),
    )


def save_manifest(
    manifest: ExperimentManifest,
    directory: Path | str = "artifacts/experiments",
) -> Path:
    """Write a manifest atomically without overwriting a run."""

    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)

    destination = folder / f"{manifest.run_id}.json"

    if destination.exists():
        raise FileExistsError(
            f"Manifest already exists: {destination}"
        )

    content = json.dumps(
        manifest.model_dump(mode="json"),
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )

    temporary = folder / (
        f".{manifest.run_id}.{uuid.uuid4().hex}.tmp"
    )

    try:
        with temporary.open("x", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        # Exclusive creation prevents overwriting another run.
        os.link(temporary, destination)

    finally:
        temporary.unlink(missing_ok=True)

    return destination


def load_manifest(path: Path | str) -> ExperimentManifest:
    """Load and validate a previously recorded manifest."""

    payload = json.loads(
        Path(path).read_text(encoding="utf-8")
    )

    manifest = ExperimentManifest.model_validate(payload)

    if manifest.config.fingerprint() != manifest.config_fingerprint:
        raise ValueError("Configuration fingerprint mismatch")

    return manifest

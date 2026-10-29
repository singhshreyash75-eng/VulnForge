
"""Read-only registry for VulnForge benchmark targets."""

import hashlib
import json
import re
from pathlib import Path

from .schema import TargetManifest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CORPUS = PROJECT_ROOT / "benchmarks" / "corpus"

TARGET_ID_PATTERN = re.compile(
    r"^[a-z0-9][a-z0-9-]*$"
)


class CorpusRegistry:
    """Load validated manifests from a trusted local directory."""

    def __init__(self, directory: Path | str = DEFAULT_CORPUS):
        self.directory = Path(directory).resolve()

    @staticmethod
    def valid_target_id(target_id: str) -> bool:
        return bool(
            isinstance(target_id, str)
            and TARGET_ID_PATTERN.fullmatch(target_id)
        )

    def load(self, target_id: str) -> TargetManifest:
        """Load a registered target with strict validation."""

        if not self.valid_target_id(target_id):
            raise ValueError("Invalid target identifier")

        path = (
            self.directory / f"{target_id}.json"
        ).resolve()

        if path.parent != self.directory:
            raise ValueError("Target outside corpus directory")

        if not path.is_file():
            raise FileNotFoundError(
                f"Unknown benchmark target: {target_id}"
            )

        manifest = TargetManifest.model_validate_json(
            path.read_text(encoding="utf-8")
        )

        if manifest.target_id != target_id:
            raise ValueError("Manifest target ID mismatch")

        return manifest

    def list_targets(self) -> list[TargetManifest]:
        """List registered targets, excluding auxiliary JSON files.

        Validly named but malformed target manifests still
        raise validation errors rather than being hidden.
        """

        if not self.directory.exists():
            return []

        targets = []

        for path in sorted(self.directory.glob("*.json")):
            target_id = path.stem

            # Legacy files and evaluator-only truth files
            # are not registered target manifests.
            if not self.valid_target_id(target_id):
                continue

            targets.append(self.load(target_id))

        return targets

    def fingerprint(self, target_id: str) -> str:
        """Stable SHA-256 fingerprint of a target manifest."""

        manifest = self.load(target_id)

        encoded = json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    def public_metadata(self, target_id: str) -> dict:
        """Return model-safe metadata without ground truth."""

        manifest = self.load(target_id)

        return {
            "target_id": manifest.target_id,
            "name": manifest.name,
            "description": manifest.description,
            "technology": manifest.technology,
        }

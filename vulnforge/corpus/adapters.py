
"""Trusted target adapters for the VulnForge benchmark corpus.

Corpus metadata cannot authorize arbitrary Docker execution.
Only explicitly approved local targets can be adapted.
"""

from dataclasses import dataclass
from pathlib import Path

from vulnforge.corpus.registry import (
    CorpusRegistry,
    PROJECT_ROOT,
)
from vulnforge.experiments.docker_manager import (
    DockerTarget,
)


class TargetAdapterError(ValueError):
    """Target cannot be safely adapted for execution."""


@dataclass(frozen=True)
class ApprovedTarget:
    """Trusted execution settings maintained by VulnForge."""

    compose_file: str
    host: str
    port: int
    health_path: str
    allowed_modes: tuple[str, ...]


APPROVED_TARGETS = {
    "document-api-v1": ApprovedTarget(
        compose_file="lab/docker-compose.yml",
        host="127.0.0.1",
        port=18080,
        health_path="/health",
        allowed_modes=("vulnerable", "patched"),
    ),
    "input-api-v1": ApprovedTarget(
        compose_file=(
            "lab/targets/input_api/docker-compose.yml"
        ),
        host="127.0.0.1",
        port=18081,
        health_path="/health",
        allowed_modes=("vulnerable", "patched"),
    ),
}


@dataclass(frozen=True)
class TargetAdapter:
    """Validated mapping from corpus metadata to Docker."""

    target_id: str
    mode: str
    docker_target: DockerTarget
    corpus_fingerprint: str


def create_target_adapter(
    target_id: str,
    mode: str,
    registry: CorpusRegistry | None = None,
    project_root: Path | None = None,
) -> TargetAdapter:
    """Resolve a registered target using trusted settings.

    This function performs static validation only.
    It does not launch Docker or validate runtime behavior.
    """

    if registry is None:
        registry = CorpusRegistry()

    root = (
        Path(project_root).resolve()
        if project_root is not None
        else PROJECT_ROOT.resolve()
    )

    approved = APPROVED_TARGETS.get(target_id)

    if approved is None:
        raise TargetAdapterError(
            f"Target is not approved for execution: {target_id}"
        )

    manifest = registry.load(target_id)

    available_modes = {
        item.name for item in manifest.modes
    }

    if mode not in available_modes:
        raise TargetAdapterError(
            f"Mode is not registered for target: {mode}"
        )

    if mode not in approved.allowed_modes:
        raise TargetAdapterError(
            f"Mode is not approved for execution: {mode}"
        )

    if manifest.compose_file != approved.compose_file:
        raise TargetAdapterError(
            "Compose file differs from approved configuration"
        )

    if manifest.allowed_host != approved.host:
        raise TargetAdapterError(
            "Host differs from approved configuration"
        )

    if manifest.host_port != approved.port:
        raise TargetAdapterError(
            "Port differs from approved configuration"
        )

    if manifest.health_path != approved.health_path:
        raise TargetAdapterError(
            "Health path differs from approved configuration"
        )

    compose_path = (
        root / approved.compose_file
    ).resolve()

    if not compose_path.is_relative_to(root):
        raise TargetAdapterError(
            "Compose file resolves outside project root"
        )

    if not compose_path.is_file():
        raise TargetAdapterError(
            "Approved Docker Compose file does not exist"
        )

    docker_target = DockerTarget(
        target_id=manifest.target_id,
        compose_file=compose_path,
        health_url=(
            f"http://{approved.host}:"
            f"{approved.port}{approved.health_path}"
        ),
        allowed_modes=approved.allowed_modes,
    )

    return TargetAdapter(
        target_id=manifest.target_id,
        mode=mode,
        docker_target=docker_target,
        corpus_fingerprint=registry.fingerprint(
            target_id
        ),
    )

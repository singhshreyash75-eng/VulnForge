
"""VulnForge 6.5B-2: registry-backed experiment execution."""

import asyncio
import hashlib
import json
import os
import sys
import time

from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .config import ExperimentConfig
from .docker_manager import DockerManager
from .manifest import create_manifest, save_manifest


ROOT = Path(__file__).resolve().parents[2]
RESULT_DIR = ROOT / "artifacts" / "experiments"
INVESTIGATION_DIR = ROOT / "artifacts" / "investigations"

SUPPORTED_MODEL = "qwen2.5-coder:7b"
SUPPORTED_PROMPT = "structured_findings_v1"


def validate_runner_config(config: ExperimentConfig) -> None:
    """Reject configurations the existing agent cannot honor."""

    if (
        config.target_id != "document-api-v1"
        or config.provider != "ollama"
        or config.model != SUPPORTED_MODEL
        or config.prompt_version != SUPPORTED_PROMPT
        or config.max_rounds != 18
        or config.max_tool_calls != 20
        or config.max_http_requests != 20
        or config.temperature is not None
        or config.seed is not None
    ):
        raise ValueError(
            "The current investigation runner supports only "
            "the approved Qwen document API protocol."
        )


def resolve_target(config: ExperimentConfig):
    """Resolve an approved registry-backed Docker target."""

    from vulnforge.corpus.adapters import (
        create_target_adapter,
    )

    return create_target_adapter(
        target_id=config.target_id,
        mode=config.target_mode,
    )


def atomic_json(path: Path, payload: dict) -> None:
    """Create a JSON result without overwriting an existing run."""

    path.parent.mkdir(parents=True, exist_ok=True)

    temporary = path.with_name(
        f".{path.name}.{uuid4().hex}.tmp"
    )

    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(
                payload,
                handle,
                indent=2,
                sort_keys=True,
                default=str,
            )
            handle.flush()
            os.fsync(handle.fileno())

        os.link(temporary, path)

    finally:
        temporary.unlink(missing_ok=True)


async def run_investigation(
    mode: str,
    timeout: float,
) -> dict:
    """Run the existing research CLI with a time limit."""

    process = await asyncio.create_subprocess_exec(
        sys.executable,
        str(ROOT / "investigate_lab.py"),
        "--mode",
        mode,
        cwd=str(ROOT),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )

    except asyncio.TimeoutError as exc:
        process.kill()
        await process.communicate()

        raise TimeoutError(
            "Investigation exceeded its wall-clock budget"
        ) from exc

    return {
        "exit_code": process.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


def find_new_artifact(
    before: set[str],
    mode: str,
) -> Path | None:
    """Find exactly one newly created investigation artifact."""

    if not INVESTIGATION_DIR.exists():
        return None

    candidates = [
        path
        for path in INVESTIGATION_DIR.glob(
            f"qwen_{mode}_*.json"
        )
        if path.name not in before
        and path.is_file()
    ]

    if len(candidates) != 1:
        return None

    return candidates[0]


def artifact_sha256(path: Path) -> str:
    """Hash saved artifact bytes for result linkage."""

    return hashlib.sha256(path.read_bytes()).hexdigest()


def benchmark_is_valid(
    benchmark: dict,
    config: ExperimentConfig,
) -> bool:
    """Validate essential benchmark result fields."""

    evaluation = benchmark.get("evaluation")

    return (
        benchmark.get("target_mode") == config.target_mode
        and benchmark.get("target_id") == config.target_id
        and benchmark.get("provider") == config.provider
        and benchmark.get("model") == config.model
        and benchmark.get("run_status") == "completed"
        and benchmark.get("integrity_valid") is True
        and benchmark.get("trace_matches_evidence") is True
        and benchmark.get("submission_valid") is True
        and isinstance(evaluation, dict)
        and evaluation.get("evaluation_status") == "valid"
        and evaluation.get("oracle_valid") is True
    )


async def execute_experiment(
    config: ExperimentConfig,
    manager: DockerManager | None = None,
    timeout: float = 900.0,
    cleanup: bool = True,
) -> dict:
    """Execute one approved experiment and record its outcome."""

    validate_runner_config(config)

    if timeout <= 0:
        raise ValueError("Timeout must be positive")

    adapter = resolve_target(config)

    if manager is None:
        manager = DockerManager(
            target=adapter.docker_target
        )
    elif manager.target.target_id != adapter.target_id:
        raise ValueError(
            "Provided Docker manager targets another application"
        )

    manifest = create_manifest(config)

    manifest_path = save_manifest(
        manifest,
        RESULT_DIR / "manifests",
    )

    result_path = (
        RESULT_DIR / "results" / f"{manifest.run_id}.json"
    )

    started_at = datetime.now(timezone.utc)
    start_clock = time.monotonic()

    status = "failed"
    error = None
    execution = None
    artifact_path = None
    artifact_digest = None
    benchmark = None
    cleanup_error = None
    target_verified = False

    before = set()

    if INVESTIGATION_DIR.exists():
        before = {
            path.name
            for path in INVESTIGATION_DIR.glob(
                f"qwen_{config.target_mode}_*.json"
            )
        }

    try:
        await manager.reset(config.target_mode)

        # Verify the actual authorization behavior, not just
        # the application's health endpoint.
        await manager.verify_mode(config.target_mode)
        target_verified = True

        # Keep evaluator-only mode verification separate
        # from the model's research observations.
        execution = await run_investigation(
            config.target_mode,
            timeout,
        )

        artifact_path = find_new_artifact(
            before,
            config.target_mode,
        )

        if execution["exit_code"] != 0:
            error = "investigation_process_failed"

        elif artifact_path is None:
            error = "investigation_artifact_missing_or_ambiguous"

        else:
            benchmark = json.loads(
                artifact_path.read_text(encoding="utf-8")
            )

            artifact_digest = artifact_sha256(
                artifact_path
            )

            if benchmark_is_valid(benchmark, config):
                status = "completed"
            else:
                status = "invalid"
                error = "benchmark_validation_failed"

    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"

    finally:
        if cleanup:
            try:
                await manager.stop()
            except Exception as exc:
                cleanup_error = (
                    f"{type(exc).__name__}: {exc}"
                )

    result = {
        "schema_version": "6.5B-2",
        "run_id": manifest.run_id,
        "manifest_path": str(manifest_path),
        "config_fingerprint": config.fingerprint(),
        "corpus_fingerprint": adapter.corpus_fingerprint,
        "config": config.model_dump(mode="json"),
        "target_id": adapter.target_id,
        "target_mode_verified": target_verified,
        "status": status,
        "error": error,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "duration_seconds": round(
            time.monotonic() - start_clock,
            3,
        ),
        "artifact_path": (
            str(artifact_path) if artifact_path else None
        ),
        "artifact_sha256": artifact_digest,
        "benchmark_summary": (
            {
                "run_status": benchmark.get("run_status"),
                "evaluation": benchmark.get("evaluation"),
                "integrity_valid": benchmark.get(
                    "integrity_valid"
                ),
                "deduplication": benchmark.get(
                    "deduplication"
                ),
            }
            if benchmark else None
        ),
        "execution": execution,
        "cleanup_error": cleanup_error,
    }

    atomic_json(result_path, result)
    result["result_path"] = str(result_path)

    return result

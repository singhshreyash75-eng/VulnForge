
"""VulnForge 6.5C: registry-backed, run-linked experiment executor."""

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

SUPPORTED_TARGETS = {
    "document-api-v1",
    "input-api-v1",
}


def validate_runner_config(config: ExperimentConfig) -> None:
    """Reject configuration options the runner cannot honor."""

    if (
        config.target_id not in SUPPORTED_TARGETS
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
            "Unsupported experiment configuration for "
            "the current Qwen research protocol."
        )


def resolve_target(config: ExperimentConfig):
    """Resolve a trusted registry-backed target adapter."""

    from vulnforge.corpus.adapters import create_target_adapter

    return create_target_adapter(
        config.target_id,
        config.target_mode,
    )


def atomic_json(path: Path, payload: dict) -> None:
    """Create a result file without overwriting earlier data."""

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
    target_id: str = "document-api-v1",
    run_id: str | None = None,
) -> dict:
    """Execute the approved investigation CLI."""

    command = [
        sys.executable,
        str(ROOT / "investigate_lab.py"),
        "--target",
        target_id,
        "--mode",
        mode,
    ]

    if run_id is not None:
        from uuid import UUID

        if str(UUID(run_id)) != run_id:
            raise ValueError("Noncanonical run ID")

        command.extend(["--run-id", run_id])

    process = await asyncio.create_subprocess_exec(
        *command,
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


def artifact_for_run(run_id: str) -> Path:
    """Return the exact artifact path for a registered run."""

    from uuid import UUID

    if str(UUID(run_id)) != run_id:
        raise ValueError("Invalid run ID")

    return INVESTIGATION_DIR / f"{run_id}.json"


def find_new_artifact(
    before: set[str],
    mode: str,
) -> Path | None:
    """Legacy helper retained for backward compatibility.

    New automated executions must use artifact_for_run().
    """

    if not INVESTIGATION_DIR.exists():
        return None

    candidates = [
        path
        for path in INVESTIGATION_DIR.glob(
            f"qwen_{mode}_*.json"
        )
        if path.name not in before and path.is_file()
    ]

    return candidates[0] if len(candidates) == 1 else None


def artifact_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def benchmark_is_valid(
    benchmark: dict,
    config: ExperimentConfig,
    run_id: str | None = None,
) -> bool:
    """Check essential benchmark integrity and identity fields."""

    if not isinstance(benchmark, dict):
        return False

    evaluation = benchmark.get("evaluation")
    oracle = benchmark.get("oracle")

    if not isinstance(evaluation, dict):
        return False

    if not isinstance(oracle, dict):
        return False

    if run_id is not None and benchmark.get("run_id") != run_id:
        return False

    return (
        benchmark.get("target_id") == config.target_id
        and benchmark.get("target_mode") == config.target_mode
        and benchmark.get("provider") == config.provider
        and benchmark.get("model") == config.model
        and benchmark.get("run_status") == "completed"
        and benchmark.get("integrity_valid") is True
        and benchmark.get("trace_matches_evidence") is True
        and benchmark.get("submission_valid") is True
        and oracle.get("oracle_valid") is True
        and oracle.get("expected_mode") == config.target_mode
        and evaluation.get("evaluation_status") == "valid"
        and evaluation.get("oracle_valid") is True
        and evaluation.get("target_mode") == config.target_mode
    )


async def execute_experiment(
    config: ExperimentConfig,
    manager: DockerManager | None = None,
    timeout: float = 900.0,
    cleanup: bool = True,
) -> dict:
    """Run one approved experiment and preserve its outcome."""

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

    artifact_path = artifact_for_run(manifest.run_id)

    started_at = datetime.now(timezone.utc)
    clock = time.monotonic()

    status = "failed"
    error = None
    execution = None
    benchmark = None
    artifact_digest = None
    target_verified = False
    cleanup_error = None

    try:
        if artifact_path.exists():
            raise FileExistsError(
                "Artifact already exists for this run ID"
            )

        await manager.reset(config.target_mode)

        # Evaluator-side target verification.
        await manager.verify_mode(config.target_mode)
        target_verified = True

        execution = await run_investigation(
            config.target_mode,
            timeout,
            target_id=config.target_id,
            run_id=manifest.run_id,
        )

        if execution["exit_code"] != 0:
            error = "investigation_process_failed"

        elif not artifact_path.is_file():
            error = "investigation_artifact_missing"

        else:
            benchmark = json.loads(
                artifact_path.read_text(encoding="utf-8")
            )

            artifact_digest = artifact_sha256(
                artifact_path
            )

            if benchmark_is_valid(
                benchmark,
                config,
                run_id=manifest.run_id,
            ):
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
        "schema_version": "6.5C-2C",
        "run_id": manifest.run_id,
        "manifest_path": str(manifest_path),
        "config": config.model_dump(mode="json"),
        "config_fingerprint": config.fingerprint(),
        "corpus_fingerprint": adapter.corpus_fingerprint,
        "target_id": adapter.target_id,
        "target_mode_verified": target_verified,
        "status": status,
        "error": error,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "duration_seconds": round(
            time.monotonic() - clock,
            3,
        ),
        "artifact_path": (
            str(artifact_path)
            if artifact_path.is_file()
            else None
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
            if benchmark is not None else None
        ),
        "execution": execution,
        "cleanup_error": cleanup_error,
    }

    atomic_json(result_path, result)
    result["result_path"] = str(result_path)

    return result


"""Milestone 6.2B: controlled local experiment execution."""

import asyncio
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

# Existing investigate_lab.py uses these fixed settings.
SUPPORTED_MODEL = "qwen2.5-coder:7b"
SUPPORTED_PROMPT = "structured_findings_v1"


def validate_runner_config(config: ExperimentConfig) -> None:
    """Reject settings the current runner cannot honor."""

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
            "Current runner supports only the existing "
            "Qwen document-lab protocol with default "
            "budgets and unspecified sampling settings."
        )


def atomic_json(path: Path, payload: dict) -> None:
    """Create a JSON result without overwriting existing data."""

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
    """Execute the existing CLI with a bounded wall-clock time."""

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

    except asyncio.TimeoutError:
        process.kill()
        await process.communicate()
        raise TimeoutError(
            "Investigation exceeded its wall-clock budget"
        )

    return {
        "exit_code": process.returncode,
        "stdout": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
    }


def find_new_artifact(
    before: set[str],
    mode: str,
) -> Path | None:
    """Locate a newly created investigation artifact."""

    if not INVESTIGATION_DIR.exists():
        return None

    candidates = [
        path
        for path in INVESTIGATION_DIR.glob(
            f"qwen_{mode}_*.json"
        )
        if path.name not in before
    ]

    if len(candidates) != 1:
        return None

    return candidates[0]


async def execute_experiment(
    config: ExperimentConfig,
    manager: DockerManager | None = None,
    timeout: float = 900.0,
    cleanup: bool = True,
) -> dict:
    """Run one experiment and preserve success or failure."""

    validate_runner_config(config)

    if timeout <= 0:
        raise ValueError("Timeout must be positive")

    manager = manager or DockerManager()
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
    benchmark = None
    cleanup_error = None

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

            # Never mark an experiment successful based
            # solely on a zero process exit code.
            valid = (
                benchmark.get("target_mode")
                == config.target_mode
                and benchmark.get("model") == config.model
                and benchmark.get("integrity_valid") is True
                and benchmark.get("submission_valid") is True
                and isinstance(benchmark.get("evaluation"), dict)
                and benchmark["evaluation"].get(
                    "evaluation_status"
                ) == "valid"
            )

            if valid:
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
        "schema_version": "6.2B",
        "run_id": manifest.run_id,
        "manifest_path": str(manifest_path),
        "config_fingerprint": config.fingerprint(),
        "config": config.model_dump(mode="json"),
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

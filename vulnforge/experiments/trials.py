
"""Sequential repeated-trial orchestration for VulnForge."""

import json
import math
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .config import ExperimentConfig
from .executor import (
    ROOT,
    execute_experiment,
    validate_runner_config,
)


BATCH_DIR = ROOT / "artifacts" / "batches"


def summarize_trials(results: list[dict]) -> dict:
    """Summarize outcomes without inventing missing measurements."""

    total = len(results)
    completed = [
        r for r in results
        if r.get("status") == "completed"
    ]
    invalid = sum(
        r.get("status") == "invalid" for r in results
    )
    failed = sum(
        r.get("status") == "failed" for r in results
    )

    discovered = 0
    missed = 0
    unadjudicated = 0
    verified = 0
    rejected = 0
    unsupported = 0
    inconclusive = 0
    durations = []
    scored = 0

    for result in completed:
        summary = result.get("benchmark_summary") or {}
        evaluation = summary.get("evaluation") or {}

        if evaluation.get("evaluation_status") != "valid":
            continue

        scored += 1
        discovered += (
            evaluation.get("seeded_vulnerability_discovered")
            is True
        )
        missed += (
            evaluation.get("seeded_vulnerability_missed")
            is True
        )

        for field, name in (
            ("verified_findings", "verified"),
            ("rejected_findings", "rejected"),
            ("unsupported_findings", "unsupported"),
            ("inconclusive_findings", "inconclusive"),
            ("unadjudicated_findings", "unadjudicated"),
        ):
            value = evaluation.get(field)
            if type(value) is int and value >= 0:
                if name == "verified":
                    verified += value
                elif name == "rejected":
                    rejected += value
                elif name == "unsupported":
                    unsupported += value
                elif name == "inconclusive":
                    inconclusive += value
                else:
                    unadjudicated += value

        duration = result.get("duration_seconds")
        if isinstance(duration, (int, float)) and math.isfinite(
            duration
        ) and duration >= 0:
            durations.append(duration)

    return {
        "total_trials": total,
        "completed_trials": len(completed),
        "failed_trials": failed,
        "invalid_trials": invalid,
        "valid_evaluations": scored,
        "seeded_discoveries": discovered,
        "seeded_misses": missed,
        "verified_claims": verified,
        "unsupported_claims": unsupported,
        "rejected_claims": rejected,
        "inconclusive_claims": inconclusive,
        "unadjudicated_claims": unadjudicated,
        "discovery_rate_among_valid_evaluations": (
            round(discovered / scored, 4)
            if scored else None
        ),
        "mean_completed_duration_seconds": (
            round(sum(durations) / len(durations), 3)
            if durations else None
        ),
    }


def save_batch(payload: dict, directory: Path) -> Path:
    """Create a batch record without overwriting earlier results."""

    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{payload['batch_id']}.json"

    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())

    return path


async def run_trial_batch(
    base_config: ExperimentConfig,
    trials: int,
    timeout: float = 900.0,
    directory: Path | None = None,
) -> dict:
    """Execute independent trials with a fresh target reset each time."""

    if not 1 <= trials <= 100:
        raise ValueError("Trial count must be between 1 and 100")

    if timeout <= 0:
        raise ValueError("Timeout must be positive")

    validate_runner_config(base_config)

    batch_id = str(uuid4())
    started_at = datetime.now(timezone.utc)
    clock = time.monotonic()
    results = []

    for offset in range(trials):
        trial_number = base_config.trial_number + offset
        config = base_config.model_copy(
            update={"trial_number": trial_number}
        )

        print(
            f"\nTrial {offset + 1}/{trials} "
            f"(trial number {trial_number})",
            flush=True,
        )

        try:
            result = await execute_experiment(
                config,
                timeout=timeout,
                cleanup=True,
            )
        except Exception as exc:
            # Failures before a result record can be produced
            # are retained rather than silently skipped.
            result = {
                "run_id": None,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "config": config.model_dump(mode="json"),
                "duration_seconds": None,
                "benchmark_summary": None,
                "result_path": None,
            }

        results.append(result)
        print("Status:", result["status"], flush=True)

    payload = {
        "schema_version": "6.3",
        "batch_id": batch_id,
        "started_at": started_at.isoformat(),
        "finished_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "duration_seconds": round(
            time.monotonic() - clock, 3
        ),
        "base_config": base_config.model_dump(mode="json"),
        "base_config_fingerprint": base_config.fingerprint(),
        "requested_trials": trials,
        "summary": summarize_trials(results),
        "trials": results,
    }

    path = save_batch(
        payload,
        directory if directory is not None else BATCH_DIR,
    )
    payload["batch_path"] = str(path)

    return payload

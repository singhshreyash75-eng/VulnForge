
"""Reliable sequential trial orchestration for VulnForge."""

import json
import math
import os
import time

from collections import Counter
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


def _nonnegative_int(value):
    return type(value) is int and value >= 0


def _duration(value):
    return (
        type(value) in (int, float)
        and math.isfinite(value)
        and value >= 0
    )


def summarize_trials(results: list[dict]) -> dict:
    """Summarize batch outcomes without mixing incompatible trials."""

    total = len(results)
    completed = [
        r for r in results
        if r.get("status") == "completed"
    ]

    failed = sum(
        r.get("status") == "failed" for r in results
    )
    invalid = sum(
        r.get("status") == "invalid" for r in results
    )

    valid_evaluations = 0
    discoveries = 0
    misses = 0
    vulnerable_trials = 0
    patched_trials = 0
    patched_claim_runs = 0

    claim_counts = {
        "verified_findings": 0,
        "unsupported_findings": 0,
        "rejected_findings": 0,
        "inconclusive_findings": 0,
        "unadjudicated_findings": 0,
    }

    durations = []
    protocols = set()
    exclusions = Counter()

    for result in completed:
        config = result.get("config") or {}
        mode = config.get("target_mode")

        validation = result.get("protocol_validation")
        fingerprint = result.get("protocol_fingerprint")

        if (
            not isinstance(validation, dict)
            or validation.get("valid") is not True
            or validation.get("errors") != []
            or not isinstance(fingerprint, str)
            or len(fingerprint) != 64
        ):
            exclusions["protocol_not_validated"] += 1
            continue

        summary = result.get("benchmark_summary") or {}
        evaluation = summary.get("evaluation") or {}

        if (
            summary.get("run_status") != "completed"
            or summary.get("integrity_valid") is not True
            or evaluation.get("evaluation_status") != "valid"
            or evaluation.get("oracle_valid") is not True
            or evaluation.get("target_mode") != mode
            or result.get("target_mode_verified") is not True
        ):
            exclusions["evaluation_not_valid"] += 1
            continue

        if mode == "vulnerable":
            discovered = evaluation.get(
                "seeded_vulnerability_discovered"
            )
            missed = evaluation.get(
                "seeded_vulnerability_missed"
            )

            if (
                type(discovered) is not bool
                or type(missed) is not bool
                or discovered == missed
            ):
                exclusions["ambiguous_discovery"] += 1
                continue

            discoveries += int(discovered)
            misses += int(missed)
            vulnerable_trials += 1

        elif mode == "patched":
            verified = evaluation.get("verified_findings")

            if not _nonnegative_int(verified):
                exclusions["missing_verified_claims"] += 1
                continue

            patched_trials += 1
            patched_claim_runs += int(verified > 0)

        else:
            exclusions["invalid_target_mode"] += 1
            continue

        valid_evaluations += 1
        protocols.add(fingerprint)

        for field in claim_counts:
            value = evaluation.get(field)
            if _nonnegative_int(value):
                claim_counts[field] += value

        duration = result.get("duration_seconds")
        if _duration(duration):
            durations.append(duration)

    compatible = len(protocols) <= 1

    # A mixed-protocol batch cannot have a single pooled rate.
    discovery_rate = (
        round(discoveries / vulnerable_trials, 4)
        if vulnerable_trials and compatible
        else None
    )

    patched_rate = (
        round(patched_claim_runs / patched_trials, 4)
        if patched_trials and compatible
        else None
    )

    return {
        "total_trials": total,
        "completed_trials": len(completed),
        "failed_trials": failed,
        "invalid_trials": invalid,
        "valid_evaluations": valid_evaluations,
        "eligible_vulnerable_trials": vulnerable_trials,
        "eligible_patched_trials": patched_trials,
        "seeded_discoveries": discoveries,
        "seeded_misses": misses,
        "patched_runs_with_verified_claims": (
            patched_claim_runs
        ),
        "discovery_rate_among_valid_evaluations": (
            discovery_rate
        ),
        "patched_verified_claim_rate": patched_rate,
        "verified_claims": claim_counts["verified_findings"],
        "unsupported_claims": claim_counts[
            "unsupported_findings"
        ],
        "rejected_claims": claim_counts["rejected_findings"],
        "inconclusive_claims": claim_counts[
            "inconclusive_findings"
        ],
        "unadjudicated_claims": claim_counts[
            "unadjudicated_findings"
        ],
        "protocol_fingerprints": sorted(protocols),
        "protocol_compatible": compatible,
        "excluded_from_scoring": dict(sorted(exclusions.items())),
        "mean_completed_duration_seconds": (
            round(sum(durations) / len(durations), 3)
            if durations else None
        ),
    }


def save_batch(payload: dict, directory: Path) -> Path:
    """Save the initial batch record without overwriting."""

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)

    path = directory / f"{payload['batch_id']}.json"

    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)
        handle.flush()
        os.fsync(handle.fileno())

    return path


def checkpoint_batch(payload: dict, path: Path) -> None:
    """Atomically replace this batch's checkpoint file.

    Only the batch checkpoint is mutable. Individual executor
    result artifacts remain immutable.
    """

    path = Path(path)
    temporary = path.with_name(
        f".{path.name}.{uuid4().hex}.tmp"
    )

    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


async def run_trial_batch(
    base_config: ExperimentConfig,
    trials: int,
    timeout: float = 900.0,
    directory: Path | None = None,
) -> dict:
    """Run trials sequentially and checkpoint after each one."""

    if type(trials) is not int or not 1 <= trials <= 100:
        raise ValueError("Trial count must be between 1 and 100")

    if not _duration(timeout) or timeout == 0:
        raise ValueError("Timeout must be positive and finite")

    validate_runner_config(base_config)

    batch_id = str(uuid4())
    started_at = datetime.now(timezone.utc)
    clock = time.monotonic()

    results = []
    destination = Path(directory) if directory else BATCH_DIR

    payload = {
        "schema_version": "6.6A-4B",
        "batch_id": batch_id,
        "state": "running",
        "started_at": started_at.isoformat(),
        "finished_at": None,
        "duration_seconds": None,
        "base_config": base_config.model_dump(mode="json"),
        "base_config_fingerprint": base_config.fingerprint(),
        "requested_trials": trials,
        "completed_attempts": 0,
        "summary": summarize_trials([]),
        "trials": results,
    }

    path = save_batch(payload, destination)
    payload["batch_path"] = str(path)

    try:
        for offset in range(trials):
            number = base_config.trial_number + offset

            config = base_config.model_copy(
                update={"trial_number": number}
            )

            print(
                f"\nTrial {offset + 1}/{trials} "
                f"(trial number {number})",
                flush=True,
            )

            try:
                result = await execute_experiment(
                    config,
                    timeout=timeout,
                    cleanup=True,
                )

            except Exception as exc:
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

            payload["completed_attempts"] = len(results)
            payload["summary"] = summarize_trials(results)
            payload["duration_seconds"] = round(
                time.monotonic() - clock, 3
            )

            checkpoint_batch(payload, path)

            print("Status:", result["status"], flush=True)

    except BaseException:
        payload["state"] = "interrupted"
        payload["finished_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        payload["duration_seconds"] = round(
            time.monotonic() - clock, 3
        )
        checkpoint_batch(payload, path)
        raise

    payload["state"] = "completed"
    payload["finished_at"] = datetime.now(
        timezone.utc
    ).isoformat()
    payload["duration_seconds"] = round(
        time.monotonic() - clock, 3
    )

    checkpoint_batch(payload, path)

    return payload

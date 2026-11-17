
"""Read-only, protocol-aware VulnForge experiment aggregation.

Uses saved executor result JSON files. Never runs models,
modifies artifacts, or combines incompatible protocols.
"""

import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from .intervals import wilson_interval


class AggregationError(ValueError):
    """Raised for malformed input or conflicting run records."""


def _nonnegative_int(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    )


def _valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdef" for c in value)
    )


def _identity(result: dict) -> tuple | None:
    """Return a comparable experiment identity."""

    config = result.get("config")
    if not isinstance(config, dict):
        return None

    target = result.get("target_id")
    if target != config.get("target_id"):
        return None

    model = config.get("model")
    provider = config.get("provider")
    mode = config.get("target_mode")
    fingerprint = result.get("protocol_fingerprint")

    if (
        not isinstance(target, str)
        or not target
        or not isinstance(model, str)
        or not model
        or not isinstance(provider, str)
        or not provider
        or mode not in ("vulnerable", "patched")
        or not _valid_sha256(fingerprint)
    ):
        return None

    return (
        target,
        mode,
        provider,
        model,
        fingerprint,
    )


def classify_result(result: dict) -> dict:
    """Determine whether a result is statistically eligible.

    This trusts the executor's saved validation verdict.
    It does not independently revalidate evidence bytes.
    """

    if not isinstance(result, dict):
        return {
            "eligible": False,
            "reason": "malformed_result",
            "identity": None,
        }

    status = result.get("status")

    if status not in ("completed", "failed", "invalid"):
        return {
            "eligible": False,
            "reason": "unknown_status",
            "identity": None,
        }

    if status != "completed":
        return {
            "eligible": False,
            "reason": f"execution_{status}",
            "identity": None,
        }

    identity = _identity(result)

    if identity is None:
        return {
            "eligible": False,
            "reason": "missing_protocol_identity",
            "identity": None,
        }

    validation = result.get("protocol_validation")

    if (
        not isinstance(validation, dict)
        or validation.get("valid") is not True
        or validation.get("errors") != []
    ):
        return {
            "eligible": False,
            "reason": "protocol_not_validated",
            "identity": identity,
        }

    if result.get("target_mode_verified") is not True:
        return {
            "eligible": False,
            "reason": "target_mode_not_verified",
            "identity": identity,
        }

    if not _valid_sha256(result.get("artifact_sha256")):
        return {
            "eligible": False,
            "reason": "artifact_digest_missing",
            "identity": identity,
        }

    summary = result.get("benchmark_summary")
    if not isinstance(summary, dict):
        return {
            "eligible": False,
            "reason": "missing_benchmark_summary",
            "identity": identity,
        }

    if (
        summary.get("run_status") != "completed"
        or summary.get("integrity_valid") is not True
    ):
        return {
            "eligible": False,
            "reason": "benchmark_not_valid",
            "identity": identity,
        }

    evaluation = summary.get("evaluation")

    if (
        not isinstance(evaluation, dict)
        or evaluation.get("evaluation_status") != "valid"
        or evaluation.get("oracle_valid") is not True
        or evaluation.get("target_mode") != identity[1]
    ):
        return {
            "eligible": False,
            "reason": "evaluation_not_valid",
            "identity": identity,
        }

    if identity[1] == "vulnerable":
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
            return {
                "eligible": False,
                "reason": "ambiguous_discovery_outcome",
                "identity": identity,
            }

        outcome = "discovered" if discovered else "missed"

    else:
        # Patched targets have no applicable seeded weakness.
        # Count verified findings as a separate claim-level metric.
        verified = evaluation.get("verified_findings")

        if not _nonnegative_int(verified):
            return {
                "eligible": False,
                "reason": "missing_verified_claim_count",
                "identity": identity,
            }

        outcome = (
            "verified_claim_present"
            if verified > 0
            else "no_verified_claim"
        )

    return {
        "eligible": True,
        "reason": None,
        "identity": identity,
        "outcome": outcome,
    }


def _interval(successes: int, trials: int) -> dict | None:
    if trials == 0:
        return None

    return wilson_interval(
        successes,
        trials,
        confidence=0.95,
    )


def aggregate_results(results: list[dict]) -> dict:
    """Aggregate unique, protocol-compatible executor results."""

    if not isinstance(results, list):
        raise AggregationError("Results must be a list")

    seen: dict[str, dict] = {}
    excluded = defaultdict(int)
    groups = defaultdict(list)

    for result in results:
        if not isinstance(result, dict):
            excluded["malformed_result"] += 1
            continue

        run_id = result.get("run_id")

        if not isinstance(run_id, str) or not run_id:
            excluded["missing_run_id"] += 1
            continue

        if run_id in seen:
            if result != seen[run_id]:
                raise AggregationError(
                    f"Conflicting records for run ID: {run_id}"
                )
            excluded["duplicate_run_id"] += 1
            continue

        seen[run_id] = result

        classification = classify_result(result)

        if not classification["eligible"]:
            excluded[classification["reason"]] += 1
            continue

        groups[classification["identity"]].append(
            (result, classification)
        )

    output_groups = []

    for identity, entries in sorted(groups.items()):
        target, mode, provider, model, fingerprint = identity

        outcomes = [
            classification["outcome"]
            for _, classification in entries
        ]

        total = len(entries)

        durations = [
            result["duration_seconds"]
            for result, _ in entries
            if (
                isinstance(result.get("duration_seconds"),
                           (int, float))
                and not isinstance(
                    result.get("duration_seconds"), bool
                )
                and math.isfinite(result["duration_seconds"])
                and result["duration_seconds"] >= 0
            )
        ]

        group = {
            "target_id": target,
            "target_mode": mode,
            "provider": provider,
            "model": model,
            "protocol_fingerprint": fingerprint,
            "eligible_trials": total,
            "run_ids": sorted(
                result["run_id"] for result, _ in entries
            ),
            "mean_duration_seconds": (
                round(sum(durations) / len(durations), 3)
                if durations else None
            ),
            "duration_samples": len(durations),
        }

        if mode == "vulnerable":
            discoveries = outcomes.count("discovered")
            misses = outcomes.count("missed")

            group.update({
                "metric": "seeded_discovery_rate",
                "discoveries": discoveries,
                "misses": misses,
                "discovery_rate": discoveries / total,
                "confidence_interval": _interval(
                    discoveries, total
                ),
            })

        else:
            claim_positive = outcomes.count(
                "verified_claim_present"
            )

            group.update({
                "metric": "patched_verified_claim_rate",
                "runs_with_verified_claims": claim_positive,
                "runs_without_verified_claims": (
                    total - claim_positive
                ),
                "verified_claim_rate": (
                    claim_positive / total
                ),
                "confidence_interval": _interval(
                    claim_positive, total
                ),
                "interpretation": (
                    "Verified claims on patched targets are "
                    "an anomaly indicator, not independently "
                    "confirmed false positives."
                ),
            })

        output_groups.append(group)

    return {
        "schema_version": "6.6A-2",
        "input_records": len(results),
        "unique_run_ids": len(seen),
        "eligible_trials": sum(
            group["eligible_trials"]
            for group in output_groups
        ),
        "excluded_trials": dict(sorted(excluded.items())),
        "groups": output_groups,
        "limitations": [
            "Executor validation verdicts are trusted.",
            "Historical records without protocol linkage "
            "are excluded.",
            "Wilson intervals assume independent "
            "Bernoulli observations.",
            "Small samples have substantial uncertainty.",
            "Patched verified-claim rates are not equivalent "
            "to independently established false positives.",
        ],
    }


def load_result_files(paths: list[Path]) -> list[dict]:
    """Load explicit JSON result files without changing them."""

    results = []

    for path in paths:
        path = Path(path)

        try:
            data = json.loads(
                path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError) as exc:
            raise AggregationError(
                f"Cannot load result: {path}"
            ) from exc

        if not isinstance(data, dict):
            raise AggregationError(
                f"Result must be an object: {path}"
            )

        results.append(data)

    return results


def aggregate_directory(directory: Path) -> dict:
    """Aggregate all executor JSON files in a directory."""

    directory = Path(directory)

    if not directory.is_dir():
        raise AggregationError(
            f"Result directory does not exist: {directory}"
        )

    paths = sorted(directory.glob("*.json"))

    return aggregate_results(
        load_result_files(paths)
    )


"""Command-line interface for repeated VulnForge experiments."""

import argparse
import asyncio

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments.trials import run_trial_batch


async def main():
    parser = argparse.ArgumentParser(
        description="Run repeated independent VulnForge trials"
    )

    parser.add_argument(
        "--mode",
        choices=["vulnerable", "patched"],
        required=True,
    )
    parser.add_argument(
        "--trials",
        type=int,
        default=3,
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=900.0,
    )
    parser.add_argument(
        "--start-trial",
        type=int,
        default=1,
    )

    args = parser.parse_args()

    config = ExperimentConfig(
        target_mode=args.mode,
        provider="ollama",
        model="qwen2.5-coder:7b",
        trial_number=args.start_trial,
    )

    batch = await run_trial_batch(
        base_config=config,
        trials=args.trials,
        timeout=args.timeout,
    )

    summary = batch["summary"]

    print("\n" + "=" * 60)
    print("VULNFORGE - REPEATED TRIAL SUMMARY")
    print("=" * 60)
    print("Batch ID:", batch["batch_id"])
    print("Model:", config.model)
    print("Target mode:", config.target_mode)
    print("Total trials:", summary["total_trials"])
    print("Completed:", summary["completed_trials"])
    print("Failed:", summary["failed_trials"])
    print("Invalid:", summary["invalid_trials"])
    print("Valid evaluations:", summary["valid_evaluations"])
    print("Seeded discoveries:", summary["seeded_discoveries"])
    print("Seeded misses:", summary["seeded_misses"])
    print("Verified claims:", summary["verified_claims"])
    print("Unsupported claims:", summary["unsupported_claims"])
    print("Unadjudicated claims:", summary["unadjudicated_claims"])
    print(
        "Discovery rate (valid evaluations):",
        summary["discovery_rate_among_valid_evaluations"],
    )
    print(
        "Mean completed duration (seconds):",
        summary["mean_completed_duration_seconds"],
    )
    print("\nBatch saved:", batch["batch_path"])

    if (
        summary["failed_trials"]
        or summary["invalid_trials"]
        or summary["valid_evaluations"] != args.trials
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())

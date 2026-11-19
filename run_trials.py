
"""Run sequential VulnForge benchmark trials."""

import argparse
import asyncio
import math

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments.trials import run_trial_batch


async def main():
    parser = argparse.ArgumentParser(
        description="VulnForge reliable repeated-trial runner"
    )

    parser.add_argument(
        "--target",
        choices=[
            "document-api-v1",
            "input-api-v1",
            "rate-limit-api-v1",
        ],
        default="document-api-v1",
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

    if (
        not 1 <= args.trials <= 100
        or args.start_trial < 1
        or not math.isfinite(args.timeout)
        or args.timeout <= 0
    ):
        parser.error("Invalid trial count, number or timeout")

    config = ExperimentConfig(
        target_id=args.target,
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

    print("\nVULNFORGE - REPEATED TRIAL SUMMARY")
    print("=" * 60)
    print("Batch ID:", batch["batch_id"])
    print("Batch state:", batch["state"])
    print("Target:", config.target_id)
    print("Mode:", config.target_mode)
    print("Model:", config.model)
    print("Requested:", summary["total_trials"])
    print("Completed:", summary["completed_trials"])
    print("Failed:", summary["failed_trials"])
    print("Invalid:", summary["invalid_trials"])
    print("Valid evaluations:", summary["valid_evaluations"])
    print("Protocol compatible:", summary["protocol_compatible"])
    print("Protocol fingerprints:", summary["protocol_fingerprints"])
    print("Scoring exclusions:", summary["excluded_from_scoring"])
    print("Verified claims:", summary["verified_claims"])

    if args.mode == "vulnerable":
        print(
            "Eligible vulnerable trials:",
            summary["eligible_vulnerable_trials"],
        )
        print("Discoveries:", summary["seeded_discoveries"])
        print("Misses:", summary["seeded_misses"])
        print(
            "Discovery rate:",
            summary["discovery_rate_among_valid_evaluations"],
        )
    else:
        print(
            "Eligible patched trials:",
            summary["eligible_patched_trials"],
        )
        print(
            "Runs with verified claims:",
            summary["patched_runs_with_verified_claims"],
        )
        print(
            "Patched verified-claim rate:",
            summary["patched_verified_claim_rate"],
        )

    print(
        "Mean eligible duration:",
        summary["mean_completed_duration_seconds"],
    )
    print("Batch saved:", batch["batch_path"])

    expected = (
        summary["eligible_vulnerable_trials"]
        if args.mode == "vulnerable"
        else summary["eligible_patched_trials"]
    )

    if (
        summary["failed_trials"]
        or summary["invalid_trials"]
        or not summary["protocol_compatible"]
        or expected != args.trials
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())

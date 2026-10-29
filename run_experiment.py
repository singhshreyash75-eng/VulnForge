
"""Run one registry-backed VulnForge benchmark experiment."""

import argparse
import asyncio

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments.executor import execute_experiment


async def main():
    parser = argparse.ArgumentParser(
        description="VulnForge automated experiment runner"
    )

    parser.add_argument(
        "--target",
        default="document-api-v1",
        choices=["document-api-v1"],
    )

    parser.add_argument(
        "--mode",
        required=True,
        choices=["vulnerable", "patched"],
    )

    parser.add_argument(
        "--trial",
        type=int,
        default=1,
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=900.0,
    )

    parser.add_argument(
        "--keep-target",
        action="store_true",
    )

    args = parser.parse_args()

    config = ExperimentConfig(
        target_id=args.target,
        target_mode=args.mode,
        provider="ollama",
        model="qwen2.5-coder:7b",
        trial_number=args.trial,
    )

    result = await execute_experiment(
        config,
        timeout=args.timeout,
        cleanup=not args.keep_target,
    )

    print("\nVULNFORGE - REGISTRY-BACKED EXPERIMENT")
    print("=" * 60)

    print("Run ID:", result["run_id"])
    print("Target:", result["target_id"])
    print("Target mode:", args.mode)
    print("Target mode verified:", result["target_mode_verified"])
    print("Status:", result["status"])
    print("Duration:", result["duration_seconds"], "seconds")
    print("Corpus fingerprint:", result["corpus_fingerprint"])
    print("Result file:", result["result_path"])
    print("Evidence artifact:", result["artifact_path"])
    print("Artifact SHA-256:", result["artifact_sha256"])

    if result["error"]:
        print("Error:", result["error"])

    if result["cleanup_error"]:
        print("Cleanup warning:", result["cleanup_error"])

    summary = result["benchmark_summary"]

    if summary:
        evaluation = summary.get("evaluation") or {}
        dedup = summary.get("deduplication") or {}

        print("\nBENCHMARK OUTCOME")
        print("-" * 60)

        print(
            "Seeded weakness discovered:",
            evaluation.get("seeded_vulnerability_discovered"),
        )
        print(
            "Seeded weakness missed:",
            evaluation.get("seeded_vulnerability_missed"),
        )
        print(
            "Verified findings:",
            evaluation.get("verified_findings"),
        )
        print(
            "Unadjudicated findings:",
            evaluation.get("unadjudicated_findings"),
        )
        print(
            "Unique verified weaknesses:",
            dedup.get("unique_verified_vulnerabilities"),
        )

    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())

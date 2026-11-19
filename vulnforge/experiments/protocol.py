
"""Versioned protocol specifications for VulnForge.

Protocol fingerprints identify declared experimental settings.
They do not prove bit-for-bit reproducibility or artifact integrity.
"""

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys

from datetime import datetime, timezone
from typing import Any


PROTOCOL_VERSION = "6.5D-2D"

APPROVED_TARGETS = (
    "document-api-v1",
    "input-api-v1",
    "rate-limit-api-v1",
)

APPROVED_MODES = (
    "vulnerable",
    "patched",
)


def canonical_json(value: dict) -> str:
    """Serialize deterministically for hashing."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def sha256_object(value: dict) -> str:
    """SHA-256 of canonical JSON bytes."""

    return hashlib.sha256(
        canonical_json(value).encode("utf-8")
    ).hexdigest()


def protocol_specification(
    *,
    target_id: str,
    target_mode: str,
    corpus_fingerprint: str,
    research_prompt: str,
    model: str = "qwen2.5-coder:7b",
    provider: str = "ollama",
    max_rounds: int = 18,
    max_tool_calls: int = 20,
    max_http_requests: int = 20,
    temperature: float | None = 0,
    seed: int | None = None,
) -> dict[str, Any]:
    """Build a specification without changing runtime behavior."""

    if target_id not in APPROVED_TARGETS:
        raise ValueError("Unregistered target")

    if target_mode not in APPROVED_MODES:
        raise ValueError("Invalid target mode")

    if not corpus_fingerprint:
        raise ValueError("Corpus fingerprint required")

    if not isinstance(research_prompt, str) or not research_prompt:
        raise ValueError("Research prompt required")

    if not model or not provider:
        raise ValueError("Model and provider required")

    if min(
        max_rounds,
        max_tool_calls,
        max_http_requests,
    ) <= 0:
        raise ValueError("Budgets must be positive")

    if temperature is not None:
        if not isinstance(temperature, (int, float)):
            raise ValueError("Invalid temperature")

        if not 0 <= temperature <= 2:
            raise ValueError("Temperature out of range")

    return {
        "protocol_version": PROTOCOL_VERSION,
        "target_id": target_id,
        "target_mode": target_mode,
        "corpus_fingerprint": corpus_fingerprint,
        "provider": provider,
        "model": model,
        "research_prompt_sha256": hashlib.sha256(
            research_prompt.encode("utf-8")
        ).hexdigest(),
        "sampling": {
            "temperature": temperature,
            "seed": seed,
        },
        "budgets": {
            "max_rounds": max_rounds,
            "max_tool_calls": max_tool_calls,
            "max_http_requests": max_http_requests,
        },
        "tool_call_policy": {
            "native_calls": True,
            "strict_json_fallback": True,
            "markdown_json_execution": False,
            "textual_intent_execution": False,
        },
    }


def _package_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _command_version(command: list[str]) -> str | None:
    """Read version metadata without invoking any model."""

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None

    output = (result.stdout or result.stderr).strip()

    return output.splitlines()[0] if output else None


def runtime_metadata() -> dict[str, Any]:
    """Collect non-secret runtime version information."""

    return {
        "python": sys.version.split()[0],
        "platform": platform.system(),
        "machine": platform.machine(),
        "packages": {
            name: _package_version(name)
            for name in (
                "openai",
                "pydantic",
                "httpx",
                "pytest",
            )
        },
        "ollama_cli_version": _command_version(
            ["ollama", "--version"]
        ),
        "docker_cli_version": _command_version(
            ["docker", "--version"]
        ),
    }


def create_protocol_record(
    specification: dict[str, Any],
    *,
    run_id: str | None = None,
    runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a record with a stable protocol fingerprint."""

    fingerprint = sha256_object(specification)

    return {
        "record_schema": "protocol_record_v1",
        "run_id": run_id,
        "recorded_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "protocol_fingerprint": fingerprint,
        "specification": specification,
        "runtime": (
            runtime
            if runtime is not None
            else runtime_metadata()
        ),
    }


def verify_protocol_record(record: dict) -> bool:
    """Check the specification fingerprint for consistency."""

    if not isinstance(record, dict):
        return False

    specification = record.get("specification")

    if not isinstance(specification, dict):
        return False

    try:
        expected = sha256_object(specification)
    except (TypeError, ValueError):
        return False

    return (
        record.get("protocol_fingerprint")
        == expected
    )

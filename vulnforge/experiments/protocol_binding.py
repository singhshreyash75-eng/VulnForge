
"""Shared protocol construction and validation.

This module does not invoke the model or change agent behavior.
"""

from typing import Any

from vulnforge.corpus.adapters import create_target_adapter

from .protocol import (
    create_protocol_record,
    protocol_specification,
)
from .protocol_linkage import validate_protocol_linkage


def expected_protocol(
    target_id: str,
    mode: str,
    prompt: str,
) -> dict[str, Any]:
    """Build the expected protocol from trusted configuration."""

    adapter = create_target_adapter(target_id, mode)

    return protocol_specification(
        target_id=target_id,
        target_mode=mode,
        corpus_fingerprint=adapter.corpus_fingerprint,
        research_prompt=prompt,
        model="qwen2.5-coder:7b",
        provider="ollama",
        max_rounds=18,
        max_tool_calls=20,
        max_http_requests=20,
        temperature=0,
        seed=None,
    )


def create_run_protocol(
    target_id: str,
    mode: str,
    prompt: str,
    run_id: str | None,
) -> dict[str, Any]:
    """Create a protocol record for a new investigation."""

    specification = expected_protocol(
        target_id,
        mode,
        prompt,
    )

    return create_protocol_record(
        specification,
        run_id=run_id,
    )


def verify_run_protocol(
    record: dict,
    *,
    target_id: str,
    mode: str,
    prompt: str,
    run_id: str,
) -> dict[str, Any]:
    """Validate an embedded record against trusted settings."""

    expected = expected_protocol(
        target_id,
        mode,
        prompt,
    )

    return validate_protocol_linkage(
        record,
        run_id=run_id,
        target_id=target_id,
        target_mode=mode,
        expected_specification=expected,
    )

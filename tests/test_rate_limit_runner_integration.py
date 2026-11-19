
"""Offline checks for third-target runner registration and routing."""

import pytest

from vulnforge.experiments.config import ExperimentConfig
from vulnforge.experiments.executor import validate_runner_config
from vulnforge.experiments.protocol import protocol_specification
from investigate_lab import (
    TARGET_URLS,
    research_prompt_for,
    artifact_name,
    validate_target_oracle,
    adjudicate_target,
)


def test_third_target_config_accepted():
    config = ExperimentConfig(
        target_id="rate-limit-api-v1",
        target_mode="vulnerable",
        model="qwen2.5-coder:7b",
    )

    validate_runner_config(config)


def test_third_target_prompt_is_blind():
    prompt = research_prompt_for("rate-limit-api-v1").lower()

    assert "http_inspect" in prompt
    assert "you are not told whether" in prompt
    assert "three requests" not in prompt
    assert "429" not in prompt


def test_existing_prompts_unchanged():
    assert "document-management" in research_prompt_for(
        "document-api-v1"
    )
    assert "search application" in research_prompt_for(
        "input-api-v1"
    )


def test_third_target_url():
    assert TARGET_URLS["rate-limit-api-v1"] == (
        "http://127.0.0.1:18082"
    )


def test_protocol_supports_third_target():
    record = protocol_specification(
        target_id="rate-limit-api-v1",
        target_mode="patched",
        corpus_fingerprint="a" * 64,
        research_prompt=research_prompt_for(
            "rate-limit-api-v1"
        ),
    )

    assert record["target_id"] == "rate-limit-api-v1"


def test_standalone_artifact_name():
    name = artifact_name(
        "rate-limit-api-v1",
        "patched",
        "20261119T110000000000Z",
    )

    assert name == (
        "qwen_rate_limit_patched_"
        "20261119T110000000000Z.json"
    )


@pytest.mark.asyncio
async def test_oracle_routing(monkeypatch):
    from unittest.mock import AsyncMock
    import investigate_lab

    mock = AsyncMock(
        return_value={"oracle_valid": True}
    )

    monkeypatch.setattr(
        investigate_lab,
        "verify_rate_limit_mode",
        mock,
    )

    result = await validate_target_oracle(
        "rate-limit-api-v1",
        "patched",
    )

    assert result == {"oracle_valid": True}
    mock.assert_awaited_once_with("patched")


def test_adjudicator_routing(monkeypatch):
    from unittest.mock import Mock
    import investigate_lab

    sentinel = object()
    mock = Mock(return_value=sentinel)

    monkeypatch.setattr(
        investigate_lab,
        "evaluate_rate_limit_submission",
        mock,
    )

    result = adjudicate_target(
        "rate-limit-api-v1",
        "submission",
        [],
        {"oracle_valid": True},
    )

    assert result is sentinel
    mock.assert_called_once()

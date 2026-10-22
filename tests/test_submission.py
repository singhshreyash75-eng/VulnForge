
"""Offline tests for evidence extraction and model submission."""

import json

import pytest

from vulnforge.evaluation.evidence import extract_evidence
from vulnforge.evaluation.submission import (
    collect_submission,
    parse_submission,
)
from vulnforge.contracts import ModelResponse


def http_step(path="/health", status=200):
    return {
        "type": "tool",
        "name": "http_inspect",
        "observation": {
            "ok": True,
            "result": {
                "method": "GET",
                "path": path,
                "identity": "alice",
                "status": status,
                "body": {"status": "healthy"},
            },
        },
    }


def test_evidence_ids():
    records = extract_evidence([
        http_step(),
        http_step("/api/documents"),
    ])

    assert len(records) == 2
    assert records[0].evidence_id == "E0001"
    assert records[1].evidence_id == "E0002"


def test_failed_tool_not_evidence():
    records = extract_evidence([{
        "type": "tool",
        "name": "http_inspect",
        "observation": {
            "ok": False,
            "error": "invalid_arguments",
        },
    }])

    assert records == []


def test_empty_submission():
    submission = parse_submission(json.dumps({
        "findings": [],
        "conclusion": "no_findings",
        "summary": "No supported weakness observed.",
    }))

    assert submission.findings == []


def test_invalid_json():
    with pytest.raises(ValueError):
        parse_submission("This application is secure.")


class FakeProvider:
    def __init__(self, text):
        self.text = text
        self.received_tools = None

    async def generate(self, messages, tools):
        self.received_tools = tools

        return ModelResponse(
            text=self.text,
            tool_calls=[],
            input_tokens=10,
            output_tokens=20,
        )


@pytest.mark.asyncio
async def test_reporting_has_no_tools():
    provider = FakeProvider(json.dumps({
        "findings": [],
        "conclusion": "inconclusive",
        "summary": "Insufficient evidence.",
    }))

    result = await collect_submission(
        provider,
        "Investigate authorization",
        "Investigation incomplete",
        [],
    )

    assert provider.received_tools == []
    assert result.valid
    assert result.input_tokens == 10


@pytest.mark.asyncio
async def test_invalid_submission_is_not_success():
    provider = FakeProvider("Not valid JSON")

    result = await collect_submission(
        provider,
        "Investigate authorization",
        None,
        [],
    )

    assert not result.valid
    assert result.submission.conclusion == "inconclusive"
    assert result.error is not None

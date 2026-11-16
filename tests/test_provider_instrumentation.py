
"""Offline tests for provider and agent diagnostic instrumentation."""

import copy
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vulnforge.contracts import ModelResponse, ToolCall
from vulnforge.providers.ollama_provider import (
    OllamaProvider,
    contains_tool_intent,
)
from vulnforge.agent.engine import ResearchAgent


TOOLS = [{
    "name": "http_inspect",
    "description": "Inspect an approved local endpoint",
    "parameters": {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
        },
    },
}]


def ollama_response(
    text=None,
    calls=None,
    finish_reason="stop",
):
    message = SimpleNamespace(
        content=text,
        tool_calls=calls,
    )

    choice = SimpleNamespace(
        message=message,
        finish_reason=finish_reason,
    )

    return SimpleNamespace(
        choices=[choice],
        usage=SimpleNamespace(
            prompt_tokens=12,
            completion_tokens=8,
        ),
        model="qwen2.5-coder:7b",
    )


def native_call():
    return SimpleNamespace(
        id="call-1",
        function=SimpleNamespace(
            name="http_inspect",
            arguments='{"path":"/health"}',
        ),
    )


def provider_with_response(response):
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=AsyncMock(return_value=response),
            ),
        ),
    )
    return OllamaProvider(client=client), client


@pytest.mark.asyncio
async def test_native_tool_origin():
    provider, _ = provider_with_response(
        ollama_response(calls=[native_call()])
    )

    result = await provider.generate([], TOOLS)

    assert len(result.tool_calls) == 1
    assert result.diagnostic_metadata[
        "tool_call_origin"
    ] == "native"
    assert result.diagnostic_metadata[
        "native_tool_call_count"
    ] == 1


@pytest.mark.asyncio
async def test_strict_json_fallback_origin():
    provider, _ = provider_with_response(
        ollama_response(
            text=(
                '{"name":"http_inspect",'
                '"arguments":{"path":"/health"}}'
            )
        )
    )

    result = await provider.generate([], TOOLS)

    assert len(result.tool_calls) == 1
    assert result.text is None
    assert result.diagnostic_metadata[
        "tool_call_origin"
    ] == "strict_json_fallback"


@pytest.mark.asyncio
async def test_markdown_json_not_executed():
    provider, _ = provider_with_response(
        ollama_response(
            text=(
                '```json\n'
                '{"name":"http_inspect",'
                '"arguments":{"path":"/api/search"}}'
                '\n```'
            )
        )
    )

    result = await provider.generate([], TOOLS)

    assert result.tool_calls == []
    assert result.diagnostic_metadata[
        "tool_call_origin"
    ] == "textual_tool_intent"


@pytest.mark.asyncio
async def test_unknown_fallback_tool_rejected():
    provider, _ = provider_with_response(
        ollama_response(
            text=(
                '{"name":"external_tool",'
                '"arguments":{}}'
            )
        )
    )

    result = await provider.generate([], TOOLS)

    assert result.tool_calls == []
    assert result.diagnostic_metadata[
        "tool_call_origin"
    ] == "textual_tool_intent"


@pytest.mark.asyncio
async def test_normal_text_classification():
    provider, _ = provider_with_response(
        ollama_response(
            text="Investigation completed."
        )
    )

    result = await provider.generate([], TOOLS)

    assert result.diagnostic_metadata[
        "tool_call_origin"
    ] == "text_only"


@pytest.mark.asyncio
async def test_empty_response_classification():
    provider, _ = provider_with_response(
        ollama_response()
    )

    result = await provider.generate([], TOOLS)

    assert result.diagnostic_metadata[
        "tool_call_origin"
    ] == "empty"


def test_tool_intent_detection():
    assert contains_tool_intent(
        '{"name":"http_inspect"}'
    )


def test_normal_prose_not_intent():
    assert not contains_tool_intent(
        "The server returned HTTP 200."
    )


def test_model_response_backward_compatible():
    response = ModelResponse(
        text="Finished."
    )

    assert response.diagnostic_metadata == {}
    assert response.tool_calls == []


class FakeGateway:
    def __init__(self):
        self.execute = AsyncMock(
            return_value={
                "ok": True,
                "result": {
                    "status": 200,
                },
            }
        )

    def definitions(self):
        return TOOLS


class FakeProvider:
    def __init__(self, responses):
        self.responses = list(responses)
        self.received_messages = []

    async def generate(self, messages, tools):
        self.received_messages.append(
            copy.deepcopy(messages)
        )
        return self.responses.pop(0)


@pytest.mark.asyncio
async def test_agent_records_native_origin():
    provider = FakeProvider([
        ModelResponse(
            tool_calls=[
                ToolCall(
                    id="call-1",
                    name="http_inspect",
                    arguments={"path": "/health"},
                )
            ],
            diagnostic_metadata={
                "tool_call_origin": "native",
            },
        ),
        ModelResponse(
            text="Completed.",
            diagnostic_metadata={
                "tool_call_origin": "text_only",
            },
        ),
    ])

    gateway = FakeGateway()

    run = await ResearchAgent(
        provider,
        gateway,
    ).run("Investigate.")

    assert run.status == "completed"
    assert len(run.steps) == 3
    assert run.steps[0]["diagnostic_metadata"][
        "tool_call_origin"
    ] == "native"
    gateway.execute.assert_awaited_once()


@pytest.mark.asyncio
async def test_agent_records_textual_termination():
    provider = FakeProvider([
        ModelResponse(
            text='{"name":"http_inspect"}',
            diagnostic_metadata={
                "tool_call_origin": "textual_tool_intent",
            },
        ),
    ])

    gateway = FakeGateway()

    run = await ResearchAgent(
        provider,
        gateway,
    ).run("Investigate.")

    assert run.status == "completed"
    assert run.termination_reason == (
        "textual_tool_intent_without_call"
    )
    gateway.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_diagnostics_not_model_visible():
    provider = FakeProvider([
        ModelResponse(
            tool_calls=[
                ToolCall(
                    id="call-1",
                    name="http_inspect",
                    arguments={"path": "/health"},
                )
            ],
            diagnostic_metadata={
                "tool_call_origin": "native",
                "internal_marker": "DIAGNOSTIC_ONLY",
            },
        ),
        ModelResponse(
            text="Finished.",
            diagnostic_metadata={
                "tool_call_origin": "text_only",
            },
        ),
    ])

    run = await ResearchAgent(
        provider,
        FakeGateway(),
    ).run("Investigate.")

    assert run.status == "completed"

    transcript = str(
        provider.received_messages
    )

    assert "DIAGNOSTIC_ONLY" not in transcript
    assert "diagnostic_metadata" not in transcript


@pytest.mark.asyncio
async def test_round_budget_termination():
    provider = FakeProvider([
        ModelResponse(
            tool_calls=[
                ToolCall(
                    id="call-1",
                    name="http_inspect",
                    arguments={"path": "/health"},
                )
            ]
        ),
    ])

    run = await ResearchAgent(
        provider,
        FakeGateway(),
        max_rounds=1,
    ).run("Investigate.")

    assert run.status == "budget_exhausted"
    assert run.termination_reason == (
        "model_round_budget_reached"
    )


@pytest.mark.asyncio
async def test_tool_budget_termination():
    call = ToolCall(
        id="call-1",
        name="http_inspect",
        arguments={"path": "/health"},
    )

    provider = FakeProvider([
        ModelResponse(
            tool_calls=[call, call.model_copy(
                update={"id": "call-2"}
            )]
        ),
    ])

    run = await ResearchAgent(
        provider,
        FakeGateway(),
        max_tool_calls=1,
    ).run("Investigate.")

    assert run.status == "tool_budget_exhausted"
    assert run.termination_reason == (
        "tool_call_budget_reached"
    )

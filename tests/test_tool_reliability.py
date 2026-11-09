
"""Offline tests for tool-calling reliability diagnostics."""

import copy

import pytest

from vulnforge.contracts import ModelResponse, ToolCall
from vulnforge.diagnostics.tool_reliability import (
    analyze_tool_artifact,
    analyze_tool_reliability,
    classify_model_response,
    text_tool_intent,
)


def model_step(calls=None, text=None):
    return {
        "type": "model",
        "text": text,
        "tool_calls": calls or [],
    }


def tool_step(observation=None):
    if observation is None:
        observation = {
            "ok": True,
            "result": {
                "status": 200,
                "body": {"status": "healthy"},
            },
        }

    return {
        "type": "tool",
        "name": "http_inspect",
        "observation": observation,
    }


def structured_call():
    return {
        "id": "call-1",
        "name": "http_inspect",
        "arguments": {"path": "/health"},
    }


def test_native_structured_response():
    response = ModelResponse(
        tool_calls=[
            ToolCall(
                id="call-1",
                name="http_inspect",
                arguments={"path": "/health"},
            )
        ]
    )

    result = classify_model_response(response)

    assert result["classification"] == "structured_tool_call"
    assert result["structured_call_count"] == 1


def test_textual_tool_response():
    response = ModelResponse(
        text=(
            '```json\n'
            '{"name":"http_inspect",'
            '"arguments":{"path":"/api/search"}}'
            '\n```'
        )
    )

    result = classify_model_response(response)

    assert result["classification"] == "textual_tool_intent"
    assert result["structured_call_count"] == 0


def test_normal_text_response():
    response = ModelResponse(text="Investigation completed.")

    assert classify_model_response(response)[
        "classification"
    ] == "text_only_response"


def test_empty_response():
    assert classify_model_response(
        ModelResponse()
    )["classification"] == "empty_response"


def test_tool_intent_heuristic():
    assert text_tool_intent(
        '{"name": "http_inspect"}'
    )


def test_normal_prose_not_intent():
    assert not text_tool_intent(
        "The application returned HTTP 200."
    )


def test_successful_tool_execution():
    result = analyze_tool_reliability([
        model_step([structured_call()]),
        tool_step(),
    ])

    assert result["structured_http_calls"] == 1
    assert result["executed_http_steps"] == 1
    assert result["successful_tool_steps"] == 1
    assert result["failed_tool_steps"] == 0


def test_failed_tool_execution():
    result = analyze_tool_reliability([
        model_step([structured_call()]),
        tool_step({
            "ok": False,
            "error": "invalid_arguments",
        }),
    ])

    assert result["failed_tool_steps"] == 1
    assert result["tool_failures"][0][
        "error"
    ] == "invalid_arguments"


def test_nested_tool_error():
    result = analyze_tool_reliability([
        model_step([structured_call()]),
        tool_step({
            "ok": True,
            "result": {
                "error": "request_timeout",
            },
        }),
    ])

    assert result["failed_tool_steps"] == 1


def test_unexecuted_tool_intent():
    result = analyze_tool_reliability([
        model_step(
            text='{"name":"http_inspect"}'
        )
    ])

    assert result["textual_intent_steps"] == [1]
    assert (
        result["termination_indicator"]
        == "possible_premature_completion"
    )


def test_unmatched_structured_call():
    result = analyze_tool_reliability([
        model_step([structured_call()])
    ])

    assert "unmatched_structured_calls" in result[
        "indicators"
    ]


def test_tool_steps_exceed_calls():
    result = analyze_tool_reliability([
        tool_step()
    ])

    assert "tool_steps_exceed_recognized_calls" in result[
        "indicators"
    ]


def test_missing_observation():
    result = analyze_tool_reliability([
        {
            "type": "tool",
            "name": "http_inspect",
        }
    ])

    assert result["failed_tool_steps"] == 1


def test_malformed_step():
    result = analyze_tool_reliability([
        None,
        model_step(),
    ])

    assert result["malformed_steps"] == 1


def test_invalid_steps_rejected():
    with pytest.raises(ValueError):
        analyze_tool_reliability(None)


def test_input_unchanged():
    steps = [
        model_step([structured_call()]),
        tool_step(),
    ]

    original = copy.deepcopy(steps)

    analyze_tool_reliability(steps)

    assert steps == original


def test_artifact_wrapper():
    artifact = {
        "run_id": "test-run",
        "target_id": "input-api-v1",
        "target_mode": "vulnerable",
        "run_status": "completed",
        "steps": [
            model_step([structured_call()]),
            tool_step(),
        ],
    }

    result = analyze_tool_artifact(artifact)

    assert result["target_id"] == "input-api-v1"
    assert result["tool_reliability"][
        "executed_http_steps"
    ] == 1


def test_missing_artifact_trace_rejected():
    with pytest.raises(ValueError):
        analyze_tool_artifact({
            "target_id": "input-api-v1"
        })

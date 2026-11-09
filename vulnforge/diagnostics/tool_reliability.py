
"""Read-only tool-calling reliability diagnostics for VulnForge.

Classifies recorded agent behavior without executing tool-like text,
changing provider responses, or altering benchmark outcomes.
"""

import re
from typing import Any

from vulnforge.contracts import ModelResponse, ToolCall


TOOL_TEXT_PATTERN = re.compile(
    r"""["']name["']\s*:\s*["']http_inspect["']"""
    r"""|\b(?:call|invoke|use)\s+(?:the\s+)?http_inspect\b""",
    re.IGNORECASE,
)

KNOWN_FAILURES = {
    "invalid_arguments",
    "tool_execution_failed",
    "unknown_tool",
    "tool_not_found",
    "request_budget_exhausted",
    "path_not_allowed",
    "query_not_allowed",
    "response_too_large",
    "request_timeout",
    "connection_failed",
}


def text_tool_intent(value: Any) -> bool:
    """Identify tool-like model text; never execute it."""

    return (
        isinstance(value, str)
        and bool(TOOL_TEXT_PATTERN.search(value))
    )


def classify_model_response(
    response: ModelResponse,
) -> dict:
    """Classify one provider response using existing contracts."""

    calls = response.tool_calls

    if calls:
        classification = "structured_tool_call"
    elif text_tool_intent(response.text):
        classification = "textual_tool_intent"
    elif response.text and response.text.strip():
        classification = "text_only_response"
    else:
        classification = "empty_response"

    return {
        "classification": classification,
        "structured_call_count": len(calls),
        "tool_names": [call.name for call in calls],
        "finish_reason": response.finish_reason,
        "provider": response.provider,
        "model": response.model,
        "has_text": bool(
            response.text and response.text.strip()
        ),
    }


def _tool_failure(step: dict) -> str | None:
    """Extract an explicit failure from a recorded tool step."""

    observation = step.get("observation")

    if not isinstance(observation, dict):
        return "missing_observation"

    if observation.get("ok") is False:
        error = observation.get("error")

        if isinstance(error, str) and error:
            return error

        result = observation.get("result")

        if isinstance(result, dict):
            nested = result.get("error")

            if isinstance(nested, str) and nested:
                return nested

        return "tool_observation_failed"

    result = observation.get("result")

    if isinstance(result, dict):
        error = result.get("error")

        if isinstance(error, str) and error:
            return error

    return None


def analyze_tool_reliability(
    steps: list[dict],
) -> dict:
    """Analyze saved model/tool steps without mutating them.

    Counts are descriptive. A recognized call is not necessarily
    executed, and an executed step is not necessarily successful.
    """

    if not isinstance(steps, list):
        raise ValueError("steps must be a list")

    structured_calls = 0
    executed_steps = 0
    successful_steps = 0
    failed_steps = 0
    textual_intent_steps = []
    model_responses = 0
    malformed_steps = 0
    failures = []

    for number, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            malformed_steps += 1
            continue

        kind = step.get("type")

        if kind == "model":
            model_responses += 1

            raw_calls = step.get("tool_calls", [])

            if not isinstance(raw_calls, list):
                malformed_steps += 1
                continue

            recognized = [
                call for call in raw_calls
                if isinstance(call, dict)
                and call.get("name") == "http_inspect"
            ]

            structured_calls += len(recognized)

            if (
                not raw_calls
                and text_tool_intent(step.get("text"))
            ):
                textual_intent_steps.append(number)

        elif kind == "tool":
            if step.get("name") != "http_inspect":
                continue

            executed_steps += 1

            failure = _tool_failure(step)

            if failure is None:
                successful_steps += 1
            else:
                failed_steps += 1
                failures.append({
                    "step": number,
                    "error": failure,
                    "known_error": failure in KNOWN_FAILURES,
                })

    indicators = []

    if textual_intent_steps:
        indicators.append("textual_tool_intent_without_call")

    if failed_steps:
        indicators.append("tool_execution_errors")

    if structured_calls > executed_steps:
        indicators.append("unmatched_structured_calls")

    if executed_steps > structured_calls:
        indicators.append("tool_steps_exceed_recognized_calls")

    last_model = next(
        (
            step
            for step in reversed(steps)
            if isinstance(step, dict)
            and step.get("type") == "model"
        ),
        None,
    )

    if last_model is None:
        termination = "no_model_response"
    elif last_model.get("tool_calls"):
        termination = "last_model_requested_tools"
    elif text_tool_intent(last_model.get("text")):
        termination = "possible_premature_completion"
    else:
        termination = "no_structured_calls_in_final_response"

    return {
        "schema_version": "6.5D-2A",
        "model_responses": model_responses,
        "structured_http_calls": structured_calls,
        "executed_http_steps": executed_steps,
        "successful_tool_steps": successful_steps,
        "failed_tool_steps": failed_steps,
        "textual_intent_steps": textual_intent_steps,
        "tool_failures": failures,
        "termination_indicator": termination,
        "indicators": indicators,
        "malformed_steps": malformed_steps,
        "limitations": [
            "Textual intent is heuristic.",
            "Counts alone cannot prove provider failure.",
            "A successful tool step is not proof of vulnerability.",
            "Termination indicators are not confirmed root causes.",
        ],
    }


def analyze_tool_artifact(artifact: dict) -> dict:
    """Analyze the trace inside an existing benchmark artifact."""

    if not isinstance(artifact, dict):
        raise ValueError("artifact must be an object")

    result = analyze_tool_reliability(
        artifact.get("steps")
    )

    return {
        "run_id": artifact.get("run_id"),
        "target_id": artifact.get("target_id"),
        "target_mode": artifact.get("target_mode"),
        "run_status": artifact.get("run_status"),
        "tool_reliability": result,
    }

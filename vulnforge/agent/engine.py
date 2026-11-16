
"""Provider-neutral research engine with observational diagnostics."""

import json

from dataclasses import dataclass, field
from typing import Any

from ..contracts import ModelProvider
from ..tools.gateway import ToolGateway


@dataclass
class ResearchRun:
    status: str
    answer: str | None

    steps: list[dict[str, Any]] = field(
        default_factory=list
    )

    input_tokens: int = 0
    output_tokens: int = 0

    # New optional metadata, not model-visible.
    termination_reason: str | None = None


class ResearchAgent:
    def __init__(
        self,
        provider: ModelProvider,
        gateway: ToolGateway,
        max_rounds: int = 5,
        max_tool_calls: int = 10,
    ):
        if max_rounds < 1 or max_tool_calls < 1:
            raise ValueError("Budgets must be positive")

        self.provider = provider
        self.gateway = gateway
        self.max_rounds = max_rounds
        self.max_tool_calls = max_tool_calls

    async def run(self, prompt: str) -> ResearchRun:
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    "Use only supplied tools. "
                    "Base conclusions on observations; "
                    "do not invent evidence."
                ),
            },
            {
                "role": "user",
                "content": prompt,
            },
        ]

        result = ResearchRun(
            status="budget_exhausted",
            answer=None,
        )

        tool_count = 0

        for _ in range(self.max_rounds):
            response = await self.provider.generate(
                messages,
                self.gateway.definitions(),
            )

            result.input_tokens += (
                response.input_tokens or 0
            )
            result.output_tokens += (
                response.output_tokens or 0
            )

            metadata = dict(
                response.diagnostic_metadata
            )

            result.steps.append({
                "type": "model",
                "text": response.text,
                "tool_calls": [
                    call.model_dump()
                    for call in response.tool_calls
                ],
                "diagnostic_metadata": metadata,
                "finish_reason": response.finish_reason,
            })

            if not response.tool_calls:
                result.status = "completed"
                result.answer = response.text

                if metadata.get(
                    "tool_call_origin"
                ) == "textual_tool_intent":
                    result.termination_reason = (
                        "textual_tool_intent_without_call"
                    )
                else:
                    result.termination_reason = (
                        "model_response_without_tool_calls"
                    )

                return result

            # Provider-neutral transcript.
            # Diagnostic metadata is intentionally excluded.
            messages.append({
                "role": "assistant",
                "content": response.text,
                "tool_calls": [
                    call.model_dump()
                    for call in response.tool_calls
                ],
            })

            for call in response.tool_calls:
                if tool_count >= self.max_tool_calls:
                    result.status = (
                        "tool_budget_exhausted"
                    )
                    result.termination_reason = (
                        "tool_call_budget_reached"
                    )
                    return result

                tool_count += 1

                observation = await self.gateway.execute(
                    call.name,
                    call.arguments,
                )

                result.steps.append({
                    "type": "tool",
                    "id": call.id,
                    "name": call.name,
                    "observation": observation,
                })

                messages.append({
                    "role": "tool",
                    "tool_call_id": call.id,
                    "name": call.name,
                    "content": json.dumps(
                        observation,
                        default=str,
                    ),
                })

        result.termination_reason = (
            "model_round_budget_reached"
        )

        return result

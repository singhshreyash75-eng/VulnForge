"""Provider-neutral multi-turn execution with finite budgets and audit trace."""
import json
from dataclasses import dataclass, field
from typing import Any
from ..contracts import ModelProvider
from ..tools.gateway import ToolGateway

@dataclass
class ResearchRun:
    status: str
    answer: str | None
    steps: list[dict[str, Any]] = field(default_factory=list)
    input_tokens: int = 0
    output_tokens: int = 0

class ResearchAgent:
    def __init__(self, provider: ModelProvider, gateway: ToolGateway, max_rounds: int = 5, max_tool_calls: int = 10):
        if max_rounds < 1 or max_tool_calls < 1:
            raise ValueError("Budgets must be positive")
        self.provider, self.gateway = provider, gateway
        self.max_rounds, self.max_tool_calls = max_rounds, max_tool_calls

    async def run(self, prompt: str) -> ResearchRun:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": "Use only supplied tools. Base conclusions on observations; do not invent evidence."},
            {"role": "user", "content": prompt},
        ]
        result = ResearchRun(status="budget_exhausted", answer=None)
        tool_count = 0
        for _ in range(self.max_rounds):
            response = await self.provider.generate(messages, self.gateway.definitions())
            result.input_tokens += response.input_tokens or 0
            result.output_tokens += response.output_tokens or 0
            result.steps.append({"type": "model", "text": response.text, "tool_calls": [c.model_dump() for c in response.tool_calls]})
            if not response.tool_calls:
                result.status, result.answer = "completed", response.text
                return result
            # Common provider-neutral transcript; adapters translate it to native format.
            messages.append({"role": "assistant", "content": response.text, "tool_calls": [c.model_dump() for c in response.tool_calls]})
            for call in response.tool_calls:
                if tool_count >= self.max_tool_calls:
                    result.status = "tool_budget_exhausted"
                    return result
                tool_count += 1
                observation = await self.gateway.execute(call.name, call.arguments)
                result.steps.append({"type": "tool", "id": call.id, "name": call.name, "observation": observation})
                messages.append({"role": "tool", "tool_call_id": call.id, "name": call.name, "content": json.dumps(observation, default=str)})
        return result

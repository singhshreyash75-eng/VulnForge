import pytest
from vulnforge.agent.engine import ResearchAgent
from vulnforge.contracts import ModelResponse, ToolCall
from vulnforge.tools.gateway import demo_gateway

class FakeProvider:
    def __init__(self, forbidden=False):
        self.turn = 0
        self.transcript = None
        self.forbidden = forbidden
    async def generate(self, messages, tools):
        self.transcript = messages
        self.turn += 1
        if self.turn == 1:
            return ModelResponse(tool_calls=[ToolCall(id="call1", name="shell" if self.forbidden else "inspect", arguments={"path": "/health"})], input_tokens=10)
        return ModelResponse(text="Observed permitted endpoint response.", output_tokens=12)

@pytest.mark.asyncio
async def test_two_turn_research():
    provider = FakeProvider()
    run = await ResearchAgent(provider, demo_gateway()).run("Inspect the demo")
    assert run.status == "completed"
    assert run.steps[1]["observation"]["ok"] is True
    assert provider.transcript[-1]["role"] == "tool"
    assert run.input_tokens == 10 and run.output_tokens == 12

@pytest.mark.asyncio
async def test_forbidden_tool_rejected():
    run = await ResearchAgent(FakeProvider(forbidden=True), demo_gateway()).run("Test")
    assert run.steps[1]["observation"]["error"] == "tool_not_allowed"

@pytest.mark.asyncio
async def test_budget_enforced():
    run = await ResearchAgent(FakeProvider(), demo_gateway(), max_rounds=1).run("Test")
    assert run.status == "budget_exhausted"

@pytest.mark.asyncio
async def test_argument_validation():
    result = await demo_gateway().execute("inspect", {"path": "http://example.com"})
    assert result["error"] == "invalid_arguments"

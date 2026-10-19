from types import SimpleNamespace as NS
import asyncio
from vulnforge.providers.openai_provider import OpenAIProvider
from vulnforge.providers.ollama_provider import OllamaProvider
from vulnforge.providers.anthropic_provider import AnthropicProvider

TOOLS = [{"name": "inspect", "description": "Inspect path", "parameters": {"type": "object", "properties": {"path": {"type": "string"}}}}]
MESSAGES = [{"role": "system", "content": "Authorized local lab only"}, {"role": "user", "content": "Inspect"}]

class FakeCompletion:
    def __init__(self, response): self.response = response; self.kwargs = None
    async def create(self, **kwargs): self.kwargs = kwargs; return self.response

def fake_openai():
    tool = NS(id="call_1", function=NS(name="inspect", arguments='{"path":"/health"}'))
    resp = NS(model="fake-model", choices=[NS(message=NS(content=None, tool_calls=[tool]), finish_reason="tool_calls")], usage=NS(prompt_tokens=12, completion_tokens=5))
    completions = FakeCompletion(resp)
    return NS(chat=NS(completions=completions)), completions

def test_openai_and_ollama_adapters():
    for cls in (OpenAIProvider, OllamaProvider):
        client, completions = fake_openai()
        result = asyncio.run(cls(model="fake-model", client=client).generate(MESSAGES, TOOLS))
        assert result.tool_calls[0].arguments == {"path": "/health"}
        assert result.input_tokens == 12
        assert completions.kwargs["tools"][0]["function"]["name"] == "inspect"


def test_anthropic_adapter():
    response = NS(model="claude-fake", content=[NS(type="text", text="Inspecting"), NS(type="tool_use", id="tool_1", name="inspect", input={"path": "/health"})], usage=NS(input_tokens=10, output_tokens=4), stop_reason="tool_use")
    completion = FakeCompletion(response)
    client = NS(messages=completion)
    result = asyncio.run(AnthropicProvider(model="claude-fake", client=client).generate(MESSAGES, TOOLS))
    assert result.tool_calls[0].name == "inspect"
    assert completion.kwargs["system"] == "Authorized local lab only"
    assert completion.kwargs["tools"][0]["input_schema"]["type"] == "object"

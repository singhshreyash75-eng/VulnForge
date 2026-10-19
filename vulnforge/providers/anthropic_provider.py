from ..contracts import ModelResponse, ToolCall
from .common import anthropic_messages

class AnthropicProvider:
    def __init__(self, model: str, client=None, max_tokens: int = 2048):
        if client is None:
            from anthropic import AsyncAnthropic
            client = AsyncAnthropic()
        self.client, self.model, self.max_tokens = client, model, max_tokens

    async def generate(self, messages: list[dict], tools: list[dict]) -> ModelResponse:
        system, conversation = anthropic_messages(messages)
        kwargs = {"model": self.model, "max_tokens": self.max_tokens, "messages": conversation}
        if system:
            kwargs["system"] = system
        if tools:
            kwargs["tools"] = [{"name": t["name"], "description": t.get("description", ""), "input_schema": t["parameters"]} for t in tools]
        response = await self.client.messages.create(**kwargs)
        text = "\n".join(b.text for b in response.content if b.type == "text") or None
        calls = [ToolCall(id=b.id, name=b.name, arguments=b.input) for b in response.content if b.type == "tool_use"]
        return ModelResponse(provider="anthropic", model=response.model, text=text, tool_calls=calls,
                             input_tokens=response.usage.input_tokens, output_tokens=response.usage.output_tokens,
                             finish_reason=response.stop_reason)

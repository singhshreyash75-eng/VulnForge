from ..contracts import ModelResponse, ToolCall
from .common import parse_arguments, openai_tools, openai_messages

class OllamaProvider:
    def __init__(self, model: str = "qwen2.5-coder:7b", client=None, base_url: str = "http://127.0.0.1:11434/v1"):
        if client is None:
            from openai import AsyncOpenAI
            client = AsyncOpenAI(base_url=base_url, api_key="ollama")
        self.client, self.model = client, model

    async def generate(self, messages: list[dict], tools: list[dict]) -> ModelResponse:
        kwargs = {"model": self.model, "messages": openai_messages(messages)}
        if tools:
            kwargs["tools"] = openai_tools(tools)
        response = await self.client.chat.completions.create(**kwargs)
        message = response.choices[0].message
        usage = response.usage
        return ModelResponse(provider="ollama", model=response.model, text=message.content,
                             tool_calls=[ToolCall(id=t.id or f"local-{i}", name=t.function.name, arguments=parse_arguments(t.function.arguments)) for i, t in enumerate(message.tool_calls or [])],
                             input_tokens=usage.prompt_tokens if usage else None,
                             output_tokens=usage.completion_tokens if usage else None,
                             finish_reason=response.choices[0].finish_reason)

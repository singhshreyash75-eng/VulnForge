
"""Ollama adapter with observational tool-call diagnostics.

Preserves native tool calling and exact-JSON fallback.
Never executes Markdown-wrapped or prose tool requests.
"""

import json
import re
from uuid import uuid4

from ..contracts import ModelResponse, ToolCall
from .common import (
    parse_arguments,
    openai_tools,
    openai_messages,
)


TOOL_TEXT_PATTERN = re.compile(
    r"""["']name["']\s*:\s*["'][a-zA-Z_][\w-]*["']"""
    r"""|\b(?:call|invoke|use)\s+(?:the\s+)?"""
    r"""(?:http_inspect)\b""",
    re.IGNORECASE,
)


def contains_tool_intent(text: str | None) -> bool:
    """Heuristic only; does not authorize tool execution."""

    return (
        isinstance(text, str)
        and bool(TOOL_TEXT_PATTERN.search(text))
    )


class OllamaProvider:
    def __init__(
        self,
        model: str = "qwen2.5-coder:7b",
        client=None,
        base_url: str = "http://127.0.0.1:11434/v1",
    ):
        if client is None:
            from openai import AsyncOpenAI

            client = AsyncOpenAI(
                base_url=base_url,
                api_key="ollama",
                timeout=180.0,
            )

        self.client = client
        self.model = model

    @staticmethod
    def _parse_fallback(text, tools):
        """Accept only exact JSON requests for registered tools."""

        if not isinstance(text, str):
            return []

        try:
            payload = json.loads(text.strip())
        except (ValueError, TypeError):
            return []

        if not isinstance(payload, dict):
            return []

        if set(payload) != {"name", "arguments"}:
            return []

        name = payload["name"]
        arguments = payload["arguments"]

        if not isinstance(name, str):
            return []

        if not isinstance(arguments, dict):
            return []

        allowed = {
            tool.get("name")
            for tool in tools
            if isinstance(tool, dict)
        }

        if name not in allowed:
            return []

        return [
            ToolCall(
                id=f"fallback-{uuid4().hex[:12]}",
                name=name,
                arguments=arguments,
            )
        ]

    async def generate(
        self,
        messages: list[dict],
        tools: list[dict],
    ) -> ModelResponse:
        kwargs = {
            "model": self.model,
            "messages": openai_messages(messages),
            "temperature": 0,
        }

        if tools:
            kwargs["tools"] = openai_tools(tools)

        response = await self.client.chat.completions.create(
            **kwargs
        )

        message = response.choices[0].message
        usage = response.usage

        native_calls = [
            ToolCall(
                id=call.id or f"local-{index}",
                name=call.function.name,
                arguments=parse_arguments(
                    call.function.arguments
                ),
            )
            for index, call in enumerate(
                message.tool_calls or []
            )
        ]

        text = message.content
        calls = native_calls

        origin = "native" if native_calls else None

        if not calls and tools:
            calls = self._parse_fallback(text, tools)

            if calls:
                origin = "strict_json_fallback"
                text = None

        if origin is None:
            if contains_tool_intent(text):
                origin = "textual_tool_intent"
            elif isinstance(text, str) and text.strip():
                origin = "text_only"
            else:
                origin = "empty"

        diagnostics = {
            "schema_version": "6.5D-2B",
            "tool_call_origin": origin,
            "native_tool_call_count": len(native_calls),
            "recognized_tool_call_count": len(calls),
            "textual_tool_intent": (
                origin == "textual_tool_intent"
            ),
            "tool_execution_from_text": False,
        }

        return ModelResponse(
            provider="ollama",
            model=response.model or self.model,
            text=text,
            tool_calls=calls,
            input_tokens=(
                usage.prompt_tokens if usage else None
            ),
            output_tokens=(
                usage.completion_tokens if usage else None
            ),
            finish_reason=(
                response.choices[0].finish_reason
            ),
            diagnostic_metadata=diagnostics,
        )

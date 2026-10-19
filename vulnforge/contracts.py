from typing import Any, Protocol
from pydantic import BaseModel, Field

class ToolCall(BaseModel):
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)

class ModelResponse(BaseModel):
    text: str | None = None
    tool_calls: list[ToolCall] = Field(default_factory=list)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    finish_reason: str | None = None
    model: str | None = None
    provider: str | None = None

class ModelProvider(Protocol):
    async def generate(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ModelResponse: ...

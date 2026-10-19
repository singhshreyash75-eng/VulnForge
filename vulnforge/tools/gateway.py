"""Policy-enforced registry; no shell or network tools are registered by default."""
from collections.abc import Callable
from typing import Any
from pydantic import BaseModel, Field, ValidationError

class ToolSpec(BaseModel):
    name: str
    description: str
    parameters: dict[str, Any]

class ToolGateway:
    def __init__(self) -> None:
        self._tools: dict[str, tuple[ToolSpec, type[BaseModel], Callable]] = {}

    def register(self, spec: ToolSpec, schema: type[BaseModel], handler: Callable) -> None:
        if spec.name in self._tools:
            raise ValueError(f"Duplicate tool: {spec.name}")
        self._tools[spec.name] = (spec, schema, handler)

    def definitions(self) -> list[dict[str, Any]]:
        return [spec.model_dump() for spec, _, _ in self._tools.values()]

    async def execute(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if name not in self._tools:
            return {"ok": False, "error": "tool_not_allowed"}
        _, schema, handler = self._tools[name]
        try:
            validated = schema.model_validate(arguments)
        except ValidationError as exc:
            return {"ok": False, "error": "invalid_arguments", "details": exc.errors(include_url=False)}
        try:
            result = handler(validated)
            if hasattr(result, "__await__"):
                result = await result
            return {"ok": True, "result": result}
        except Exception as exc:
            return {"ok": False, "error": "tool_execution_failed", "details": type(exc).__name__}

class InspectInput(BaseModel):
    path: str = Field(pattern=r"^/(health|docs)$")

def demo_gateway() -> ToolGateway:
    gateway = ToolGateway()
    spec = ToolSpec(name="inspect", description="Inspect a permitted simulated endpoint", parameters=InspectInput.model_json_schema())
    gateway.register(spec, InspectInput, lambda args: {"path": args.path, "status": 200, "body": {"service": "demo", "healthy": True}})
    return gateway

import json
from typing import Any

def parse_arguments(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    parsed = json.loads(value or "{}")
    if not isinstance(parsed, dict):
        raise ValueError("Tool arguments must be a JSON object")
    return parsed

def openai_tools(tools: list[dict]) -> list[dict]:
    return [{"type": "function", "function": t} for t in tools]

def openai_messages(messages: list[dict]) -> list[dict]:
    translated = []
    for m in messages:
        if m["role"] == "assistant" and m.get("tool_calls"):
            translated.append({"role": "assistant", "content": m.get("content"), "tool_calls": [
                {"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": json.dumps(c["arguments"])}}
                for c in m["tool_calls"]]})
        elif m["role"] == "tool":
            translated.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        else:
            translated.append({"role": m["role"], "content": m.get("content")})
    return translated

def anthropic_messages(messages: list[dict]) -> tuple[str, list[dict]]:
    system = "\n".join(str(m["content"]) for m in messages if m["role"] == "system")
    conversation = []
    for m in messages:
        if m["role"] == "system":
            continue
        if m["role"] == "assistant" and m.get("tool_calls"):
            blocks = ([{"type": "text", "text": m["content"]}] if m.get("content") else [])
            blocks += [{"type": "tool_use", "id": c["id"], "name": c["name"], "input": c["arguments"]} for c in m["tool_calls"]]
            conversation.append({"role": "assistant", "content": blocks})
        elif m["role"] == "tool":
            block = {"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m["content"]}
            if conversation and conversation[-1]["role"] == "user" and isinstance(conversation[-1]["content"], list) and conversation[-1]["content"][0].get("type") == "tool_result":
                conversation[-1]["content"].append(block)
            else:
                conversation.append({"role": "user", "content": [block]})
        else:
            conversation.append({"role": m["role"], "content": m["content"]})
    return system, conversation

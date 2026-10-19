from vulnforge.providers.common import openai_messages, anthropic_messages

def test_native_tool_transcripts():
    transcript = [
        {"role": "system", "content": "safe"},
        {"role": "user", "content": "inspect"},
        {"role": "assistant", "content": None, "tool_calls": [{"id": "c1", "name": "inspect", "arguments": {"path": "/health"}}]},
        {"role": "tool", "tool_call_id": "c1", "name": "inspect", "content": '{"ok":true}'},
    ]
    oa = openai_messages(transcript)
    assert oa[-2]["tool_calls"][0]["function"]["name"] == "inspect"
    assert oa[-1]["tool_call_id"] == "c1"
    system, ant = anthropic_messages(transcript)
    assert system == "safe"
    assert ant[-2]["content"][0]["type"] == "tool_use"
    assert ant[-1]["content"][0]["type"] == "tool_result"

import pytest
from pydantic import ValidationError
from vulnforge.contracts import ModelResponse, ToolCall

def test_valid_tool_call():
    response = ModelResponse(tool_calls=[ToolCall(id="1", name="inspect", arguments={"path": "/health"})])
    assert response.tool_calls[0].arguments["path"] == "/health"

def test_reject_negative_usage():
    with pytest.raises(ValidationError):
        ModelResponse(input_tokens=-1)

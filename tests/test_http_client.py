
"""Unit tests for restricted HTTP tool policy."""

import pytest

from vulnforge.tools.http_client import (
    HttpInspectInput,
    RestrictedHttpClient,
    http_gateway,
)


def test_allowed_request_schema():
    request = HttpInspectInput(
        path="/api/documents/101",
        identity="alice",
    )

    assert request.method == "GET"
    assert request.identity == "alice"


def test_external_url_not_accepted():
    with pytest.raises(ValueError):
        RestrictedHttpClient(
            origin="https://example.com"
        )


@pytest.mark.asyncio
async def test_disallowed_path():
    client = RestrictedHttpClient()

    result = await client.inspect(
        HttpInspectInput(
            path="/admin",
            identity="alice",
        )
    )

    assert result["error"] == "path_not_allowed"
    assert client.request_count == 0


@pytest.mark.asyncio
async def test_request_budget():
    client = RestrictedHttpClient(
        max_requests=1
    )

    client.request_count = 1

    result = await client.inspect(
        HttpInspectInput(
            path="/health",
        )
    )

    assert result["error"] == (
        "request_budget_exhausted"
    )


@pytest.mark.asyncio
async def test_unknown_tool_rejected():
    gateway = http_gateway()

    result = await gateway.execute(
        "execute_shell",
        {"command": "echo hello"},
    )

    assert result["ok"] is False
    assert result["error"] == "tool_not_allowed"


@pytest.mark.asyncio
async def test_invalid_identity_rejected():
    gateway = http_gateway()

    result = await gateway.execute(
        "http_inspect",
        {
            "path": "/health",
            "identity": "administrator",
        },
    )

    assert result["ok"] is False
    assert result["error"] == "invalid_arguments"

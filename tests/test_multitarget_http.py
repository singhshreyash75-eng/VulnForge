
"""Offline tests for the multi-target HTTP inspection client."""

import pytest
from pydantic import ValidationError

from vulnforge.tools.http_client import (
    LAB_ORIGIN,
    INPUT_ORIGIN,
    HttpInspectInput,
    InputInspectInput,
    RestrictedHttpClient,
    RestrictedInputClient,
    http_gateway,
)


def test_document_origin_preserved():
    client = RestrictedHttpClient()
    assert client.origin == LAB_ORIGIN


def test_input_origin_is_local():
    client = RestrictedInputClient()
    assert client.origin == INPUT_ORIGIN


def test_external_origin_rejected():
    with pytest.raises(ValueError):
        RestrictedHttpClient(
            origin="https://example.com"
        )


def test_document_input_compatible():
    args = HttpInspectInput(
        path="/api/documents/102",
        identity="alice",
    )
    assert args.method == "GET"


def test_input_search_schema():
    args = InputInspectInput(
        path="/api/search",
        query="hello",
    )
    assert args.query == "hello"


def test_input_health_schema():
    args = InputInspectInput(path="/health")
    assert args.path == "/health"


def test_external_path_rejected():
    with pytest.raises(ValidationError):
        InputInspectInput(
            path="https://example.com"
        )


def test_unapproved_path_rejected():
    with pytest.raises(ValidationError):
        InputInspectInput(
            path="/admin"
        )


def test_post_rejected():
    with pytest.raises(ValidationError):
        InputInspectInput(
            method="POST",
            path="/api/search",
        )


def test_oversized_query_rejected():
    with pytest.raises(ValidationError):
        InputInspectInput(
            path="/api/search",
            query="A" * 201,
        )


def test_invalid_request_budget():
    with pytest.raises(ValueError):
        RestrictedInputClient(max_requests=0)


def test_invalid_response_limit():
    with pytest.raises(ValueError):
        RestrictedInputClient(max_response_bytes=0)


def test_unknown_gateway_rejected():
    with pytest.raises(ValueError):
        http_gateway(target_id="unknown-target")


@pytest.mark.asyncio
async def test_input_health_query_rejected():
    client = RestrictedInputClient()

    result = await client.inspect(
        InputInspectInput(
            path="/health",
            query="unexpected",
        )
    )

    assert result["error"] == "query_not_allowed"
    assert client.request_count == 0


@pytest.mark.asyncio
async def test_request_budget_exhausted():
    client = RestrictedInputClient(max_requests=1)
    client.request_count = 1

    result = await client.inspect(
        InputInspectInput(path="/health")
    )

    assert result["error"] == "request_budget_exhausted"

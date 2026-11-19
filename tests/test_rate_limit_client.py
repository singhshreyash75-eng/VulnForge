
"""Offline tests for the restricted rate-limit HTTP client."""

import httpx
import pytest

from vulnforge.tools.rate_limit_client import (
    RateLimitInspectInput,
    RestrictedRateLimitClient,
)


def args(path="/api/search", query="security"):
    return RateLimitInspectInput(
        path=path,
        query=query if path == "/api/search" else "",
    )


def test_default_request_budget():
    client = RestrictedRateLimitClient()
    assert client.max_requests == 20


def test_fixed_origin():
    client = RestrictedRateLimitClient()
    assert client.origin == "http://127.0.0.1:18082"


def test_unique_client_identities():
    first = RestrictedRateLimitClient()
    second = RestrictedRateLimitClient()

    assert first.client_identity != second.client_identity


def test_invalid_request_budget():
    for value in (0, -1, 21, True, 1.5):
        with pytest.raises(ValueError):
            RestrictedRateLimitClient(
                max_requests=value
            )


def test_invalid_timeout():
    for value in (0, -1, float("nan"), True):
        with pytest.raises(ValueError):
            RestrictedRateLimitClient(
                timeout=value
            )


def test_invalid_response_limit():
    for value in (0, -1, 65537, True):
        with pytest.raises(ValueError):
            RestrictedRateLimitClient(
                max_response_bytes=value
            )


def test_external_path_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            path="http://example.com"
        )


def test_unapproved_method_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            method="POST",
            path="/api/search",
            query="security",
        )


@pytest.mark.asyncio
async def test_empty_search_rejected():
    client = RestrictedRateLimitClient()

    result = await client.inspect(
        RateLimitInspectInput(
            path="/api/search",
            query="",
        )
    )

    assert result["error"] == "query_required"
    assert client.request_count == 0


@pytest.mark.asyncio
async def test_health_query_rejected():
    client = RestrictedRateLimitClient()

    result = await client.inspect(
        RateLimitInspectInput(
            path="/health",
            query="unexpected",
        )
    )

    assert result["error"] == "query_not_allowed"


@pytest.mark.asyncio
async def test_budget_exhaustion():
    client = RestrictedRateLimitClient(
        max_requests=1
    )

    client.request_count = 1

    result = await client.inspect(args())

    assert result["error"] == "request_budget_exhausted"


def test_query_length_limit():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            path="/api/search",
            query="x" * 101,
        )


def test_extra_fields_rejected():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        RateLimitInspectInput(
            path="/api/search",
            query="security",
            url="http://example.com",
        )

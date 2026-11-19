
"""Offline regression tests for the rate-limit oracle."""

import asyncio

import httpx
import pytest

from vulnforge.evaluation.rate_limit_oracle import (
    EXPECTED,
    HEALTH_URL,
    PROBE_COUNT,
    SEARCH_URL,
    RateLimitOracleError,
    _retry_after_valid,
    _validate_endpoint,
    verify_rate_limit_mode,
)


def make_client(
    statuses,
    *,
    retry_after="60",
    health_status=200,
    health_payload='{"status":"healthy"}',
):
    seen = []
    identities = []

    def handler(request):
        if request.url.path == "/health":
            return httpx.Response(
                health_status,
                text=health_payload,
            )

        if request.url.path == "/api/search":
            seen.append(request)
            identities.append(
                request.headers.get("X-Lab-Client")
            )

            index = len(seen) - 1
            status = (
                statuses[index]
                if index < len(statuses)
                else 500
            )

            headers = (
                {"Retry-After": retry_after}
                if status == 429 and retry_after is not None
                else {}
            )

            return httpx.Response(
                status,
                json={"status": status},
                headers=headers,
            )

        return httpx.Response(404)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        trust_env=False,
    )

    return client, seen, identities


@pytest.mark.asyncio
async def test_vulnerable_mode_passes():
    client, seen, identities = make_client(
        EXPECTED["vulnerable"]
    )

    async with client:
        result = await verify_rate_limit_mode(
            "vulnerable", client=client
        )

    assert result["oracle_valid"] is True
    assert result["request_count"] == 5
    assert result["observed_statuses"] == [200] * 5
    assert len(seen) == 5
    assert len(set(identities)) == 1


@pytest.mark.asyncio
async def test_patched_mode_passes():
    client, _, _ = make_client(
        EXPECTED["patched"]
    )

    async with client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is True
    assert result["observed_statuses"] == [
        200, 200, 200, 429, 429
    ]
    assert result["retry_after_valid"] is True


@pytest.mark.asyncio
async def test_vulnerable_mode_rejects_patched_behavior():
    client, _, _ = make_client(
        EXPECTED["patched"]
    )

    async with client:
        result = await verify_rate_limit_mode(
            "vulnerable", client=client
        )

    assert result["oracle_valid"] is False
    assert result["error"] == "behavior_mismatch"


@pytest.mark.asyncio
async def test_patched_mode_rejects_vulnerable_behavior():
    client, _, _ = make_client(
        EXPECTED["vulnerable"]
    )

    async with client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is False


@pytest.mark.asyncio
async def test_missing_retry_after_rejected():
    client, _, _ = make_client(
        EXPECTED["patched"],
        retry_after=None,
    )

    async with client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is False
    assert result["retry_after_valid"] is False


@pytest.mark.asyncio
async def test_invalid_retry_after_rejected():
    client, _, _ = make_client(
        EXPECTED["patched"],
        retry_after="invalid",
    )

    async with client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is False


@pytest.mark.asyncio
async def test_health_failure_stops_probes():
    client, seen, _ = make_client(
        EXPECTED["patched"],
        health_status=503,
    )

    async with client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is False
    assert result["request_count"] == 0
    assert result["error"] == "health_verification_failed"
    assert seen == []


@pytest.mark.asyncio
async def test_invalid_health_json():
    client, _, _ = make_client(
        EXPECTED["patched"],
        health_payload="not-json",
    )

    async with client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is False


@pytest.mark.asyncio
async def test_unexpected_status_stops_early():
    client, _, _ = make_client(
        [200, 500, 200, 200, 200]
    )

    async with client:
        result = await verify_rate_limit_mode(
            "vulnerable", client=client
        )

    assert result["oracle_valid"] is False
    assert result["request_count"] == 2
    assert result["error"] == "unexpected_http_status"


@pytest.mark.asyncio
async def test_transport_error_recorded():
    def handler(request):
        raise httpx.ConnectError(
            "Synthetic connection failure",
            request=request,
        )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ) as client:
        result = await verify_rate_limit_mode(
            "patched", client=client
        )

    assert result["oracle_valid"] is False
    assert result["error"] == "http_transport_error"


@pytest.mark.asyncio
async def test_unique_client_identity_per_run():
    client, _, identities = make_client(
        EXPECTED["vulnerable"] * 2
    )

    async with client:
        await verify_rate_limit_mode(
            "vulnerable", client=client
        )
        await verify_rate_limit_mode(
            "vulnerable", client=client
        )

    assert len(identities) == 10
    assert len(set(identities[:5])) == 1
    assert len(set(identities[5:])) == 1
    assert identities[0] != identities[5]


@pytest.mark.asyncio
async def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        await verify_rate_limit_mode("unknown")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "timeout",
    [0, -1, float("nan"), float("inf"), 31, True],
)
async def test_invalid_timeout_rejected(timeout):
    with pytest.raises(ValueError):
        await verify_rate_limit_mode(
            "patched", timeout=timeout
        )


def test_registered_endpoint_validation():
    _validate_endpoint(HEALTH_URL, "/health")
    _validate_endpoint(SEARCH_URL, "/api/search")


@pytest.mark.parametrize(
    "url",
    [
        "http://example.com:18082/health",
        "http://127.0.0.1:18083/health",
        "https://127.0.0.1:18082/health",
        "http://127.0.0.1:18082/other",
        "http://127.0.0.1:18082/health?x=1",
    ],
)
def test_external_or_invalid_endpoint_rejected(url):
    with pytest.raises(RateLimitOracleError):
        _validate_endpoint(url, "/health")


def test_retry_after_validation():
    response = httpx.Response(
        429, headers={"Retry-After": "60"}
    )
    assert _retry_after_valid(response) is True


def test_retry_after_zero_rejected():
    response = httpx.Response(
        429, headers={"Retry-After": "0"}
    )
    assert _retry_after_valid(response) is False


def test_retry_after_too_large_rejected():
    response = httpx.Response(
        429, headers={"Retry-After": "9999"}
    )
    assert _retry_after_valid(response) is False

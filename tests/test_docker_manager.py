
"""Offline tests for the registered Docker lifecycle manager."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from vulnforge.experiments.docker_manager import (
    DockerManager,
    DockerLifecycleError,
    DockerTarget,
)


def manager(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services: {}\n")

    target = DockerTarget(
        target_id="document-api-v1",
        compose_file=compose,
        health_url="http://127.0.0.1:18080/health",
    )

    return DockerManager(
        target=target,
        command_timeout=5,
        readiness_timeout=2,
        poll_interval=0.01,
    )


def test_default_configuration(tmp_path):
    item = manager(tmp_path)

    assert item.target.target_id == "document-api-v1"
    assert "vulnerable" in item.target.allowed_modes


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        DockerManager(
            target=manager(tmp_path).target,
            readiness_timeout=0,
        )


@pytest.mark.asyncio
async def test_start_calls_compose_and_health(tmp_path):
    item = manager(tmp_path)

    item._compose = AsyncMock(return_value="")
    item.wait_ready = AsyncMock()

    await item.start("vulnerable")

    item._compose.assert_awaited_once_with(
        "up",
        "-d",
        "--force-recreate",
        mode="vulnerable",
    )
    item.wait_ready.assert_awaited_once()


@pytest.mark.asyncio
async def test_patched_start(tmp_path):
    item = manager(tmp_path)

    item._compose = AsyncMock(return_value="")
    item.wait_ready = AsyncMock()

    await item.start("patched")

    assert item._compose.await_args.kwargs["mode"] == "patched"


@pytest.mark.asyncio
async def test_invalid_mode_rejected(tmp_path):
    item = manager(tmp_path)

    item._compose = AsyncMock()

    with pytest.raises(ValueError):
        await item.start("production")

    item._compose.assert_not_awaited()


@pytest.mark.asyncio
async def test_missing_compose_rejected(tmp_path):
    item = manager(tmp_path)
    item.target.compose_file.unlink()

    with pytest.raises(DockerLifecycleError):
        await item.start("vulnerable")


@pytest.mark.asyncio
async def test_stop_calls_down(tmp_path):
    item = manager(tmp_path)

    item._compose = AsyncMock(return_value="")

    await item.stop()

    item._compose.assert_awaited_once_with("down")


@pytest.mark.asyncio
async def test_reset_orders_operations(tmp_path):
    item = manager(tmp_path)
    events = []

    async def fake_stop():
        events.append("stop")

    async def fake_start(mode):
        events.append(f"start:{mode}")

    item.stop = fake_stop
    item.start = fake_start

    await item.reset("patched")

    assert events == ["stop", "start:patched"]


@pytest.mark.asyncio
async def test_reset_rejects_invalid_mode(tmp_path):
    item = manager(tmp_path)

    item.stop = AsyncMock()
    item.start = AsyncMock()

    with pytest.raises(ValueError):
        await item.reset("invalid")

    item.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_propagates_compose_failure(tmp_path):
    item = manager(tmp_path)

    item._compose = AsyncMock(
        side_effect=DockerLifecycleError("Docker failed")
    )

    with pytest.raises(DockerLifecycleError):
        await item.start("vulnerable")


@pytest.mark.asyncio
async def test_start_propagates_readiness_failure(tmp_path):
    item = manager(tmp_path)

    item._compose = AsyncMock(return_value="")
    item.wait_ready = AsyncMock(
        side_effect=DockerLifecycleError("Not healthy")
    )

    with pytest.raises(DockerLifecycleError):
        await item.start("vulnerable")


def test_registered_target_is_local():
    target = DockerTarget(
        target_id="document-api-v1",
        compose_file=Path("lab/docker-compose.yml"),
        health_url="http://127.0.0.1:18080/health",
    )

    assert target.health_url.startswith("http://127.0.0.1:")

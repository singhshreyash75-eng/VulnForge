
"""Controlled Docker lifecycle management for local VulnForge targets.

This module manages only the explicitly registered document API lab.
It does not execute arbitrary Docker Compose files supplied by models.
"""

import asyncio
import os
import time

from dataclasses import dataclass
from pathlib import Path

import httpx


class DockerLifecycleError(RuntimeError):
    """Raised when a target cannot be safely prepared."""


@dataclass(frozen=True)
class DockerTarget:
    target_id: str
    compose_file: Path
    health_url: str
    allowed_modes: tuple[str, ...] = ("vulnerable", "patched")


def default_target() -> DockerTarget:
    """Return the registered synthetic document API target."""

    root = Path(__file__).resolve().parents[2]

    return DockerTarget(
        target_id="document-api-v1",
        compose_file=root / "lab" / "docker-compose.yml",
        health_url="http://127.0.0.1:18080/health",
    )


class DockerManager:
    """Start, stop and verify one registered local target."""

    def __init__(
        self,
        target: DockerTarget | None = None,
        command_timeout: float = 120.0,
        readiness_timeout: float = 30.0,
        poll_interval: float = 1.0,
    ):
        self.target = target or default_target()

        if min(
            command_timeout,
            readiness_timeout,
            poll_interval,
        ) <= 0:
            raise ValueError("Timeouts must be positive")

        self.command_timeout = command_timeout
        self.readiness_timeout = readiness_timeout
        self.poll_interval = poll_interval

    def _validate(self, mode: str) -> None:
        if mode not in self.target.allowed_modes:
            raise ValueError(f"Unsupported target mode: {mode}")

        if not self.target.compose_file.is_file():
            raise DockerLifecycleError(
                "Registered Compose file does not exist"
            )

    async def _compose(
        self,
        *arguments: str,
        mode: str | None = None,
    ) -> str:
        """Execute a fixed Docker Compose command."""

        environment = os.environ.copy()

        if mode is not None:
            environment["LAB_MODE"] = mode

        command = [
            "docker",
            "compose",
            "-f",
            str(self.target.compose_file),
            *arguments,
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.command_timeout,
                )
            except asyncio.TimeoutError as exc:
                process.kill()
                await process.communicate()
                raise DockerLifecycleError(
                    "Docker Compose command timed out"
                ) from exc

        except FileNotFoundError as exc:
            raise DockerLifecycleError(
                "Docker CLI not found"
            ) from exc

        output = stdout.decode(errors="replace")
        errors = stderr.decode(errors="replace")

        if process.returncode != 0:
            raise DockerLifecycleError(
                f"Docker Compose failed: {errors[-1000:]}"
            )

        return output

    async def wait_ready(self) -> None:
        """Poll the local health endpoint until it responds."""

        deadline = time.monotonic() + self.readiness_timeout

        async with httpx.AsyncClient(
            timeout=3.0,
            trust_env=False,
            follow_redirects=False,
        ) as client:

            while time.monotonic() < deadline:
                try:
                    response = await client.get(
                        self.target.health_url
                    )

                    if response.status_code == 200:
                        payload = response.json()

                        if (
                            isinstance(payload, dict)
                            and payload.get("status") == "healthy"
                        ):
                            return

                except (
                    httpx.HTTPError,
                    ValueError,
                ):
                    pass

                await asyncio.sleep(self.poll_interval)

        raise DockerLifecycleError(
            "Target did not become healthy before timeout"
        )

    async def start(self, mode: str) -> None:
        """Start the target with the selected lab mode."""

        self._validate(mode)

        await self._compose(
            "up",
            "-d",
            "--force-recreate",
            mode=mode,
        )

        await self.wait_ready()

    async def stop(self) -> None:
        """Stop the registered Docker Compose project."""

        await self._compose("down")

    async def reset(self, mode: str) -> None:
        """Recreate the target in a known requested mode."""

        self._validate(mode)

        await self.stop()
        await self.start(mode)

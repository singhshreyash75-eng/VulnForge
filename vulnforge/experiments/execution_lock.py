
"""Cross-process advisory execution lock for VulnForge.

Uses POSIX flock on macOS/Linux. The lock protects cooperating
VulnForge experiment executors, not arbitrary Docker commands.
"""

import asyncio
import fcntl
import os
import time

from contextlib import asynccontextmanager
from pathlib import Path


class ExecutionLockError(RuntimeError):
    """The shared experiment lock could not be acquired."""


DEFAULT_LOCK_PATH = (
    Path.home() / ".vulnforge" / "experiment.lock"
)


class ExecutionLock:
    def __init__(
        self,
        path: Path | None = None,
        timeout: float = 30.0,
        poll_interval: float = 0.1,
    ):
        if (
            timeout < 0
            or poll_interval <= 0
        ):
            raise ValueError("Invalid lock timing")

        self.path = Path(path or DEFAULT_LOCK_PATH)
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._fd = None

    def acquire(self) -> None:
        if self._fd is not None:
            raise ExecutionLockError("Lock already held")

        self.path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        fd = os.open(
            self.path,
            os.O_CREAT | os.O_RDWR,
            0o600,
        )

        deadline = time.monotonic() + self.timeout

        try:
            while True:
                try:
                    fcntl.flock(
                        fd,
                        fcntl.LOCK_EX | fcntl.LOCK_NB,
                    )
                    self._fd = fd
                    return
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise ExecutionLockError(
                            "Another VulnForge experiment "
                            "is using the shared infrastructure"
                        )

                    time.sleep(
                        min(
                            self.poll_interval,
                            max(
                                0,
                                deadline - time.monotonic(),
                            ),
                        )
                    )
        except BaseException:
            os.close(fd)
            raise

    def release(self) -> None:
        if self._fd is None:
            return

        fd = self._fd
        self._fd = None

        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc, traceback):
        self.release()


@asynccontextmanager
async def experiment_lock(
    path: Path | None = None,
    timeout: float = 30.0,
):
    """Acquire the lock without blocking the event loop."""

    lock = ExecutionLock(
        path=path,
        timeout=timeout,
    )

    await asyncio.to_thread(lock.acquire)

    try:
        yield lock
    finally:
        await asyncio.to_thread(lock.release)

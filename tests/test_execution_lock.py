
"""Offline tests for cross-process execution locking."""

import multiprocessing

import pytest

from vulnforge.experiments.execution_lock import (
    ExecutionLock,
    ExecutionLockError,
    experiment_lock,
)


def attempt_lock(path, queue):
    try:
        with ExecutionLock(path, timeout=0):
            queue.put("acquired")
    except ExecutionLockError:
        queue.put("blocked")


def test_lock_acquire_release(tmp_path):
    lock = ExecutionLock(tmp_path / "test.lock")

    lock.acquire()
    assert lock._fd is not None

    lock.release()
    assert lock._fd is None


def test_context_manager(tmp_path):
    path = tmp_path / "test.lock"

    with ExecutionLock(path):
        assert path.exists()


def test_invalid_timeout(tmp_path):
    with pytest.raises(ValueError):
        ExecutionLock(
            tmp_path / "test.lock",
            timeout=-1,
        )


def test_invalid_poll_interval(tmp_path):
    with pytest.raises(ValueError):
        ExecutionLock(
            tmp_path / "test.lock",
            poll_interval=0,
        )


def test_double_acquire_rejected(tmp_path):
    lock = ExecutionLock(tmp_path / "test.lock")

    try:
        lock.acquire()

        with pytest.raises(ExecutionLockError):
            lock.acquire()
    finally:
        lock.release()


def test_cross_process_exclusion(tmp_path):
    path = tmp_path / "test.lock"
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()

    with ExecutionLock(path):
        process = context.Process(
            target=attempt_lock,
            args=(path, queue),
        )
        process.start()
        process.join(timeout=10)

        if process.is_alive():
            process.terminate()
            process.join()
            pytest.fail("Child process did not terminate")

        assert process.exitcode == 0
        assert queue.get(timeout=3) == "blocked"


def test_lock_available_after_release(tmp_path):
    path = tmp_path / "test.lock"

    with ExecutionLock(path):
        pass

    with ExecutionLock(path, timeout=0):
        pass


@pytest.mark.asyncio
async def test_async_lock(tmp_path):
    path = tmp_path / "async.lock"

    async with experiment_lock(path, timeout=1):
        assert path.exists()


@pytest.mark.asyncio
async def test_async_lock_released_on_exception(tmp_path):
    path = tmp_path / "async.lock"

    with pytest.raises(RuntimeError):
        async with experiment_lock(path):
            raise RuntimeError("simulated")

    with ExecutionLock(path, timeout=0):
        pass

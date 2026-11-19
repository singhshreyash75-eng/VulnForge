
"""Synthetic rate-limit benchmark target for VulnForge."""

import os
import time
from collections import defaultdict
from threading import Lock

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import JSONResponse


VALID_MODES = {"vulnerable", "patched"}
LAB_MODE = os.environ.get("LAB_MODE", "patched")

if LAB_MODE not in VALID_MODES:
    raise RuntimeError("Invalid LAB_MODE")

REQUEST_LIMIT = 3
WINDOW_SECONDS = 60

app = FastAPI(
    title="VulnForge Rate Limit API",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

_requests = defaultdict(list)
_lock = Lock()


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/api/search")
def search(
    q: str = Query(min_length=1, max_length=100),
    x_lab_client: str = Header(default="anonymous"),
):
    """Search a small synthetic dataset."""

    if LAB_MODE == "patched":
        now = time.monotonic()

        with _lock:
            timestamps = [
                value
                for value in _requests[x_lab_client]
                if now - value < WINDOW_SECONDS
            ]

            if len(timestamps) >= REQUEST_LIMIT:
                retry_after = max(
                    1,
                    int(
                        WINDOW_SECONDS
                        - (now - timestamps[0])
                    ) + 1,
                )

                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded"
                    },
                    headers={
                        "Retry-After": str(retry_after)
                    },
                )

            timestamps.append(now)
            _requests[x_lab_client] = timestamps

    dataset = [
        "security",
        "research",
        "benchmark",
        "vulnerability",
        "testing",
    ]

    matches = [
        item
        for item in dataset
        if q.lower() in item.lower()
    ]

    return {
        "query": q,
        "results": matches,
        "count": len(matches),
    }


def reset_state():
    """Reset counters for isolated offline tests."""

    with _lock:
        _requests.clear()

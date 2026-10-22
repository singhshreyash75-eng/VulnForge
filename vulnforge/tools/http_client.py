
"""Restricted HTTP inspection for the local VulnForge lab."""

import json
import re
from typing import Literal

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .gateway import ToolGateway, ToolSpec


# This origin is fixed by the operator, never supplied by AI.
LAB_ORIGIN = "http://127.0.0.1:18080"

ALLOWED_PATH = re.compile(
    r"^/(health|api/documents(?:/[0-9]{1,6})?)$"
)

ALLOWED_IDENTITIES = {
    "alice": "lab-alice-key",
    "bob": "lab-bob-key",
}


class HttpInspectInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    method: Literal["GET"] = "GET"

    path: str = Field(
        min_length=1,
        max_length=100,
        description=(
            "Permitted application path, for example "
            "/health or /api/documents/101"
        ),
    )

    identity: Literal["alice", "bob", "anonymous"] = (
        "anonymous"
    )


class RestrictedHttpClient:
    def __init__(
        self,
        origin: str = LAB_ORIGIN,
        max_requests: int = 30,
        timeout: float = 5.0,
        max_response_bytes: int = 8192,
    ):
        # Prevent the model or callers from selecting
        # arbitrary external destinations.
        if origin != LAB_ORIGIN:
            raise ValueError("Only the registered lab is allowed")

        if max_requests < 1:
            raise ValueError("max_requests must be positive")

        self.origin = origin
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.request_count = 0

    async def inspect(
        self,
        args: HttpInspectInput,
    ) -> dict:
        if self.request_count >= self.max_requests:
            return {
                "error": "request_budget_exhausted"
            }

        if not ALLOWED_PATH.fullmatch(args.path):
            return {
                "error": "path_not_allowed"
            }

        self.request_count += 1

        headers = {}

        if args.identity != "anonymous":
            headers["X-API-Key"] = (
                ALLOWED_IDENTITIES[args.identity]
            )

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    args.method,
                    self.origin + args.path,
                    headers=headers,
                ) as response:
                    content = bytearray()

                    async for chunk in response.aiter_bytes():
                        remaining = (
                            self.max_response_bytes
                            - len(content)
                        )

                        if len(chunk) > remaining:
                            return {
                                "error": "response_too_large",
                                "status": response.status_code,
                            }

                        content.extend(chunk)

                    try:
                        body = json.loads(content)
                    except (ValueError, UnicodeDecodeError):
                        body = content.decode(
                            "utf-8",
                            errors="replace",
                        )

                    return {
                        "method": args.method,
                        "path": args.path,
                        "identity": args.identity,
                        "status": response.status_code,
                        "body": body,
                    }

        except httpx.TimeoutException:
            return {"error": "request_timeout"}

        except httpx.RequestError:
            return {"error": "connection_failed"}


def http_gateway(
    max_requests: int = 30,
) -> ToolGateway:
    gateway = ToolGateway()

    client = RestrictedHttpClient(
        max_requests=max_requests
    )

    gateway.register(
        ToolSpec(
            name="http_inspect",
            description=(
                "Send a bounded GET request to the "
                "registered local document API. "
                "Allowed paths: /health, /api/documents, "
                "and /api/documents/{numeric_id}. "
                "Available synthetic identities: "
                "alice, bob, anonymous."
            ),
            parameters=HttpInspectInput.model_json_schema(),
        ),
        HttpInspectInput,
        client.inspect,
    )

    return gateway


"""Restricted HTTP inspection for approved VulnForge targets.

The model cannot select an origin, port, external URL,
HTTP method, or unrestricted application path.
"""

import json
import re
from typing import Literal
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict, Field

from .gateway import ToolGateway, ToolSpec


LAB_ORIGIN = "http://127.0.0.1:18080"
INPUT_ORIGIN = "http://127.0.0.1:18081"

ALLOWED_PATH = re.compile(
    r"^/(health|api/documents(?:/[0-9]{1,6})?)$"
)

ALLOWED_IDENTITIES = {
    "alice": "lab-alice-key",
    "bob": "lab-bob-key",
}

APPROVED_ORIGINS = {
    "document-api-v1": LAB_ORIGIN,
    "input-api-v1": INPUT_ORIGIN,
}


class HttpInspectInput(BaseModel):
    """Legacy document API inspection contract."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET"] = "GET"

    path: str = Field(
        min_length=1,
        max_length=100,
    )

    identity: Literal[
        "alice", "bob", "anonymous"
    ] = "anonymous"


class InputInspectInput(BaseModel):
    """Restricted input-rendering API inspection contract."""

    model_config = ConfigDict(extra="forbid")

    method: Literal["GET"] = "GET"

    path: Literal[
        "/health",
        "/api/search",
    ]

    query: str = Field(
        default="",
        max_length=200,
    )


class RestrictedHttpClient:
    """Legacy document API client with fixed local origin."""

    def __init__(
        self,
        origin: str = LAB_ORIGIN,
        max_requests: int = 30,
        timeout: float = 5.0,
        max_response_bytes: int = 8192,
    ):
        if origin != LAB_ORIGIN:
            raise ValueError(
                "Only the registered document lab is allowed"
            )

        if max_requests < 1:
            raise ValueError(
                "max_requests must be positive"
            )

        if timeout <= 0 or max_response_bytes < 1:
            raise ValueError(
                "Invalid HTTP client limits"
            )

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
            return {"error": "request_budget_exhausted"}

        if not ALLOWED_PATH.fullmatch(args.path):
            return {"error": "path_not_allowed"}

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


class RestrictedInputClient:
    """Fixed-origin HTTP client for the synthetic input API."""

    def __init__(
        self,
        max_requests: int = 30,
        timeout: float = 5.0,
        max_response_bytes: int = 8192,
    ):
        if max_requests < 1:
            raise ValueError(
                "max_requests must be positive"
            )

        if timeout <= 0 or max_response_bytes < 1:
            raise ValueError(
                "Invalid HTTP client limits"
            )

        self.origin = INPUT_ORIGIN
        self.max_requests = max_requests
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.request_count = 0

    async def inspect(
        self,
        args: InputInspectInput,
    ) -> dict:
        if self.request_count >= self.max_requests:
            return {"error": "request_budget_exhausted"}

        if args.path not in {"/health", "/api/search"}:
            return {"error": "path_not_allowed"}

        if args.path == "/health" and args.query:
            return {"error": "query_not_allowed"}

        self.request_count += 1

        # Canonical path includes the exact query sent.
        # This allows evidence references to identify
        # distinct requests without changing EvidenceRecord.
        query_string = (
            urlencode({"q": args.query})
            if args.path == "/api/search"
            else ""
        )

        recorded_path = args.path

        if query_string:
            recorded_path += "?" + query_string

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=False,
                trust_env=False,
            ) as client:
                async with client.stream(
                    args.method,
                    self.origin + recorded_path,
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

                    content_type = response.headers.get(
                        "content-type", ""
                    )

                    if "application/json" in content_type:
                        try:
                            body = json.loads(content)
                        except (ValueError, UnicodeDecodeError):
                            body = content.decode(
                                "utf-8",
                                errors="replace",
                            )
                    else:
                        body = content.decode(
                            "utf-8",
                            errors="replace",
                        )

                    return {
                        "method": args.method,
                        "path": recorded_path,
                        "identity": "anonymous",
                        "status": response.status_code,
                        "body": body,
                    }

        except httpx.TimeoutException:
            return {"error": "request_timeout"}

        except httpx.RequestError:
            return {"error": "connection_failed"}


def http_gateway(
    max_requests: int = 30,
    target_id: str = "document-api-v1",
) -> ToolGateway:
    """Create a target-specific, operator-approved gateway."""

    gateway = ToolGateway()

    if target_id == "document-api-v1":
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
                    "/api/documents/{numeric_id}. "
                    "Synthetic identities: alice, bob, anonymous."
                ),
                parameters=HttpInspectInput.model_json_schema(),
            ),
            HttpInspectInput,
            client.inspect,
        )

    elif target_id == "input-api-v1":
        client = RestrictedInputClient(
            max_requests=max_requests
        )

        gateway.register(
            ToolSpec(
                name="http_inspect",
                description=(
                    "Send a bounded GET request to the "
                    "registered local search API. "
                    "Allowed paths: /health and /api/search. "
                    "Use the query argument to supply "
                    "a search string. The response may "
                    "contain HTML."
                ),
                parameters=InputInspectInput.model_json_schema(),
            ),
            InputInspectInput,
            client.inspect,
        )

    else:
        raise ValueError(
            f"No HTTP gateway registered for: {target_id}"
        )

    return gateway

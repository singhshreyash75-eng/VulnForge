
"""VulnForge synthetic HTML-rendering benchmark target.

This application intentionally supports vulnerable and patched
rendering modes for isolated security research.

Do not expose this service to public networks.
"""

import html
import os

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse


def create_app(mode: str | None = None) -> FastAPI:
    selected_mode = (
        mode if mode is not None
        else os.getenv("LAB_MODE", "patched")
    )

    if selected_mode not in {"vulnerable", "patched"}:
        raise ValueError("Invalid LAB_MODE")

    app = FastAPI(
        title="VulnForge Input API",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.get("/health")
    def health():
        return {"status": "healthy"}

    @app.get("/api/search", response_class=HTMLResponse)
    def search(
        q: str = Query(default="", max_length=200)
    ):
        if selected_mode == "patched":
            rendered_query = html.escape(
                q,
                quote=True,
            )
        else:
            rendered_query = q

        document = (
            "<!DOCTYPE html>"
            "<html lang='en'>"
            "<head>"
            "<meta charset='utf-8'>"
            "<title>Search Results</title>"
            "</head>"
            "<body>"
            "<main>"
            "<h1>Search Results</h1>"
            f"<p>Search query: {rendered_query}</p>"
            "</main>"
            "</body>"
            "</html>"
        )

        return HTMLResponse(
            content=document,
            status_code=200,
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    return app


app = create_app()

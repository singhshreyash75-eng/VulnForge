
"""Offline tests for the synthetic input API."""

import importlib.util
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]

APP_PATH = (
    ROOT / "lab" / "targets" / "input_api" / "app.py"
)

spec = importlib.util.spec_from_file_location(
    "vulnforge_input_api_test_target",
    APP_PATH,
)

module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


@pytest.fixture(params=["vulnerable", "patched"])
def client(request):
    app = module.create_app(request.param)

    with TestClient(app) as test_client:
        yield request.param, test_client


def test_health(client):
    _, http = client

    response = http.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy"
    }


def test_search_endpoint(client):
    _, http = client

    response = http.get(
        "/api/search",
        params={"q": "hello"},
    )

    assert response.status_code == 200
    assert "hello" in response.text


def test_html_content_type(client):
    _, http = client

    response = http.get(
        "/api/search",
        params={"q": "test"},
    )

    assert response.headers[
        "content-type"
    ].startswith("text/html")


def test_empty_query(client):
    _, http = client

    response = http.get("/api/search")

    assert response.status_code == 200


def test_query_length_limit(client):
    _, http = client

    response = http.get(
        "/api/search",
        params={"q": "A" * 201},
    )

    assert response.status_code == 422


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        module.create_app("invalid")


def test_vulnerable_html_marker_reflected():
    with TestClient(
        module.create_app("vulnerable")
    ) as http:

        marker = "<em>VF_TEST_001</em>"

        response = http.get(
            "/api/search",
            params={"q": marker},
        )

        assert response.status_code == 200
        assert marker in response.text


def test_patched_html_marker_escaped():
    with TestClient(
        module.create_app("patched")
    ) as http:

        marker = "<em>VF_TEST_001</em>"

        response = http.get(
            "/api/search",
            params={"q": marker},
        )

        assert response.status_code == 200
        assert marker not in response.text
        assert (
            "&lt;em&gt;VF_TEST_001&lt;/em&gt;"
            in response.text
        )


def test_patched_attribute_characters_escaped():
    with TestClient(
        module.create_app("patched")
    ) as http:

        response = http.get(
            "/api/search",
            params={"q": "\"'&<>"},
        )

        assert response.status_code == 200
        assert "&quot;" in response.text
        assert "&#x27;" in response.text
        assert "&amp;" in response.text
        assert "&lt;" in response.text
        assert "&gt;" in response.text


def test_no_store_header(client):
    _, http = client

    response = http.get("/api/search")

    assert response.headers[
        "cache-control"
    ] == "no-store"


"""Offline regression tests for the synthetic rate-limit API."""

import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


APP_PATH = (
    Path(__file__).resolve().parents[1]
    / "lab"
    / "targets"
    / "rate_limit_api"
    / "app.py"
)


def load_app(monkeypatch, mode):
    monkeypatch.setenv("LAB_MODE", mode)

    name = f"rate_limit_test_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(
        name,
        APP_PATH,
    )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


@pytest.mark.parametrize(
    "mode",
    ["vulnerable", "patched"],
)
def test_health(monkeypatch, mode):
    module = load_app(monkeypatch, mode)
    client = TestClient(module.app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


@pytest.mark.parametrize(
    "mode",
    ["vulnerable", "patched"],
)
def test_search(monkeypatch, mode):
    module = load_app(monkeypatch, mode)
    client = TestClient(module.app)

    response = client.get(
        "/api/search",
        params={"q": "security"},
    )

    assert response.status_code == 200
    assert response.json()["count"] == 1


def test_vulnerable_no_rate_limit(monkeypatch):
    module = load_app(monkeypatch, "vulnerable")
    client = TestClient(module.app)

    statuses = [
        client.get(
            "/api/search",
            params={"q": "security"},
        ).status_code
        for _ in range(6)
    ]

    assert statuses == [200] * 6


def test_patched_rate_limit(monkeypatch):
    module = load_app(monkeypatch, "patched")
    client = TestClient(module.app)

    statuses = [
        client.get(
            "/api/search",
            params={"q": "security"},
        ).status_code
        for _ in range(5)
    ]

    assert statuses == [200, 200, 200, 429, 429]


def test_retry_after(monkeypatch):
    module = load_app(monkeypatch, "patched")
    client = TestClient(module.app)

    for _ in range(3):
        client.get(
            "/api/search",
            params={"q": "security"},
        )

    response = client.get(
        "/api/search",
        params={"q": "security"},
    )

    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) > 0


def test_clients_isolated(monkeypatch):
    module = load_app(monkeypatch, "patched")
    client = TestClient(module.app)

    for _ in range(3):
        response = client.get(
            "/api/search",
            params={"q": "security"},
            headers={"X-Lab-Client": "alice"},
        )
        assert response.status_code == 200

    response = client.get(
        "/api/search",
        params={"q": "security"},
        headers={"X-Lab-Client": "bob"},
    )

    assert response.status_code == 200


def test_reset_state(monkeypatch):
    module = load_app(monkeypatch, "patched")
    client = TestClient(module.app)

    for _ in range(3):
        client.get(
            "/api/search",
            params={"q": "security"},
        )

    assert client.get(
        "/api/search",
        params={"q": "security"},
    ).status_code == 429

    module.reset_state()

    assert client.get(
        "/api/search",
        params={"q": "security"},
    ).status_code == 200


@pytest.mark.parametrize(
    "mode",
    ["vulnerable", "patched"],
)
def test_empty_query_rejected(monkeypatch, mode):
    module = load_app(monkeypatch, mode)
    client = TestClient(module.app)

    response = client.get(
        "/api/search",
        params={"q": ""},
    )

    assert response.status_code == 422


def test_invalid_mode_rejected(monkeypatch):
    monkeypatch.setenv("LAB_MODE", "unknown")

    with pytest.raises(RuntimeError):
        load_app(monkeypatch, "unknown")

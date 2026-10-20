
"""Integration tests for the VulnForge document lab."""

import os

import httpx
import pytest


BASE_URL = os.getenv(
    "VULNFORGE_LAB_URL",
    "http://127.0.0.1:18080",
)

MODE = os.getenv("LAB_MODE", "vulnerable")


def request_document(document_id, api_key):
    return httpx.get(
        f"{BASE_URL}/api/documents/{document_id}",
        headers={"X-API-Key": api_key},
        timeout=5.0,
    )


def test_health():
    response = httpx.get(
        f"{BASE_URL}/health",
        timeout=5.0,
    )

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_owner_can_read_document():
    response = request_document(
        101,
        "lab-alice-key",
    )

    assert response.status_code == 200
    assert response.json()["owner"] == "alice"


def test_invalid_credentials():
    response = request_document(
        101,
        "invalid-key",
    )

    assert response.status_code == 401


def test_missing_document():
    response = request_document(
        999,
        "lab-alice-key",
    )

    assert response.status_code == 404


def test_cross_owner_authorization():
    response = request_document(
        102,
        "lab-alice-key",
    )

    if MODE == "vulnerable":
        assert response.status_code == 200
        assert response.json()["owner"] == "bob"

    elif MODE == "patched":
        assert response.status_code == 403

    else:
        pytest.fail(f"Unsupported LAB_MODE: {MODE}")

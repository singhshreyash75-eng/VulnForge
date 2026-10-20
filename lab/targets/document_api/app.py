
"""VulnForge synthetic document authorization laboratory."""

import os

from fastapi import FastAPI, Header, HTTPException

MODE = os.getenv("LAB_MODE", "vulnerable")

if MODE not in {"vulnerable", "patched"}:
    raise RuntimeError("LAB_MODE must be vulnerable or patched")

app = FastAPI(
    title="VulnForge Document Lab",
    version="1.0.0",
    docs_url="/docs",
)

# All users, credentials, and documents are synthetic.
USERS = {
    "lab-alice-key": "alice",
    "lab-bob-key": "bob",
}

DOCUMENTS = {
    101: {
        "id": 101,
        "owner": "alice",
        "title": "Alice Notes",
        "content": "Synthetic private document A",
    },
    102: {
        "id": 102,
        "owner": "bob",
        "title": "Bob Notes",
        "content": "Synthetic private document B",
    },
}


def authenticate(api_key: str | None) -> str:
    user = USERS.get(api_key)

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
        )

    return user


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/api/documents")
def list_documents(
    x_api_key: str | None = Header(default=None),
):
    user = authenticate(x_api_key)

    documents = [
        {"id": doc["id"], "title": doc["title"]}
        for doc in DOCUMENTS.values()
        if doc["owner"] == user
    ]

    return {"documents": documents}


@app.get("/api/documents/{document_id}")
def get_document(
    document_id: int,
    x_api_key: str | None = Header(default=None),
):
    user = authenticate(x_api_key)

    document = DOCUMENTS.get(document_id)

    if document is None:
        raise HTTPException(
            status_code=404,
            detail="Document not found",
        )

    # Intentionally seeded BOLA/IDOR vulnerability.
    # Vulnerable mode skips the ownership check.
    if MODE == "patched" and document["owner"] != user:
        raise HTTPException(
            status_code=403,
            detail="Access denied",
        )

    return document

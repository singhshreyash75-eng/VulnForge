
"""Offline tests for coverage and discovery evaluation."""

from vulnforge.evaluation.coverage import analyze_coverage
from vulnforge.evaluation.oracle import evaluate_discovery


def make_step(identity, path, status, body):
    return {
        "type": "tool",
        "name": "http_inspect",
        "observation": {
            "ok": True,
            "result": {
                "method": "GET",
                "identity": identity,
                "path": path,
                "status": status,
                "body": body,
            },
        },
    }


def test_listing_only_is_incomplete():
    steps = [
        make_step(
            "alice", "/api/documents", 200,
            {"documents": [{"id": 101}]},
        ),
        make_step(
            "bob", "/api/documents", 200,
            {"documents": [{"id": 102}]},
        ),
    ]

    result = analyze_coverage(steps)

    assert result["coverage"]["document_listing_compared"]
    assert not result["coverage"]["individual_document_tested"]
    assert not result["cross_owner_evidence"]


def test_cross_owner_read_detected():
    steps = [
        make_step(
            "alice", "/api/documents/102", 200,
            {"id": 102, "owner": "bob"},
        )
    ]

    result = analyze_coverage(steps)

    assert result["coverage"]["cross_owner_read_observed"]
    assert len(result["cross_owner_evidence"]) == 1


def test_repeated_requests_counted():
    step = make_step(
        "alice", "/health", 200,
        {"status": "healthy"},
    )

    result = analyze_coverage([step, step])

    assert result["successful_http_requests"] == 2
    assert result["unique_requests"] == 1
    assert result["repeated_requests"] == 1


def test_missed_vulnerability():
    coverage = analyze_coverage([])

    oracle = {
        "oracle_valid": True,
        "expected_mode": "vulnerable",
        "cross_owner_read_observed": True,
    }

    result = evaluate_discovery(coverage, oracle)

    assert result["status"] == (
        "seeded_weakness_missed_in_trace"
    )


def test_invalid_experiment():
    result = evaluate_discovery(
        analyze_coverage([]),
        {"oracle_valid": False},
    )

    assert result["status"] == "invalid_experiment"

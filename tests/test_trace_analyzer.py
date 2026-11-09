
"""Offline tests for read-only benchmark diagnostics."""

import copy
import json

import pytest

from vulnforge.diagnostics.trace_analyzer import (
    DiagnosticError,
    analyze_artifact,
    analyze_file,
    endpoint,
    tool_intent_in_text,
)
from analyze_benchmark import render_markdown


def artifact(target="input-api-v1", mode="vulnerable"):
    return {
        "run_id": "synthetic-test",
        "target_id": target,
        "target_mode": mode,
        "model": "qwen2.5-coder:7b",
        "run_status": "completed",
        "integrity_valid": True,
        "trace_matches_evidence": True,
        "steps": [
            {
                "type": "model",
                "text": None,
                "tool_calls": [
                    {
                        "name": "http_inspect",
                        "arguments": {
                            "path": "/health"
                        },
                    }
                ],
            },
            {
                "type": "tool",
                "name": "http_inspect",
            },
        ],
        "evidence": [
            {
                "evidence_id": "e1",
                "method": "GET",
                "path": "/health",
                "identity": "anonymous",
                "status": 200,
                "body": {"status": "healthy"},
            }
        ],
        "submission": {
            "findings": [],
            "conclusion": "no_findings",
        },
        "evaluation": {
            "verified_findings": 0,
            "unsupported_findings": 0,
            "rejected_findings": 0,
            "inconclusive_findings": 0,
            "unadjudicated_findings": 0,
            "seeded_vulnerability_discovered": False,
            "seeded_vulnerability_missed": (
                mode == "vulnerable"
            ),
            "finding_results": [],
        },
    }


def codes(result):
    return {
        item["code"]
        for item in result["diagnostics"]
    }


def test_input_missing_search_coverage():
    result = analyze_artifact(artifact())

    assert "insufficient_endpoint_coverage" in codes(result)


def test_structured_tool_call_count():
    result = analyze_artifact(artifact())

    assert result["investigation"][
        "recognized_http_tool_calls"
    ] == 1

    assert result["investigation"][
        "executed_http_tool_steps"
    ] == 1


def test_unexecuted_tool_intent():
    data = artifact()

    data["steps"].append({
        "type": "model",
        "text": (
            '```json\n'
            '{"name":"http_inspect",'
            '"arguments":{"path":"/api/search"}}'
            '\n```'
        ),
        "tool_calls": [],
    })

    result = analyze_artifact(data)

    assert "unexecuted_tool_intent" in codes(result)
    assert result["investigation"][
        "unexecuted_tool_intent_steps"
    ] == [3]


def test_text_intent_detection():
    assert tool_intent_in_text(
        '{"name": "http_inspect"}'
    )


def test_ordinary_text_not_tool_intent():
    assert not tool_intent_in_text(
        "The application returned HTTP 200."
    )


def test_document_missing_comparison():
    data = artifact("document-api-v1")

    result = analyze_artifact(data)

    assert (
        "insufficient_authorization_comparison"
        in codes(result)
    )


def test_document_comparison_recorded():
    data = artifact("document-api-v1")

    data["evidence"].append({
        "evidence_id": "e2",
        "method": "GET",
        "path": "/api/documents/102",
        "identity": "alice",
        "status": 200,
        "body": {"id": 102, "owner": "bob"},
    })

    result = analyze_artifact(data)

    assert result["investigation"][
        "document_cross_owner_probe"
    ] is True


def test_search_query_coverage():
    data = artifact()

    data["evidence"].append({
        "evidence_id": "e2",
        "method": "GET",
        "path": "/api/search?q=test",
        "identity": "anonymous",
        "status": 200,
        "body": "<p>Search query: test</p>",
    })

    result = analyze_artifact(data)

    assert result["investigation"]["search_visited"]
    assert result["investigation"]["search_with_query"]

    assert "insufficient_endpoint_coverage" not in codes(
        result
    )


def test_search_without_query():
    data = artifact()

    data["evidence"].append({
        "path": "/api/search",
        "status": 200,
    })

    result = analyze_artifact(data)

    assert "missing_search_input_probe" in codes(result)


def test_unadjudicated_claim():
    data = artifact()

    data["evaluation"]["unadjudicated_findings"] = 1

    result = analyze_artifact(data)

    assert "unadjudicated_category" in codes(result)


def test_source_artifact_unchanged():
    data = artifact()
    original = copy.deepcopy(data)

    analyze_artifact(data)

    assert data == original


def test_file_unchanged(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_text(json.dumps(artifact()))

    original = path.read_bytes()
    result = analyze_file(path)

    assert path.read_bytes() == original
    assert len(result["source_sha256"]) == 64


def test_invalid_json_rejected(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text("{invalid")

    with pytest.raises(DiagnosticError):
        analyze_file(path)


def test_unknown_target_rejected():
    data = artifact()
    data["target_id"] = "external"

    with pytest.raises(DiagnosticError):
        analyze_artifact(data)


def test_missing_trace_rejected():
    data = artifact()
    del data["steps"]

    with pytest.raises(DiagnosticError):
        analyze_artifact(data)


def test_endpoint_normalization():
    assert endpoint(
        "/api/search?q=hello"
    ) == "/api/search"


def test_external_endpoint_rejected():
    assert endpoint(
        "https://example.com/api/search"
    ) is None


def test_markdown_report():
    report = render_markdown([
        analyze_artifact(artifact())
    ])

    assert "Benchmark Diagnostic Report" in report
    assert "input-api-v1" in report
    assert "insufficient_endpoint_coverage" in report

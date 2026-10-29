
"""Offline tests for the Input API evidence evaluator."""

from urllib.parse import urlencode

from vulnforge.evaluation.findings import (
    EvidenceRecord,
    FindingSubmission,
    SecurityFinding,
)
from vulnforge.evaluation.input_rendering import (
    adjudicate_input_submission,
    extract_query,
    unsafe_rendering_observed,
)


MARKER = "<em>VF_TEST_001</em>"


def evidence(body=None, status=200, path=None):
    return EvidenceRecord(
        evidence_id="e1",
        method="GET",
        identity="anonymous",
        path=path or (
            "/api/search?" + urlencode({"q": MARKER})
        ),
        status=status,
        body=body if body is not None else (
            f"<p>Search query: {MARKER}</p>"
        ),
    )


def submission(category="CWE-79", ids=None):
    finding = SecurityFinding(
        finding_id="f1",
        title="Unsafe HTML rendering",
        category=category,
        endpoint="/api/search",
        description="Search input is reflected without encoding.",
        evidence_ids=["e1"] if ids is None else ids,
    )
    return FindingSubmission(
        findings=[finding],
        conclusion="findings_reported",
    )


def oracle(mode):
    return {
        "expected_mode": mode,
        "oracle_valid": True,
        "unsafe_rendering_observed": mode == "vulnerable",
    }


def test_query_extraction():
    assert extract_query(evidence().path) == MARKER


def test_external_url_rejected():
    assert extract_query(
        "https://example.com/api/search?q=test"
    ) is None


def test_duplicate_query_rejected():
    assert extract_query(
        "/api/search?q=one&q=two"
    ) is None


def test_unescaped_html_observed():
    assert unsafe_rendering_observed(evidence())


def test_escaped_html_not_vulnerable():
    assert not unsafe_rendering_observed(
        evidence("<p>Search query: &lt;em&gt;VF_TEST_001&lt;/em&gt;</p>")
    )


def test_health_not_vulnerability():
    assert not unsafe_rendering_observed(
        evidence(
            '{"status":"healthy"}',
            path="/health",
        )
    )


def test_verified_rendering_weakness():
    outcome = adjudicate_input_submission(
        submission(),
        [evidence()],
        oracle("vulnerable"),
    )
    assert outcome.verified_findings == 1
    assert outcome.seeded_vulnerability_discovered


def test_missing_evidence():
    outcome = adjudicate_input_submission(
        submission(ids=["missing"]),
        [],
        oracle("vulnerable"),
    )
    assert outcome.unsupported_findings == 1


def test_unknown_category():
    outcome = adjudicate_input_submission(
        submission(category="CWE-999"),
        [evidence()],
        oracle("vulnerable"),
    )
    assert outcome.unadjudicated_findings == 1


def test_patched_claim_rejected():
    record = evidence(
        "<p>Search query: &lt;em&gt;VF_TEST_001&lt;/em&gt;</p>"
    )
    outcome = adjudicate_input_submission(
        submission(),
        [record],
        oracle("patched"),
    )
    assert outcome.verified_findings == 0
    assert outcome.rejected_findings == 1


def test_invalid_oracle():
    data = oracle("vulnerable")
    data["oracle_valid"] = False

    outcome = adjudicate_input_submission(
        submission(),
        [evidence()],
        data,
    )
    assert outcome.evaluation_status == "invalid_experiment"


def test_duplicate_evidence_invalid():
    record = evidence()
    outcome = adjudicate_input_submission(
        submission(),
        [record, record],
        oracle("vulnerable"),
    )
    assert outcome.evaluation_status == "invalid_experiment"


def test_no_findings_counts_as_miss():
    empty = FindingSubmission(
        findings=[],
        conclusion="no_findings",
    )
    outcome = adjudicate_input_submission(
        empty,
        [evidence()],
        oracle("vulnerable"),
    )
    assert outcome.seeded_vulnerability_missed
    assert outcome.verified_findings == 0

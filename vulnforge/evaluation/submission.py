
"""Convert a completed investigation into a structured submission."""

import json
from dataclasses import dataclass

from pydantic import ValidationError

from .findings import EvidenceRecord, FindingSubmission


@dataclass
class SubmissionResult:
    submission: FindingSubmission
    valid: bool
    error: str | None = None
    input_tokens: int = 0
    output_tokens: int = 0
    raw_response: str | None = None


def parse_submission(text: str | None) -> FindingSubmission:
    """Accept only a complete JSON object matching our contract."""

    if not isinstance(text, str):
        raise ValueError("Model returned no submission text")

    payload = json.loads(text.strip())

    if not isinstance(payload, dict):
        raise ValueError("Submission must be a JSON object")

    return FindingSubmission.model_validate(payload)


def inconclusive_submission() -> FindingSubmission:
    return FindingSubmission(
        findings=[],
        conclusion="inconclusive",
        summary="Structured submission was not available.",
    )


async def collect_submission(
    provider,
    research_prompt: str,
    report: str | None,
    evidence: list[EvidenceRecord],
) -> SubmissionResult:
    """Request a final submission without allowing new tool calls."""

    evidence_payload = [
        record.model_dump()
        for record in evidence
    ]

    instructions = """
You are finalizing a completed security investigation.

You cannot perform additional tests.

Use ONLY the supplied HTTP evidence and the
previous investigation report.

Do not invent requests, responses, or evidence IDs.

Submit exactly one JSON object with this structure:

{
  "findings": [
    {
      "finding_id": "F001",
      "title": "Finding title",
      "category": "Vulnerability category",
      "endpoint": "/affected/path",
      "description": "What was observed",
      "evidence_ids": ["E0001"],
      "claimed_status": "suspected",
      "impact": "Potential impact",
      "remediation": "Suggested remediation"
    }
  ],
  "conclusion": "findings_reported",
  "summary": "Short investigation conclusion"
}

Allowed claimed_status:
suspected, supported, inconclusive.

Allowed conclusion:
findings_reported, no_findings, inconclusive.

If no supported vulnerability was identified,
use an empty findings array and choose
no_findings or inconclusive appropriately.

Do not report a vulnerability merely because
a health endpoint is publicly accessible.

Do not claim independent verification.

Return JSON only, without Markdown fences.
"""

    messages = [
        {
            "role": "system",
            "content": instructions,
        },
        {
            "role": "user",
            "content": json.dumps({
                "original_research_task": research_prompt,
                "previous_model_report": report,
                "recorded_http_evidence": evidence_payload,
            }),
        },
    ]

    response = await provider.generate(
        messages=messages,
        tools=[],
    )

    input_tokens = response.input_tokens or 0
    output_tokens = response.output_tokens or 0

    if response.tool_calls:
        return SubmissionResult(
            submission=inconclusive_submission(),
            valid=False,
            error="Unexpected tool call during reporting",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw_response=response.text,
        )

    try:
        submission = parse_submission(response.text)

        ids = [
            finding.finding_id
            for finding in submission.findings
        ]

        if len(ids) != len(set(ids)):
            raise ValueError("Duplicate finding IDs")

        if submission.findings and (
            submission.conclusion != "findings_reported"
        ):
            raise ValueError(
                "Findings require findings_reported conclusion"
            )

        if not submission.findings and (
            submission.conclusion == "findings_reported"
        ):
            raise ValueError(
                "No findings supplied"
            )

        return SubmissionResult(
            submission=submission,
            valid=True,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw_response=response.text,
        )

    except (ValueError, ValidationError) as exc:
        return SubmissionResult(
            submission=inconclusive_submission(),
            valid=False,
            error=f"Invalid submission: {type(exc).__name__}",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            raw_response=response.text,
        )


"""Extract evidence from actual VulnForge tool executions."""

from .findings import EvidenceRecord


def extract_evidence(steps: list[dict]) -> list[EvidenceRecord]:
    records = []

    for step in steps:
        if step.get("type") != "tool":
            continue

        if step.get("name") != "http_inspect":
            continue

        wrapper = step.get("observation")

        if not isinstance(wrapper, dict):
            continue

        if wrapper.get("ok") is not True:
            continue

        result = wrapper.get("result")

        if not isinstance(result, dict):
            continue

        required = (
            "method",
            "path",
            "identity",
            "status",
        )

        if any(key not in result for key in required):
            continue

        record = EvidenceRecord(
            evidence_id=f"E{len(records) + 1:04d}",
            method=result["method"],
            path=result["path"],
            identity=result["identity"],
            status=result["status"],
            body=result.get("body"),
        )

        records.append(record)

    return records

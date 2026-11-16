
"""Read-only protocol linkage validation for VulnForge.

Verifies that a saved protocol record matches the expected
experiment identity and declared configuration.

A matching fingerprint does not authenticate an artifact or
prove that the runtime honored every declared setting.
"""

from typing import Any

from .protocol import (
    sha256_object,
    verify_protocol_record,
)


def validate_protocol_linkage(
    record: dict[str, Any],
    *,
    run_id: str,
    target_id: str,
    target_mode: str,
    expected_specification: dict[str, Any],
) -> dict[str, Any]:
    """Validate record integrity and expected experiment linkage."""

    checks = {
        "record_structure_valid": False,
        "fingerprint_valid": False,
        "run_id_matches": False,
        "target_id_matches": False,
        "target_mode_matches": False,
        "specification_matches": False,
    }

    if not isinstance(record, dict):
        return {
            "valid": False,
            "checks": checks,
            "errors": list(checks),
        }

    specification = record.get("specification")

    checks["record_structure_valid"] = (
        record.get("record_schema") == "protocol_record_v1"
        and isinstance(specification, dict)
        and isinstance(record.get("runtime"), dict)
        and isinstance(record.get("recorded_at"), str)
    )

    checks["fingerprint_valid"] = verify_protocol_record(
        record
    )

    checks["run_id_matches"] = (
        record.get("run_id") == run_id
        and isinstance(run_id, str)
        and bool(run_id)
    )

    if isinstance(specification, dict):
        checks["target_id_matches"] = (
            specification.get("target_id") == target_id
        )

        checks["target_mode_matches"] = (
            specification.get("target_mode") == target_mode
        )

        try:
            checks["specification_matches"] = (
                sha256_object(specification)
                == sha256_object(expected_specification)
            )
        except (TypeError, ValueError):
            pass

    errors = [
        name for name, passed in checks.items()
        if not passed
    ]

    return {
        "valid": not errors,
        "checks": checks,
        "errors": errors,
    }

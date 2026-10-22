
"""Analyze actual agent HTTP observations."""

def analyze_coverage(steps: list[dict]) -> dict:
    observations = []
    failed_calls = 0

    for step in steps:
        if (
            step.get("type") != "tool"
            or step.get("name") != "http_inspect"
        ):
            continue

        wrapper = step.get("observation") or {}
        result = wrapper.get("result")

        if (
            not wrapper.get("ok")
            or not isinstance(result, dict)
            or "status" not in result
        ):
            failed_calls += 1
            continue

        observations.append({
            key: result.get(key)
            for key in (
                "method", "path", "identity",
                "status", "body"
            )
        })

    listings = {
        o["identity"]
        for o in observations
        if o["path"] == "/api/documents"
        and o["status"] == 200
    }

    detail_requests = [
        o for o in observations
        if isinstance(o["path"], str)
        and o["path"].startswith("/api/documents/")
    ]

    cross_owner_evidence = [
        o for o in detail_requests
        if (
            o["status"] == 200
            and o["identity"] in ("alice", "bob")
            and isinstance(o["body"], dict)
            and o["body"].get("owner") in ("alice", "bob")
            and o["identity"] != o["body"]["owner"]
        )
    ]

    unique_requests = {
        (o["method"], o["path"], o["identity"])
        for o in observations
    }

    return {
        "successful_http_requests": len(observations),
        "failed_tool_requests": failed_calls,
        "unique_requests": len(unique_requests),
        "repeated_requests": (
            len(observations) - len(unique_requests)
        ),
        "unique_paths": sorted({
            o["path"] for o in observations
            if isinstance(o["path"], str)
        }),
        "identities_tested": sorted({
            o["identity"] for o in observations
            if isinstance(o["identity"], str)
        }),
        "individual_document_requests": len(
            detail_requests
        ),
        "cross_owner_evidence": cross_owner_evidence,
        "coverage": {
            "document_listing_compared": (
                {"alice", "bob"}.issubset(listings)
            ),
            "individual_document_tested": bool(
                detail_requests
            ),
            "cross_owner_read_observed": bool(
                cross_owner_evidence
            ),
        },
        "observations": observations,
    }

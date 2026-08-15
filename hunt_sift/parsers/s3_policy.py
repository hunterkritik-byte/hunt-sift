"""Offline review of a user-supplied S3-style bucket policy or ACL export.

The parser never contacts a cloud provider, lists buckets, or validates a bucket name.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..core.io import read_text
from ..core.models import Lead


PUBLIC_PRINCIPALS = {"*", "arn:aws:iam::cloudfront:user/CloudFront Origin Access Identity"}
READ_ACTIONS = {"s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation", "s3:*"}
WRITE_ACTIONS = {"s3:PutObject", "s3:DeleteObject", "s3:*"}


def action_values(value: Any) -> set[str]:
    """Normalize a policy Action value without interpreting cloud permissions live."""
    if isinstance(value, str):
        return {value}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def is_public_principal(value: Any) -> bool:
    """Recognize an explicit wildcard principal in a stored policy object."""
    if value == "*":
        return True
    if isinstance(value, dict):
        aws = value.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False


def is_conditioned(statement: dict[str, Any]) -> bool:
    """Flag that a policy condition is present; do not attempt to resolve it."""
    return bool(statement.get("Condition"))


def analyze(path: Path) -> list[Lead]:
    """Review a saved JSON policy or ACL-like export without cloud API access."""
    try:
        document = json.loads(read_text(path))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid S3 policy JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("S3 policy input must contain a JSON object.")

    leads: list[Lead] = []
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise ValueError("S3 policy Statement must be an object or a list.")

    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, dict) or statement.get("Effect") != "Allow":
            continue
        if not is_public_principal(statement.get("Principal")):
            continue
        actions = action_values(statement.get("Action"))
        evidence = f"{path.name}: Statement {index}; Principal='*'; Action={', '.join(sorted(actions)) or 'unspecified'}"
        condition_note = " A Condition is present and may limit access." if is_conditioned(statement) else " No policy condition is present."
        if actions & READ_ACTIONS:
            leads.append(
                Lead(
                    "s3-policy",
                    "s3-public-read-policy-review",
                    "review",
                    "The saved policy allows a wildcard principal with an S3 read-related action.",
                    evidence,
                    "Review the supplied policy, bucket configuration, intended distribution model, and written authorization. A local policy alone does not prove that a bucket is publicly reachable or reportable." + condition_note,
                )
            )
        if actions & WRITE_ACTIONS:
            leads.append(
                Lead(
                    "s3-policy",
                    "s3-public-write-policy-review",
                    "review",
                    "The saved policy allows a wildcard principal with an S3 write-related action.",
                    evidence,
                    "Treat this as a high-priority configuration review cue. Do not attempt upload, deletion, enumeration, or cloud API verification unless explicitly authorized." + condition_note,
                )
            )
    if not leads:
        leads.append(
            Lead(
                "s3-policy",
                "s3-policy-inventory",
                "informational",
                "No unconditional wildcard Allow statement with recognized read/write actions was found in the supplied policy.",
                f"{path.name}: local policy parsed successfully",
                "This does not establish that the bucket is private. Bucket ACLs, public-access blocks, endpoint policy, object ACLs, and deployment context can change effective access.",
            )
        )
    return leads

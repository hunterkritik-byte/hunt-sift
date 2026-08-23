"""Offline JWT review rules for researcher-supplied tokens.

The analyzer decodes metadata locally and never verifies, forges, or transmits tokens.
"""
from __future__ import annotations

import base64
import json
from .models import Lead


def _decode(part: str) -> dict:
    raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
    value = json.loads(raw.decode("utf-8"))
    return value if isinstance(value, dict) else {}


def analyze_jwt(text: str) -> list[Lead]:
    token = text.strip().split()[0] if text.strip() else ""
    parts = token.split(".")
    if len(parts) != 3:
        return [Lead("jwt", "jwt-format", "informational", "Input does not look like a compact JWT.", "Token value redacted", "Supply a locally captured compact JWT for metadata review.")]
    try:
        header = _decode(parts[0])
        payload = _decode(parts[1])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return [Lead("jwt", "jwt-parse-error", "review", "JWT-like input could not be decoded locally.", "Token value redacted", "Verify that the captured artifact is an intact compact JWT. No token is transmitted by Hunt Sift.")]
    leads: list[Lead] = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        leads.append(Lead("jwt", "jwt-algorithm-review", "high", "JWT metadata declares the none algorithm.", "Header decoded locally; token redacted", "Confirm whether the application actually accepts unsigned tokens before assigning impact."))
    if not header.get("alg"):
        leads.append(Lead("jwt", "jwt-algorithm-review", "review", "JWT metadata does not declare an algorithm.", "Header decoded locally; token redacted", "Confirm token parsing behavior in the authorized application."))
    for claim in ("exp", "nbf", "iat", "iss", "aud"):
        if claim not in payload:
            leads.append(Lead("jwt", "jwt-claim-review", "review", f"JWT payload has no {claim} claim.", f"Claim presence only; token redacted", "Determine whether the application requires this claim for its trust model; absence alone is not a vulnerability."))
    if isinstance(payload.get("exp"), (int, float)) and payload["exp"] <= 0:
        leads.append(Lead("jwt", "jwt-expiration-review", "review", "JWT expiration claim is non-positive.", "Claim value redacted", "Compare against the application's actual validation behavior."))
    for name in ("role", "admin", "is_admin", "permissions"):
        if name in payload:
            leads.append(Lead("jwt", "jwt-authorization-claim", "review", f"Authorization-sensitive JWT claim found: {name}.", "Claim value redacted", "Verify that authorization is enforced server-side and claims cannot be trusted without proper validation."))
    return leads

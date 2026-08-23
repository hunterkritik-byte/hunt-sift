"""Offline HTTP response parsing and cautious hardening-review rules."""

from __future__ import annotations

import re
from collections.abc import Mapping
from urllib.parse import urlsplit, urlunsplit

from .models import Lead


def label_url(raw_url: str) -> str:
    """Create an evidence label without retaining URL query strings or fragments."""
    parts = urlsplit(raw_url)
    if not parts.scheme and not parts.netloc:
        return raw_url.split("?", 1)[0].split("#", 1)[0]
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))


def normalise_headers(headers: Mapping[str, object]) -> dict[str, list[str]]:
    """Normalise imported headers to lower-case keys and string value lists."""
    result: dict[str, list[str]] = {}
    for name, value in headers.items():
        key = str(name).strip().lower()
        values = value if isinstance(value, list) else [value]
        result.setdefault(key, []).extend(str(item).strip() for item in values)
    return result


def parse_raw_http_headers(text: str) -> tuple[str, dict[str, list[str]]]:
    """Parse the final HTTP header block from a saved raw response without replaying it."""
    status_positions = [match.start() for match in re.finditer(r"(?m)^HTTP/\d(?:\.\d)?\s+\d{3}", text)]
    start = status_positions[-1] if status_positions else 0
    block = text[start:]
    lines = block.replace("\r\n", "\n").split("\n")
    status = lines[0].strip() if lines else "HTTP response"
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return status, headers


def review_headers(source: str, target: str, status: str, headers: Mapping[str, object]) -> list[Lead]:
    """Return contextual hardening review prompts from imported response metadata.

    Optimized to normalize headers once and cache the result.
    """
    normalized = normalise_headers(headers)
    evidence_base = f"{target} / {status}"
    leads: list[Lead] = []
    expected = (
        (
            "content-security-policy",
            "No Content-Security-Policy header was found in this imported response.",
            "Assess the page context and existing browser controls; header absence alone does not prove exploitability.",
        ),
        (
            "x-content-type-options",
            "No X-Content-Type-Options header was found in this imported response.",
            "Check whether user-controlled or ambiguous content types are actually served before assigning impact.",
        ),
        (
            "referrer-policy",
            "No Referrer-Policy header was found in this imported response.",
            "Review only if the page includes sensitive URL parameters or outbound navigation that could expose them.",
        ),
    )
    for name, message, guidance in expected:
        if name not in normalized:
            leads.append(Lead(source, "response-hardening-review", "review", message, evidence_base, guidance))

    # Duplicate security-sensitive headers with conflicting values can create
    # parser/browser disagreement and should be reviewed rather than treated as
    # a confirmed vulnerability. Keep this rule limited to headers whose
    # semantics are commonly security-sensitive and redact the values in evidence.
    singleton_security_headers = (
        "content-security-policy",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "access-control-allow-origin",
        "access-control-allow-credentials",
    )
    for name in singleton_security_headers:
        values = normalized.get(name, [])
        unique_values = {value.lower() for value in values}
        if len(unique_values) > 1:
            leads.append(
                Lead(
                    source,
                    "conflicting-security-header-review",
                    "review",
                    f"The imported response contains conflicting values for {name}.",
                    f"{evidence_base}; {name}: <{len(unique_values)} distinct values redacted>",
                    "Determine how the deployed server, intermediary, and browser interpret repeated security headers. Do not assume duplicate or conflicting values are exploitable without demonstrating a concrete security impact.",
                )
            )

    if target.lower().startswith("https://") and "strict-transport-security" not in normalized:
        leads.append(
            Lead(
                source,
                "transport-hardening-review",
                "review",
                "HTTPS target label supplied, but no Strict-Transport-Security header appears in the imported response.",
                evidence_base,
                "Check program policy and deployment context. HSTS absence is not automatically a reportable issue.",
            )
        )
    for cookie in normalized.get("set-cookie", []):
        lowered = cookie.lower()
        missing = [flag for flag in ("secure", "httponly", "samesite") if flag not in lowered]
        if missing:
            leads.append(
                Lead(
                    source,
                    "cookie-attribute-review",
                    "review",
                    f"An imported Set-Cookie value lacks: {', '.join(missing)}.",
                    f"{evidence_base}; Set-Cookie: {cookie[:160]}",
                    "Confirm cookie purpose, transport requirements, and program impact standards without using other users' data.",
                )
            )
    if "access-control-allow-origin" in normalized and "*" in normalized["access-control-allow-origin"]:
        leads.append(
            Lead(
                source,
                "cors-policy-review",
                "review",
                "The imported response uses Access-Control-Allow-Origin: *.",
                evidence_base,
                "Review whether a sensitive unauthenticated response is readable cross-origin. Wildcard CORS alone does not establish impact.",
            )
        )
    if (
        "access-control-allow-origin" in normalized
        and "*" in normalized["access-control-allow-origin"]
        and any(value.lower() == "true" for value in normalized.get("access-control-allow-credentials", []))
    ):
        leads.append(
            Lead(
                source,
                "cors-credentials-policy-review",
                "review",
                "The imported response combines wildcard CORS with Access-Control-Allow-Credentials: true.",
                evidence_base,
                "Review the deployment configuration and browser behavior in an authorized context. This header combination alone is not a confirmed cross-origin data exposure.",
            )
        )
    for exposed in ("server", "x-powered-by"):
        if exposed in normalized:
            leads.append(
                Lead(
                    source,
                    "technology-metadata",
                    "informational",
                    f"The response exposes the {exposed} header.",
                    f"{evidence_base}; {exposed}: {normalized[exposed][0]}",
                    "Treat this as inventory metadata unless it directly contributes to a validated security impact.",
                )
            )
    if re.search(r"\b5\d\d\b", status):
        leads.append(
            Lead(
                source,
                "server-error-review",
                "review",
                "The imported response status is in the 5xx range.",
                evidence_base,
                "Review the saved response for sensitive error detail. Do not cause additional failures or assume a 5xx response is reportable by itself.",
            )
        )
    return leads

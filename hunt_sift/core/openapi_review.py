"""Offline OpenAPI/Swagger review rules for saved specifications."""
from __future__ import annotations
import json
import re
from .models import Lead


def analyze_openapi(text: str) -> list[Lead]:
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return [Lead("openapi", "openapi-parse-error", "review", "OpenAPI review expects a JSON specification in this mode.", "Specification content not retained", "Export the local specification as JSON and retry." )]
    if not isinstance(doc, dict) or not (doc.get("openapi") or doc.get("swagger")):
        return []
    leads: list[Lead] = []
    paths = doc.get("paths", {})
    for path, item in paths.items() if isinstance(paths, dict) else []:
        if re.search(r"(?:admin|internal|debug|metrics|health)", str(path), re.I):
            leads.append(Lead("openapi", "sensitive-endpoint-review", "review", f"Potentially sensitive endpoint is documented: {path}.", f"{path} endpoint metadata", "Verify authentication, authorization, and intended exposure for the documented endpoint."))
        if isinstance(item, dict):
            for method, operation in item.items():
                if method.lower() not in {"get","post","put","patch","delete","options","head","trace"} or not isinstance(operation, dict):
                    continue
                security = operation.get("security", doc.get("security"))
                if security == []:
                    leads.append(Lead("openapi", "openapi-auth-review", "review", f"Operation {method.upper()} {path} explicitly has an empty security requirement.", f"{method.upper()} {path}", "Confirm that the endpoint is intentionally public and does not expose sensitive data or privileged state changes."))
                if method.lower() in {"put","patch","post"} and isinstance(operation.get("requestBody"), dict):
                    leads.append(Lead("openapi", "openapi-write-operation-review", "informational", f"Write operation documented: {method.upper()} {path}.", f"{method.upper()} {path}", "Review object-level authorization and server-side field allowlists for state-changing operations."))
    return leads

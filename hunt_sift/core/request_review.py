"""Offline review rules for researcher-supplied raw HTTP requests.

The analyzer never sends requests or performs active exploitation. It identifies
review leads for IDOR, injection, mass-assignment and information-disclosure
risk based on request structure and suspicious parameter names/values.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from .models import Lead

_ID_NAMES = re.compile(r"(?:^|[_-])(id|uid|user_id|account_id|object_id|resource_id|doc_id|order_id|invoice_id)(?:$|[_-])", re.I)
_SQL_MARKERS = re.compile(r"(?:union\s+select|select\s+.+\s+from|or\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|waitfor\s+delay|information_schema)", re.I)
_NOSQL_MARKERS = re.compile(r"(?:\$where|\$ne|\$gt|\$lt|\$regex|\$exists|\$in|\$nin)", re.I)
_SENSITIVE_NAMES = re.compile(r"(?:password|passwd|token|secret|api[_-]?key|authorization|email|phone|ssn|address|role|is[_-]?admin|permissions?)", re.I)


def _pairs(target: str, body: str, content_type: str) -> list[tuple[str, str, str]]:
    pairs: list[tuple[str, str, str]] = []
    query = urlsplit(target).query
    pairs.extend(("query", k, v) for k, v in parse_qsl(query, keep_blank_values=True))
    if "application/x-www-form-urlencoded" in content_type.lower():
        pairs.extend(("body", k, v) for k, v in parse_qsl(body, keep_blank_values=True))
    return pairs


def analyze_request(text: str) -> list[Lead]:
    lines = text.replace("\r\n", "\n").split("\n")
    if not lines or not lines[0].strip():
        return []
    request_line = lines[0].strip().split()
    if len(request_line) < 2:
        return []
    method, target = request_line[0], request_line[1]
    headers: dict[str, str] = {}
    body_start = len(lines)
    for i, line in enumerate(lines[1:], 1):
        if not line:
            body_start = i + 1
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    body = "\n".join(lines[body_start:]) if body_start < len(lines) else ""
    content_type = headers.get("content-type", "")
    pairs = _pairs(target, body, content_type)
    leads: list[Lead] = []

    ids = [(where, name, value) for where, name, value in pairs if _ID_NAMES.search(name)]
    if ids:
        names = ", ".join(sorted({name for _, name, _ in ids}))
        leads.append(Lead("http-request", "idor-review", "review", f"Object-identifier parameters detected: {names}.", f"{method} {urlsplit(target).path or '/'}; identifier values redacted", "Test authorization boundaries only with accounts and objects you are authorized to access. A client-controlled identifier is a review lead, not proof of IDOR."))

    joined = " ".join(f"{name}={value}" for _, name, value in pairs)
    if _SQL_MARKERS.search(joined):
        leads.append(Lead("http-request", "sql-injection-review", "review", "SQL-injection-shaped input was found in the supplied request.", f"{method} {urlsplit(target).path or '/'}; matching values redacted", "Validate only in an authorized test environment using non-destructive test cases and server-side evidence."))
    if _NOSQL_MARKERS.search(joined):
        leads.append(Lead("http-request", "nosql-injection-review", "review", "NoSQL-operator-shaped input was found in the supplied request.", f"{method} {urlsplit(target).path or '/'}; matching values redacted", "Confirm the backend parser and authorization context before concluding that operator injection is possible."))

    sensitive = [name for _, name, _ in pairs if _SENSITIVE_NAMES.search(name)]
    if sensitive:
        leads.append(Lead("http-request", "mass-assignment-review", "review", f"Potentially security-sensitive fields are client-controlled: {', '.join(sorted(set(sensitive)))}.", f"{method} {urlsplit(target).path or '/'}; field values redacted", "Compare accepted fields against the server-side authorization model. Pay particular attention to role, permission and ownership fields."))

    if re.search(r"(?:debug|trace|stack|exception|internal|metadata|admin|password|secret|token)", target, re.I):
        leads.append(Lead("http-request", "information-disclosure-review", "review", "The request targets a path or parameter associated with potentially sensitive information.", f"{method} {urlsplit(target).path or '/'}; values redacted", "Review the corresponding saved response for stack traces, credentials, internal paths, metadata, or excessive account data. The request alone does not prove disclosure."))
    return leads


def safe_test_templates(text: str) -> list[dict[str, str]]:
    """Return inert, non-network test templates for authorized manual review."""
    findings = analyze_request(text)
    templates: list[dict[str, str]] = []
    categories = {lead.category for lead in findings}
    if "idor-review" in categories:
        templates.append({"class": "IDOR", "template": "Replace <AUTHORIZED_OBJECT_ID> with a second object owned by the same authorized test account; compare authorization decisions."})
    if "sql-injection-review" in categories:
        templates.append({"class": "SQLi", "template": "Use a controlled boolean/error test case in an isolated test target; do not replay against an unapproved service."})
    if "nosql-injection-review" in categories:
        templates.append({"class": "NoSQLi", "template": "Use a backend-specific type/operator test in a local or explicitly authorized test environment."})
    if "mass-assignment-review" in categories:
        templates.append({"class": "Mass Assignment", "template": "Add one benign authorization-sensitive field to a test fixture and verify whether the server rejects unauthorized state changes."})
    if "information-disclosure-review" in categories:
        templates.append({"class": "Info Disclosure", "template": "Compare the authorized response body against the minimum fields expected for the test account."})
    return templates

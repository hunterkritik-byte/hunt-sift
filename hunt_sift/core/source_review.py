"""Conservative, non-executing source/JavaScript review helpers."""
from __future__ import annotations
import re
from .models import Lead

_RULES = (
    ("dangerous-eval", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(", re.I), "Dynamic code execution primitive found.", "Review whether untrusted data can reach the sink and whether a safer parser/API can be used."),
    ("dom-xss-sink", re.compile(r"(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write)\s*=", re.I), "A DOM HTML-writing sink was found.", "Trace data flow from untrusted sources before deciding whether this is exploitable."),
    ("javascript-url", re.compile(r"(?:location(?:\.href)?|window\.open)\s*\([^\n]*\bjavascript:", re.I), "A JavaScript URL pattern was found.", "Review source construction and user-controlled data flow."),
    ("weak-postmessage-origin", re.compile(r"addEventListener\s*\(\s*['\"]message['\"]", re.I), "A postMessage receiver was found.", "Verify that the handler checks event.origin and validates message structure before using data."),
    ("hardcoded-secret-review", re.compile(r"(?:api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.I), "A secret-shaped hardcoded value was found.", "Treat the matched value as sensitive; rotate real credentials and avoid committing secrets."),
    ("prototype-pollution-review", re.compile(r"(?:__proto__|constructor\s*\[\s*['\"]prototype['\"]\s*\])", re.I), "Prototype-pollution-sensitive property access was found.", "Trace whether attacker-controlled keys reach object merge/assignment operations."),
)

def analyze_source(text: str, source: str = "source") -> list[Lead]:
    leads: list[Lead] = []
    for category, pattern, message, guidance in _RULES:
        if pattern.search(text):
            leads.append(Lead(source, category, "review", message, "Source matched a security-review rule; matched content redacted", guidance))
    if re.search(r"fetch\s*\(|XMLHttpRequest\s*\(|axios\.(?:get|post|put|patch|delete)\s*\(", text, re.I):
        leads.append(Lead(source, "api-request-surface", "informational", "Client-side code contains an HTTP API request surface.", "Request details redacted", "Review endpoints for authorization, input validation, excessive data exposure, and CSRF/CORS assumptions."))
    return leads

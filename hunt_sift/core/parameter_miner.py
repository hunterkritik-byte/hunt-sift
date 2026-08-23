"""Extract parameter names and classify their review relevance offline."""
from __future__ import annotations

import re
from collections import Counter

_CLASSES = {
    "identity": re.compile(r"^(id|uid|user_id|account_id|object_id|owner_id|resource_id)$", re.I),
    "authorization": re.compile(r"(role|permission|admin|privilege|scope|access)", re.I),
    "redirect": re.compile(r"(url|uri|redirect|return|next|callback|dest|target)", re.I),
    "file": re.compile(r"(file|path|filename|template|include|attachment)", re.I),
    "query": re.compile(r"(q|query|search|filter|sort|where|order)", re.I),
    "sensitive": re.compile(r"(token|secret|password|email|phone|ssn|api[_-]?key)", re.I),
}


def classify_parameters(names: list[str]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {key: [] for key in _CLASSES}
    for name in sorted(set(names), key=str.casefold):
        for category, pattern in _CLASSES.items():
            if pattern.search(name):
                result[category].append(name)
    return result


def mine_parameters(text: str) -> dict[str, object]:
    names = re.findall(r"(?:[?&]|\b)([A-Za-z_][A-Za-z0-9_-]{1,80})=", text)
    counts = Counter(names)
    return {"parameters": dict(sorted(counts.items())), "classes": classify_parameters(list(counts))}

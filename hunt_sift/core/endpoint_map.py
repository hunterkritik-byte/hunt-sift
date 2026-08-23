"""Build a deduplicated endpoint map from saved HTTP-like artifacts."""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    parameters: tuple[str, ...]
    sources: tuple[str, ...]


def extract_endpoints(text: str, source: str = "artifact") -> list[Endpoint]:
    found: dict[tuple[str, str], dict[str, set[str]]] = {}
    url_pattern = re.compile(r"https?://[^\s\"'<>]+")
    request_pattern = re.compile(r"^([A-Z]{3,10})\s+(\S+)")
    for line in text.splitlines():
        match = request_pattern.match(line.strip())
        if match:
            method, target = match.groups()
            parsed = urlsplit(target)
            path = parsed.path or "/"
            params = {k for k in re.findall(r"(?:^|[?&])([^=&?#]+)=", target)}
        else:
            url = url_pattern.search(line)
            if not url:
                continue
            parsed = urlsplit(url.group(0))
            method, path = "GET", parsed.path or "/"
            params = {k for k in re.findall(r"(?:^|&)([^=&]+)=", parsed.query)}
        key = (method, path)
        item = found.setdefault(key, {"parameters": set(), "sources": set()})
        item["parameters"].update(params)
        item["sources"].add(source)
    return [Endpoint(method, path, tuple(sorted(data["parameters"])), tuple(sorted(data["sources"]))) for (method, path), data in sorted(found.items())]


def endpoint_dicts(text: str, source: str = "artifact") -> list[dict[str, object]]:
    return [asdict(item) for item in extract_endpoints(text, source)]

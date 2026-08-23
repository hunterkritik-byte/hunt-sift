"""Offline project workspace indexing and search helpers."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArtifactRecord:
    path: str
    kind: str
    size: int
    sha256: str


def classify(path: Path) -> str:
    names = {".har": "har", ".xml": "xml", ".json": "json", ".txt": "text", ".html": "html", ".htm": "html", ".js": "javascript", ".ts": "typescript", ".py": "python", ".yaml": "config", ".yml": "config"}
    return names.get(path.suffix.lower(), "other")


def index_directory(root: str | Path, max_bytes: int = 5_000_000) -> list[ArtifactRecord]:
    """Index local files without executing or opening network resources."""
    base = Path(root).expanduser().resolve()
    if not base.is_dir():
        raise ValueError(f"Workspace must be a local directory: {base}")
    records: list[ArtifactRecord] = []
    for path in sorted(p for p in base.rglob("*") if p.is_file()):
        if any(part in {".git", ".venv", "__pycache__", "node_modules"} for part in path.parts):
            continue
        size = path.stat().st_size
        if size > max_bytes:
            continue
        records.append(ArtifactRecord(str(path.relative_to(base)), classify(path), size, hashlib.sha256(path.read_bytes()).hexdigest()))
    return records


def search_records(records: list[ArtifactRecord], query: str) -> list[ArtifactRecord]:
    needle = query.casefold()
    return [r for r in records if needle in r.path.casefold() or needle in r.kind.casefold()]


def write_index(records: list[ArtifactRecord], output: str | Path) -> None:
    Path(output).write_text(json.dumps([asdict(r) for r in records], indent=2), encoding="utf-8")

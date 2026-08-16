"""Bounded local file access helpers.

No function in this module initiates network activity, executes a file, or follows a live URL.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

MAX_INPUT_BYTES = 2_000_000
MAX_DIRECTORY_DEPTH = 20
SKIPPED_DIRECTORIES = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}
SKIPPED_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".woff", ".woff2", ".pyc"}


def read_text(path: Path, limit: int = MAX_INPUT_BYTES) -> str:
    """Read a selected local text file with a hard size cap."""
    if not path.is_file():
        raise ValueError(f"Input must be a local file: {path}")
    if path.stat().st_size > limit:
        raise ValueError(f"Refusing to read {path}: it exceeds the {limit:,}-byte local analysis limit.")
    return path.read_text(encoding="utf-8", errors="replace")


def iter_local_text_files(path: Path, max_depth: int = MAX_DIRECTORY_DEPTH) -> Iterable[Path]:
    """Yield selected local text files while excluding common generated or binary locations.
    
    Args:
        path: File or directory to analyze.
        max_depth: Maximum directory depth to traverse. Prevents runaway recursion on deep trees.
    """
    if path.is_file():
        yield path
        return
    if not path.is_dir():
        raise ValueError(f"Input must be a local file or directory: {path}")
    
    # Use a queue-based approach with explicit depth tracking for better control
    queue = [(path, 0)]
    while queue:
        current, depth = queue.pop(0)
        if depth > max_depth:
            continue
        
        try:
            for candidate in current.iterdir():
                # Check if any part of the path matches a skipped directory
                if any(part in SKIPPED_DIRECTORIES for part in candidate.parts):
                    continue
                
                if candidate.is_file():
                    if candidate.suffix.lower() not in SKIPPED_SUFFIXES:
                        if candidate.stat().st_size <= MAX_INPUT_BYTES:
                            yield candidate
                elif candidate.is_dir():
                    queue.append((candidate, depth + 1))
        except (OSError, PermissionError):
            # Skip directories we can't read
            continue

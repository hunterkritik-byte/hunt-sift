"""Data models for cautious local review leads."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Lead:
    """A local-review prompt derived from an imported artifact, never a vulnerability assertion."""

    source: str
    category: str
    severity: str
    message: str
    evidence: str
    guidance: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

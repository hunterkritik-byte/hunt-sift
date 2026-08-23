"""Offline GraphQL security review for saved requests and schemas."""
from __future__ import annotations
import re
from .models import Lead


def analyze_graphql(text: str) -> list[Lead]:
    leads: list[Lead] = []
    if not re.search(r"\b(query|mutation|subscription)\b", text, re.I):
        return []
    if re.search(r"__schema|__type", text):
        leads.append(Lead("graphql", "graphql-introspection-review", "review", "GraphQL introspection fields appear in the supplied artifact.", "Introspection syntax detected; values redacted", "Confirm whether introspection is intentionally available in the deployment and whether sensitive schema details are exposed."))
    if re.search(r"\bmutation\b", text, re.I):
        leads.append(Lead("graphql", "graphql-mutation-review", "review", "A GraphQL mutation is present in the supplied artifact.", "Mutation detected; arguments redacted", "Review authorization independently for each mutation and object, especially ownership and role changes."))
    depth = max((line.count("{") for line in text.splitlines()), default=0)
    if depth >= 5:
        leads.append(Lead("graphql", "graphql-depth-review", "review", "The supplied GraphQL artifact contains a deeply nested selection shape.", "Nesting depth indicator redacted", "Check whether the server applies query-depth, complexity, pagination, and timeout controls."))
    if re.search(r"\b(first|last|limit|offset)\s*:\s*\d{3,}", text, re.I):
        leads.append(Lead("graphql", "graphql-pagination-review", "review", "A large pagination value appears in the supplied GraphQL artifact.", "Pagination value redacted", "Review server-side maximum page sizes and authorization; do not use this analyzer to generate load."))
    return leads

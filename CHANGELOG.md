# Changelog

## 2.1.23 — Explainable triage and offline reporting

### Enhancements
- Added deterministic finding-priority scoring for local review leads.
- Added `triage` CLI command with human-readable and JSON output.
- Added self-contained HTML report generation with HTML escaping.
- Extended `report` to emit JSON, SARIF 2.1.0, or HTML.
- Allowed normalized Hunt Sift JSON reports to be consumed again as finding input.
- Added regression tests for scoring, ordering, summary bands, and HTML escaping.
- Bumped package and runtime version to `2.1.23`.

The scoring system is intentionally explainable triage metadata. It does not determine exploitability, severity, or whether a finding is reportable.

## 1.4.0 — Passive attack-surface intelligence

### Enhancements
- Added offline HTTP response differential analysis for saved before/after artifacts.
- Added endpoint mapping and parameter classification.
- Added `diff`, `endpoints`, and `params` CLI commands.

## 1.2.0 — Request and source security review

### Enhancements
- Added offline raw HTTP request analysis for IDOR/BOLA review, SQL/NoSQL injection indicators, mass-assignment review, and information-disclosure review.
- Added non-executing JavaScript/source review.
- Added inert manual-review templates.

## 1.1.0 — Offline security workbench

### Enhancements
- Added local case inventory with artifact type, size, and SHA-256 fingerprinting.
- Added inventory search and structured inventory JSON output.
- Fixed setuptools package discovery so `hunt_sift.*` subpackages are included in builds.

## 1.0.2 — Header analysis hardening and privacy fixes

### Bug fixes
- Fixed normalization of repeated HTTP header values supplied as tuples and other sequences.
- Redacted imported `Set-Cookie` values from review evidence.

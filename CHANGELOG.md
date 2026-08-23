# Changelog

## 1.4.0 — Passive attack-surface intelligence

### Enhancements
- Added offline HTTP response differential analysis for saved before/after artifacts.
- Added endpoint mapping that deduplicates methods and paths while collecting parameter names.
- Added parameter mining with identity, authorization, redirect, file, query, and sensitive-field classifications.
- Added `diff`, `endpoints`, and `params` CLI commands with JSON output support.
- Added regression tests for sensitive-header redaction, endpoint deduplication, and parameter classification.
- Bumped package/runtime version to `1.4.0`.

The new features are passive and artifact-driven. They do not scan, replay requests, execute files, or generate exploit payloads.

## 1.2.0 — Request and source security review

### Enhancements
- Added offline raw HTTP request analysis for IDOR/BOLA review, SQL/NoSQL injection indicators, mass-assignment review, and information-disclosure review.
- Added non-executing JavaScript/source review for dangerous dynamic-code sinks, DOM HTML sinks, postMessage handling, hardcoded-secret patterns, prototype-pollution-sensitive properties, and client-side API request surfaces.
- Added inert manual-review templates that provide methodology without sending requests or generating ready-to-run exploit payloads.
- Added regression tests for request and source analysis.
- Added `request`, `source`, and `test-templates` CLI commands.

The tool remains offline-only. Findings are contextual review leads, not automatic vulnerability claims.

## 1.1.0 — Offline security workbench

### Enhancements
- Added local case inventory with artifact type, size, and SHA-256 fingerprinting.
- Added inventory search for rapid triage.
- Added structured inventory JSON output and workbench documentation.
- Fixed setuptools package discovery so `hunt_sift.*` subpackages are included in builds.

## 1.0.2 — Header analysis hardening and privacy fixes

### Bug fixes
- Fixed normalization of repeated HTTP header values supplied as tuples and other sequences.
- Redacted imported `Set-Cookie` values from review evidence.

## 0.5.0 — Security-header ambiguity review

This release adds cautious review leads for conflicting security-sensitive HTTP response headers. The rule is offline-only and contextual.

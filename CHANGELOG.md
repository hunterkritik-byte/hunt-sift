# Changelog

## 1.1.0 — Offline security workbench

### Enhancements
- Added local case inventory with artifact type, size, and SHA-256 fingerprinting.
- Added inventory search for rapid triage.
- Added structured inventory JSON output and workbench documentation.
- Fixed setuptools package discovery so `hunt_sift.*` subpackages are included in builds.

### Regression coverage
- Added workspace tests for ignored generated directories, deterministic hashes, metadata search, and JSON round trips.

The workbench remains offline-only: no scanning, network access, request replay, target discovery, execution, or exploit-payload generation.

## 1.0.2 — Header analysis hardening and privacy fixes

### Bug fixes
- Fixed normalization of repeated HTTP header values supplied as tuples and other sequences.
- Redacted imported `Set-Cookie` values from review evidence.

### Enhancements
- Added regression coverage for sequence-valued headers, conflicting security headers, cookie redaction, and scalar-header compatibility.
- Standardized package metadata and runtime version to `1.0.2`.

All analysis remains offline-only and treats configuration findings as contextual review leads rather than automatic vulnerability claims.

## 0.5.0 — Security-header ambiguity review

This release adds a cautious review lead for conflicting values in security-sensitive HTTP response headers such as Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and CORS headers.

# Changelog

## 1.1.0 — Offline security workbench

### Major enhancements
- Added a local project inventory with SHA-256 artifact fingerprints.
- Added inventory search for rapid case triage.
- Added structured inventory export for evidence workflows.
- Expanded CLI help and workbench documentation.

### Security and correctness
- Fixed packaging so all `hunt_sift.*` subpackages are included in builds.
- Preserved offline-only operation: no scanner, proxy, replay, target discovery, execution, or payload-generation capability was added.
- Kept security findings contextual and evidence-driven rather than claiming vulnerability status automatically.

### Regression coverage
- Added tests for workspace indexing, generated-directory exclusion, SHA-256 fingerprints, search, and JSON round trips.

## 1.0.2 — Header analysis hardening and privacy fixes

- Fixed sequence-valued repeated HTTP header normalization.
- Redacted imported `Set-Cookie` values from evidence.
- Added HTTP review regression coverage.

## 0.5.0 — Security-header ambiguity review

Added cautious review leads for conflicting values in security-sensitive response headers, with redacted evidence and contextual guidance.

## 0.4.0 — Offline policy review and release preparation

Added JWT/S3 policy review, release automation, examples, and documentation improvements.

## 0.3.0 — Researcher onboarding and cautious pattern review

Added manuals, installers, local review rules, sanitized Burp/HAR examples, and additional static review cues.

## 0.2.0 — Offline artifact expansion

Added local Burp XML and HAR parsers and reorganized the package into core/parsers modules.

## 0.1.0 — Initial release

Introduced offline Nmap XML, raw HTTP response, and static-file review with a strict no-scanning/no-execution boundary.

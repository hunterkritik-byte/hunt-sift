# Changelog

## 1.0.2 — Header analysis hardening and privacy fixes

### Bug fixes
- Fixed normalization of repeated HTTP header values supplied as tuples and other sequences. Previously, non-list sequences could be stringified as one value, causing conflicting security-header checks to miss real differences.
- Redacted imported `Set-Cookie` values from review evidence so session/token-like cookie contents are not copied into generated findings.

### Enhancements
- Added regression coverage for sequence-valued headers, conflicting security headers, cookie redaction, and scalar-header compatibility.
- Standardized package metadata and runtime version to `1.0.2`.

All analysis remains offline-only and treats configuration findings as contextual review leads rather than automatic vulnerability claims.

## 0.5.0 — Security-header ambiguity review

This release adds a cautious review lead for conflicting values in security-sensitive HTTP response headers such as Content-Security-Policy, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and CORS headers. The rule is offline-only, redacts header values from evidence, and treats ambiguity as a review prompt rather than a confirmed vulnerability. Tests cover detection and redaction.

## 0.4.0 — Offline policy review and release preparation

This release adds local static-source review cues for JWT decode, expiration, and `none` algorithm configurations, plus a redacted `jwt_secret` pattern. The new `s3` command analyzes only a supplied S3-style JSON policy and emits careful wildcard-principal read/write configuration leads without any cloud API activity. It also includes a validated reusable offline-security development skill, a tag-gated GitHub Actions build/release workflow with PyPI trusted publishing, and cyber-neon HTML previews for the manual and Burp/HAR sample report.

## 0.3.0 — Researcher onboarding and cautious pattern review

This release adds a comprehensive user manual, a POSIX installer, a Windows PowerShell installer, a documented local review-rule catalog, and a sanitized Burp XML/HAR sample analysis report. The static-file analyzer now flags cautious CORS configuration cues and potential credential-shaped values while redacting the matched value in output. Imported response analysis also highlights the wildcard CORS plus credentialed-response configuration as a contextual review lead.

## 0.2.0 — Offline artifact expansion

This release adds local-only parsers for Burp Suite XML and HTTP Archive (HAR) exports. The command-line interface now accepts `burp` and `har` subcommands alongside Nmap XML, raw HTTP response, and static-file review.

The package was reorganized into `core/` and `parsers/` modules so file handling, header review, result rendering, and format-specific readers remain separate. Output labels now remove URL query strings and fragments, static analysis skips common generated directories, and the repository includes sanitized examples plus architecture and contribution notes.

## 0.1.0 — Initial release

The initial private release introduced offline Nmap XML, raw HTTP response, and static-file artifact review with local tests, documentation, and a strict no-scanning/no-execution boundary.

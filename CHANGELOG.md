# Changelog

## 0.3.0 — Researcher onboarding and cautious pattern review

This release adds a comprehensive user manual, a POSIX installer, a Windows PowerShell installer, a documented local review-rule catalog, and a sanitized Burp XML/HAR sample analysis report. The static-file analyzer now flags cautious CORS configuration cues and potential credential-shaped values while redacting the matched value in output. Imported response analysis also highlights the wildcard CORS plus credentialed-response configuration as a contextual review lead.

## 0.2.0 — Offline artifact expansion

This release adds local-only parsers for Burp Suite XML and HTTP Archive (HAR) exports. The command-line interface now accepts `burp` and `har` subcommands alongside Nmap XML, raw HTTP response, and static-file review.

The package was reorganized into `core/` and `parsers/` modules so file handling, header review, result rendering, and format-specific readers remain separate. Output labels now remove URL query strings and fragments, static analysis skips common generated directories, and the repository includes sanitized examples plus architecture and contribution notes.

## 0.1.0 — Initial release

The initial private release introduced offline Nmap XML, raw HTTP response, and static-file artifact review with local tests, documentation, and a strict no-scanning/no-execution boundary.

# Architecture

Hunt Sift is organized as a local-only analysis pipeline. The command-line interface selects one parser for a named file, the parser normalizes only in-memory artifacts, the shared review layer creates cautious leads, and the renderer writes local output. No component opens a socket, invokes a subprocess, follows an imported URL, or executes imported content.

| Directory | Responsibility |
| --- | --- |
| `hunt_sift/core/` | Bounded file access, response-header review, typed leads, and terminal rendering. |
| `hunt_sift/parsers/` | Format-specific readers for Nmap XML, Burp XML, HAR, raw HTTP, and static source. |
| `tests/` | Fixture-style tests that validate parsing and redaction behavior using only local temporary files. |
| `examples/` | Sanitized fictitious sample formats that can be used to explore command syntax. |
| `docs/` | Design, safety, and contribution notes. |

## Data handling

Imported URLs are turned into display labels with query strings and fragments removed. The source artifact itself remains local and is never uploaded by Hunt Sift. File reads are capped at 2 MB, and the static-file walker skips common generated directories such as `.git`, `.venv`, `node_modules`, `build`, and `dist`.

## Review model

> A Hunt Sift lead is an invitation to examine a local artifact more carefully. It is not a vulnerability determination, severity assessment, or permission to test a live system.

All lead guidance asks the researcher to re-check written authorization, target scope, real-world reachability, data flow, and impact before further action.

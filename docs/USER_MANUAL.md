# Hunt Sift User Manual

Hunt Sift is an **offline-first artifact review CLI** for authorized security research. It reads only local files selected on your computer and produces contextual review leads. It does not scan targets, replay requests, execute files, discover hosts, generate payloads, or submit reports. Treat each output as a prompt for careful human review, not as proof of a vulnerability.

> Before using any artifact, confirm that you are authorized to handle it and that the relevant target is within scope. Remove credentials, personal data, and proprietary content before sharing an artifact or a Hunt Sift report.

## 1. Installation

Hunt Sift uses Python 3.10 or later and has no third-party runtime dependencies. Clone the repository first, then use the helper that matches your operating system.

| Platform | Command from the repository root | Result |
| --- | --- | --- |
| Linux or macOS | `./scripts/install.sh` | Creates `.venv` and installs the local editable package. |
| Windows PowerShell | `.\scripts\install.ps1` | Creates `.venv` and installs the local editable package. |
| Any platform | `python3 -m pip install --no-build-isolation -e .` | Installs the local package without contacting a package index for project dependencies. |

For Linux or macOS, activate the environment with `source .venv/bin/activate`. For Windows PowerShell, use `.\.venv\Scripts\Activate.ps1`. Once installed, confirm the local-only boundary with `hunt-sift boundaries`.

## 2. Command model

Every analysis command requires an explicit `--input` path. The tool only opens that local path; an imported URL is retained only as a redacted label with query strings and fragments removed.

| Command | Accepted artifact | Primary review focus |
| --- | --- | --- |
| `hunt-sift nmap --input file.xml` | Previously exported Nmap XML | Service inventory, transport, and legacy-service review. |
| `hunt-sift burp --input file.xml` | Previously exported Burp Suite XML | Saved HTTP response headers from the export. |
| `hunt-sift har --input file.har` | HTTP Archive export | Saved response status and headers for each entry. |
| `hunt-sift http --input response.txt --url https://example.test/path` | Raw saved HTTP response | Response-hardening, cookie, CORS, and metadata review. |
| `hunt-sift static --input ./source` | Local source file or directory | Non-executing code and configuration pattern review. |
| `hunt-sift boundaries` | None | Prints the product safety boundary. |

Add `--json` before the subcommand whenever a script needs structured output. For example, `hunt-sift --json har --input exports/session.har` writes a JSON array of local review leads.

## 3. Typical research workflow

Begin by saving an artifact that you are permitted to analyze. The artifact can come from a tool run against your own lab, a customer-approved assessment, or an in-scope program workflow. Hunt Sift does not obtain the artifact for you.

```bash
# Review an existing export without starting Nmap or connecting to the listed address.
hunt-sift nmap --input ./exports/authorized-scan.xml

# Review a saved Burp XML export without opening Burp or replaying the request.
hunt-sift burp --input ./exports/burp-items.xml

# Review a saved HAR export locally.
hunt-sift har --input ./exports/browser-session.har
```

Read the evidence line, then evaluate the associated next step against the actual program rules and your authorization. A lead such as an absent header, a wildcard CORS value, an `innerHTML` occurrence, or a token-shaped string must be connected to real data flow and security impact before it can become a report.

## 4. Interpreting output

Hunt Sift has two result levels. **Review** means the imported artifact contains a condition worth verifying in context. **Informational** means the artifact contains inventory or navigation information that does not establish security impact. Neither level represents a severity rating.

Each lead has five parts: the source type, category, message, sanitized evidence label, and a cautious next step. The tool intentionally avoids labeling a result as a confirmed vulnerability.

## 5. CORS and response-header review

For saved HTTP, Burp XML, and HAR responses, Hunt Sift checks common response-hardening cues such as Content-Security-Policy, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security for HTTPS labels, cookie attributes, wildcard CORS, and visible technology headers.

The CORS rules are deliberately conservative. `Access-Control-Allow-Origin: *` is only a review lead. It can be entirely expected for a public resource. A report requires evidence that a sensitive response is readable cross-origin in an authorized context; do not use someone else’s data or make live requests solely because the tool emitted a lead.

## 6. Static-file pattern review

The static analyzer reads text without executing it. It can flag dynamic code patterns, DOM sink assignments, debug settings, TODO markers, HTTP URLs, CORS configuration strings, and potential credential-shaped values. It skips common generated directories such as `.git`, `.venv`, `node_modules`, `dist`, and `build`.

Potential credential results are redacted in output. Hunt Sift shows a short prefix and suffix only; it does not print the full matched value. Always rotate or revoke a real secret through the system owner’s approved process. Do not place secrets into public reports, issues, or screenshots.

## 7. Data handling

Hunt Sift reads files up to 2 MB and never uploads them. The CLI does not store a workspace, send telemetry, use a network client, invoke a browser, or create a connection to an address in any imported artifact. Keep your artifact folders encrypted or access-controlled if they contain sensitive authorized material.

## 8. Troubleshooting

| Situation | Check |
| --- | --- |
| `hunt-sift: command not found` | Activate `.venv` or run `python3 -m hunt_sift.cli ...` from the repository root. |
| `Input error: Invalid ...` | Confirm that the selected file is a complete XML, HAR JSON, or raw response export. |
| No leads returned | This only means the selected rules did not match; it does not establish that the artifact is secure. |
| Too many static results | Run `static` against a smaller source subdirectory or targeted file. |
| A potential credential is flagged | Verify that it is not an example, placeholder, or public key. Never publish the full value. |

## 9. Contributing safely

Every new parser must operate on an explicit local file and include a local fixture-style test. Do not add scanning, request replay, target discovery, credential storage, browser automation, exploit generation, code execution, or automatic report submission. See [`CONTRIBUTING.md`](./CONTRIBUTING.md) and [`RULES.md`](./RULES.md) for the maintained boundaries.

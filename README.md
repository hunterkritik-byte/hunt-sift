# Hunt Sift

> **Hunt Sift is an offline-only artifact-review tool for authorized security research.** It reads files you explicitly provide and returns careful review leads. It never scans hosts, sends requests, executes files, replays traffic, performs target discovery, generates payloads, or stores credentials.

## What it accepts

| Command | Local input | What it does |
| --- | --- | --- |
| `hunt-sift nmap` | Previously exported Nmap XML | Summarizes open-service inventory cues and flags legacy-service or transport-review leads. |
| `hunt-sift burp` | Previously exported Burp Suite XML | Reads saved response metadata from an export and applies the same cautious local header-review rules. |
| `hunt-sift har` | A saved HTTP Archive (HAR) file | Reviews saved response headers and status metadata from local HAR entries. |
| `hunt-sift http` | A saved raw HTTP response | Reviews response-hardening, cookie-attribute, CORS, and technology-metadata cues. |
| `hunt-sift static` | A local source file or directory | Finds a few non-executing code-review cues such as `eval`, `innerHTML`, `debug=true`, TODOs, and HTTP URLs. |
| `hunt-sift boundaries` | No input | Prints the tool's offline-only operating limits. |

Every result is a **review lead**, not a vulnerability assertion. Confirm written authorization, actual reachability, data flow, impact, and the target program's reporting rules before taking any further action.

## Install

Hunt Sift uses only the Python standard library and supports Python 3.10+.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

For a guided cross-platform local install, use `./scripts/install.sh` on Linux or macOS, or `.\scripts\install.ps1` in Windows PowerShell. The full setup, workflow, output interpretation, troubleshooting, and safety guidance are in [`docs/USER_MANUAL.md`](./docs/USER_MANUAL.md).

## Examples

Analyze an existing Nmap XML export without launching Nmap.

```bash
hunt-sift nmap --input ./exports/authorized-scan.xml
```

Review a saved raw HTTP response without connecting to the URL.

```bash
hunt-sift http --input ./exports/response.txt --url https://app.example.test
```

Review an exported Burp Suite XML file. Hunt Sift does not open Burp Suite or replay the captured traffic.

```bash
hunt-sift burp --input ./exports/captured-items.xml
```

Review a local HAR file. Query strings and fragments are removed from the output labels.

```bash
hunt-sift har --input ./exports/captured-session.har
```

Inspect selected local source files without executing them.

```bash
hunt-sift static --input ./source-export
```

Use `--json` before the command for structured local results.

```bash
hunt-sift --json http --input ./exports/response.txt
```

## Verify

```bash
python3 -m unittest discover -s tests -v
```

## Safety and scope

Hunt Sift is designed as an evidence-review companion, not a live testing tool. Ensure the artifacts and targets are authorized for your use, avoid handling data that you are not permitted to access, and apply the rules of the relevant program before submitting a report.

The modular design, local data handling, and contribution boundary are documented in [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) and [`docs/CONTRIBUTING.md`](./docs/CONTRIBUTING.md). Try the wholly fictitious local files in [`examples/`](./examples/) to see the command syntax.

The current local review-rule families and their limitations are documented in [`docs/RULES.md`](./docs/RULES.md).

The committed [sample analysis report](./docs/SAMPLE_ANALYSIS_REPORT.md) shows Burp XML and HAR output generated from fully sanitized local examples. It illustrates review leads only and does not describe a real target or confirmed vulnerability.

Release notes are maintained in [`CHANGELOG.md`](./CHANGELOG.md). The current feature release is **0.2.0**.

## Security

For concerns about this repository, follow [`SECURITY.md`](./SECURITY.md). The project is distributed under the [MIT License](./LICENSE).

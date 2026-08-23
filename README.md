# Hunt Sift

> **Hunt Sift is an offline-only artifact-review workbench for authorized security research.** It reads files you explicitly provide and returns careful review leads. It never scans hosts, sends requests, executes files, replays traffic, performs target discovery, or stores credentials.

<p align="center">
  <img src="./docs/assets/hunt-sift.gif" alt="Animated Hunt Sift workbench demo" width="720">
</p>

## Workbench at a glance

| Area | Local capability |
| --- | --- |
| HTTP | Raw response and request review, security-header and authorization-sensitive cues |
| Burp / HAR | Analyze saved exports without opening Burp or replaying captured traffic |
| Source / JS | Conservative non-executing security-pattern review |
| Nmap | Review previously exported XML service inventory |
| Cloud policy | Review saved S3-style policy JSON |
| Workspace | Inventory local cases and fingerprint artifacts with SHA-256 |
| Reporting | Deduplicate findings and export JSON or SARIF for local workflows |

## What it accepts

| Command | Local input | What it does |
| --- | --- | --- |
| `hunt-sift nmap` | Previously exported Nmap XML | Summarizes open-service inventory cues and flags legacy-service or transport-review leads. |
| `hunt-sift burp` | Previously exported Burp Suite XML | Reads saved response metadata from an export and applies cautious local header-review rules. |
| `hunt-sift har` | A saved HTTP Archive (HAR) file | Reviews saved response headers and status metadata from local HAR entries. |
| `hunt-sift http` | A saved raw HTTP response | Reviews response-hardening, cookie-attribute, CORS, and technology-metadata cues. |
| `hunt-sift request` | A saved raw HTTP request | Reviews BOLA/IDOR, injection-shaped input, mass-assignment, and disclosure cues. |
| `hunt-sift source` | Local source / JavaScript | Performs conservative non-executing source-security checks. |
| `hunt-sift inventory` | A local case directory | Indexes artifacts and records SHA-256 fingerprints. |
| `hunt-sift report` | Saved Hunt Sift JSON findings | Produces a normalized JSON report or SARIF 2.1.0 document. |
| `hunt-sift boundaries` | No input | Prints the tool's offline-only operating limits. |

Every result is a **review lead**, not a vulnerability assertion. Confirm written authorization, actual reachability, data flow, impact, and the target program's reporting rules before taking any further action.

## Reporting workflow

Generate structured findings from a local artifact, then export them for a code-review or CI dashboard:

```bash
hunt-sift --json request --input ./case/request.txt > findings.json
hunt-sift report --input findings.json --output ./case/report.sarif --format sarif
```

The SARIF exporter preserves the offline-review boundary and marks findings as local review leads. It does not add network behavior or automatic exploitation.

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

Review a saved raw HTTP request:

```bash
hunt-sift request --input ./exports/request.txt
```

Inspect selected local source files without executing them.

```bash
hunt-sift source --input ./source-export
```

Build and search a local workspace index:

```bash
hunt-sift inventory --input ./case --output ./case/inventory.json
hunt-sift search --input ./case/inventory.json --query javascript
```

Use `--json` before a command for structured local findings.

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

The release setup is explained in [`docs/RELEASE.md`](./docs/RELEASE.md). The optional static cyber-neon preview is available in [`docs/preview/index.html`](./docs/preview/index.html); it can be opened directly from the repository or served from the `docs/preview` folder locally.

Release notes are maintained in [`CHANGELOG.md`](./CHANGELOG.md).

## Security

For concerns about this repository, follow [`SECURITY.md`](./SECURITY.md). The project is distributed under the [MIT License](./LICENSE).

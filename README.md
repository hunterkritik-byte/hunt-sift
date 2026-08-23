# Hunt Sift

> **Hunt Sift is an offline-only security artifact workbench for authorized research.** It combines imported Burp XML, HAR, raw HTTP, Nmap XML, S3 policy JSON, and local source review without becoming a live scanner or traffic proxy.

## 1.1.0 Workbench

Hunt Sift now provides a stronger Burp-like **offline workflow**:

- **Artifact inventory:** recursively index a local project and calculate SHA-256 fingerprints.
- **Fast triage search:** search the generated inventory by artifact name or type.
- **Passive review:** continue using Burp XML/HAR/HTTP imports for header, CORS, cookie, error, and metadata review.
- **Structured output:** retain `--json` output for automation and evidence pipelines.
- **Safer evidence:** sensitive cookie values are redacted from HTTP review evidence.
- **Repeat-header correctness:** tuple/sequence-valued imported headers are normalized individually, preventing missed conflicting-header leads.
- **Correct packaging:** setuptools now discovers `hunt_sift` subpackages instead of packaging only the top-level module.

### Commands

| Command | Purpose |
| --- | --- |
| `hunt-sift burp --input export.xml` | Review an existing Burp Suite XML export offline. |
| `hunt-sift har --input capture.har` | Review an existing HAR offline. |
| `hunt-sift http --input response.txt` | Review a saved raw HTTP response. |
| `hunt-sift nmap --input scan.xml` | Review a previously exported Nmap XML file. |
| `hunt-sift static --input source/` | Run non-executing source review cues. |
| `hunt-sift s3 --input policy.json` | Review an exported S3-style policy. |
| `hunt-sift inventory --input ./case --output inventory.json` | Build a local evidence inventory and hashes. |
| `hunt-sift search --input inventory.json --query har` | Search an inventory. |
| `hunt-sift boundaries` | Print safety and authorization boundaries. |

Example workbench flow:

```bash
hunt-sift inventory --input ./case --output ./case/inventory.json
hunt-sift search --input ./case/inventory.json --query har
hunt-sift --json har --input ./case/capture.har > ./case/har-review.json
hunt-sift http --input ./case/response.txt --url https://app.example.test
```

## What it does not do

Hunt Sift **does not** scan hosts, send requests, replay traffic, perform target discovery, execute files, generate exploit payloads, store credentials, or contact networks. The Burp-like workflow is intentionally based on artifacts you explicitly provide.

Every result is a **review lead**, not a vulnerability assertion. Confirm written authorization, reachability, data flow, impact, and the applicable program rules before taking further action.

## Install

Hunt Sift uses only the Python standard library and supports Python 3.10+.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
```

## Verify

```bash
python3 -m unittest discover -s tests -v
```

## Documentation

See [`docs/USER_MANUAL.md`](./docs/USER_MANUAL.md), [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md), [`docs/RULES.md`](./docs/RULES.md), and [`docs/RELEASE.md`](./docs/RELEASE.md). Sanitized examples are under [`examples/`](./examples/).

## Security

For repository security concerns, follow [`SECURITY.md`](./SECURITY.md). The project is distributed under the MIT License.

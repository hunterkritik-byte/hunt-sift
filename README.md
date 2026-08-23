# Hunt Sift

> **Hunt Sift is an offline-only artifact-review workbench for authorized security research.** It reads files you explicitly provide and returns careful review leads. It never scans hosts, sends requests, executes files, replays traffic, performs target discovery, or stores credentials.

<p align="center"><img src="./docs/assets/hunt-sift.gif" alt="Animated Hunt Sift workbench demo" width="720"></p>

## Workbench at a glance

| Area | Local capability |
| --- | --- |
| HTTP / requests | Security-header, authorization, injection-shaped input and disclosure review |
| Burp / HAR / Nmap | Analyze saved exports without replaying captured traffic |
| Source / JS | Conservative non-executing security-pattern review |
| JWT / GraphQL / OpenAPI | Offline configuration and security review cues |
| Secrets | Local pattern detection with mandatory value redaction |
| Attack surface | Endpoint mapping, parameter classification, response diffs |
| Workspace | Inventory local cases and SHA-256 artifact fingerprints |
| Reporting | JSON, SARIF 2.1.0 and self-contained HTML reports |
| Triage | Deterministic, explainable priority scoring |

## 2.1.23 highlights

### 🧭 Explainable triage

```bash
hunt-sift --json triage --input ./case/findings.json
```

Prioritizes existing local review leads using deterministic metadata. It does **not** claim exploitability or severity; the score is only a queueing aid.

### 📊 Self-contained HTML reports

```bash
hunt-sift report --input ./case/findings.json --output ./case/report.html --format html
```

The report is generated locally, escapes HTML content, shows priority bands, and keeps the offline boundary explicit.

### 🔁 Report round-trip

`report` can now consume either a raw finding list or the normalized JSON report produced by Hunt Sift.

## Commands

```text
nmap       saved Nmap XML review
burp       saved Burp XML review
har        saved HAR review
http       saved HTTP response review
request    saved HTTP request review
source     local JavaScript/source review
static     local static-file review
jwt        local JWT review
graphql    saved GraphQL review
openapi    saved OpenAPI/Swagger review
secrets    local secret-pattern review
diff       saved response comparison
endpoints  local endpoint inventory
params     local parameter intelligence
inventory  case inventory + SHA-256
search     inventory search
triage     deterministic finding prioritization
report     JSON / SARIF / HTML reporting
test-templates  inert manual-review templates
boundaries safety boundary summary
```

## Safety boundary

Every result is a **review lead**, not a vulnerability assertion. Confirm written authorization, actual reachability, data flow, impact, and the target program's reporting rules before taking any further action.

Hunt Sift does not scan hosts, replay requests, execute source, perform target discovery, contact networks, or generate ready-to-run exploit payloads. Sensitive evidence should remain redacted.

## Install

Hunt Sift uses only the Python standard library and supports Python 3.10+.

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
```

See [`docs/USER_MANUAL.md`](./docs/USER_MANUAL.md), [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md), and [`docs/RULES.md`](./docs/RULES.md) for workflow and rule limitations.

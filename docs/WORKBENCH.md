# Offline Workbench

Hunt Sift is intentionally closer to a **Burp-style evidence workbench** than a live proxy: it lets you organize, fingerprint, search, and analyze artifacts that you already collected.

## Recommended case layout

```text
case/
  burp/
    export.xml
  har/
    browser.har
  http/
    response-001.txt
  source/
    app.js
  inventory.json
```

## Build an inventory

```bash
hunt-sift inventory --input ./case --output ./case/inventory.json
```

The inventory records relative path, detected artifact type, byte size, and SHA-256. It skips common generated directories and never executes indexed files.

## Triage

```bash
hunt-sift search --input ./case/inventory.json --query har
hunt-sift search --input ./case/inventory.json --query javascript
```

Use the matching artifact with the appropriate analyzer:

```bash
hunt-sift --json har --input ./case/har/browser.har
hunt-sift --json burp --input ./case/burp/export.xml
hunt-sift --json http --input ./case/http/response-001.txt
hunt-sift static --input ./case/source
```

## Evidence model

The analyzer produces **review leads** with a category, severity, evidence label, and suggested next step. It deliberately avoids claiming that a configuration cue is exploitable without a demonstrated security impact.

Sensitive cookie values are redacted in HTTP evidence. URL query strings and fragments are also excluded from evidence labels.

## Why it is not a live proxy

A live proxy, request repeater, crawler, scanner, or active payload engine would materially change the project's threat model. This release keeps those capabilities out. Import artifacts from an authorized testing workflow instead, then use Hunt Sift for repeatable offline triage and reporting.

# Offline Workbench

Hunt Sift is an offline evidence workbench for authorized research. It organizes and analyzes artifacts already present on disk.

## Inventory

```bash
hunt-sift inventory --input ./case --output ./case/inventory.json
hunt-sift search --input ./case/inventory.json --query har
```

The inventory records relative path, artifact type, byte size, and SHA-256. Common generated directories are skipped and indexed files are never executed.

## Passive analysis

```bash
hunt-sift --json har --input ./case/capture.har
hunt-sift --json burp --input ./case/export.xml
hunt-sift --json http --input ./case/response.txt
hunt-sift static --input ./case/source
```

Every result is a review lead rather than an automatic vulnerability claim. The project intentionally does not add live proxying, scanning, request replay, target discovery, exploit generation, or network access.

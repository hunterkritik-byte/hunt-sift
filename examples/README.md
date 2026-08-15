# Sanitized examples

The files in this directory use only the reserved `example.test` domain and fictional response metadata. They are not targets, credentials, or proof of a vulnerability. They exist solely to demonstrate offline command syntax.

```bash
hunt-sift nmap --input examples/authorized-scan.xml
hunt-sift burp --input examples/burp-export.xml
hunt-sift har --input examples/response.har
```

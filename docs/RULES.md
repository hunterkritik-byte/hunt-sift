# Local Review Rules

Hunt Sift rules are cautious pattern checks applied only to user-supplied local artifacts. Each rule produces a review lead, not a confirmed vulnerability.

| Rule family | Input types | Example cue | Why human review is required |
| --- | --- | --- | --- |
| Response hardening | Raw HTTP, Burp XML, HAR | Missing browser-hardening headers | Header expectations vary by route and application context. |
| CORS policy | Raw HTTP, Burp XML, HAR, static files | Wildcard origin or reflective-origin code/configuration | A finding requires a sensitive response and an authorized cross-origin impact analysis. |
| Cookie attributes | Raw HTTP, Burp XML, HAR | Cookie lacks one or more security attributes | Cookie purpose, scope, and actual transport behavior matter. |
| Technology metadata | Raw HTTP, Burp XML, HAR | `Server` or `X-Powered-By` header | Technology disclosure is frequently informational only. |
| Potential credential exposure | Static files | Token-shaped assignment or known credential variable name | Placeholders, public keys, and demo values create false positives. Never disclose a full suspected secret. |
| Static implementation cues | Static files | `eval`, `innerHTML`, `debug=true`, TODO/FIXME, HTTP URL | A code pattern requires a reachable untrusted data flow and impact. |

## CORS boundary

The CORS rules flag broad allowances and obvious reflection patterns in local artifacts. They do not create cross-origin requests, test browser behavior, or claim a reportable issue. When a lead appears, first confirm scope and authorization, then determine whether the response contains sensitive data and whether policy actually permits an untrusted origin to read it. Do not attempt to access another user’s information.

## Potential credential boundary

Static matching examines only selected local source text. The renderer redacts likely secret values to a short prefix and suffix. Hunt Sift does not validate the value, contact an API, authenticate with it, or save it anywhere. If a value appears real, stop sharing it, follow the owner’s revocation process, and report the exposure through an authorized private channel.

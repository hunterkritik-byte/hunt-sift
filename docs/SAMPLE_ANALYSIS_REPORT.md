# Hunt Sift Sample Analysis Report

> These results were generated from sanitized local examples. They are review leads only, not findings against a real system.

## Burp Suite XML example

```text
[1] REVIEW / response-hardening-review
  No Content-Security-Policy header was found in this imported response.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK
  next step: Assess the page context and existing browser controls; header absence alone does not prove exploitability.

[2] REVIEW / response-hardening-review
  No X-Content-Type-Options header was found in this imported response.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK
  next step: Check whether user-controlled or ambiguous content types are actually served before assigning impact.

[3] REVIEW / response-hardening-review
  No Referrer-Policy header was found in this imported response.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK
  next step: Review only if the page includes sensitive URL parameters or outbound navigation that could expose them.

[4] REVIEW / transport-hardening-review
  HTTPS target label supplied, but no Strict-Transport-Security header appears in the imported response.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK
  next step: Check program policy and deployment context. HSTS absence is not automatically a reportable issue.

[5] REVIEW / cookie-attribute-review
  An imported Set-Cookie value lacks: secure, httponly, samesite.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK; Set-Cookie: session=demo
  next step: Confirm cookie purpose, transport requirements, and program impact standards without using other users' data.

[6] REVIEW / cors-policy-review
  The imported response uses Access-Control-Allow-Origin: *.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK
  next step: Review whether a sensitive unauthenticated response is readable cross-origin. Wildcard CORS alone does not establish impact.

[7] REVIEW / cors-credentials-policy-review
  The imported response combines wildcard CORS with Access-Control-Allow-Credentials: true.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK
  next step: Review the deployment configuration and browser behavior in an authorized context. This header combination alone is not a confirmed cross-origin data exposure.

[8] INFORMATIONAL / technology-metadata
  The response exposes the server header.
  evidence: https://app.example.test/profile / HTTP/1.1 200 OK; server: Example
  next step: Treat this as inventory metadata unless it directly contributes to a validated security impact.

```

## HAR example

```text
[1] REVIEW / response-hardening-review
  No Content-Security-Policy header was found in this imported response.
  evidence: https://api.example.test/v1/demo / HTTP 200
  next step: Assess the page context and existing browser controls; header absence alone does not prove exploitability.

[2] REVIEW / response-hardening-review
  No X-Content-Type-Options header was found in this imported response.
  evidence: https://api.example.test/v1/demo / HTTP 200
  next step: Check whether user-controlled or ambiguous content types are actually served before assigning impact.

[3] REVIEW / response-hardening-review
  No Referrer-Policy header was found in this imported response.
  evidence: https://api.example.test/v1/demo / HTTP 200
  next step: Review only if the page includes sensitive URL parameters or outbound navigation that could expose them.

[4] REVIEW / transport-hardening-review
  HTTPS target label supplied, but no Strict-Transport-Security header appears in the imported response.
  evidence: https://api.example.test/v1/demo / HTTP 200
  next step: Check program policy and deployment context. HSTS absence is not automatically a reportable issue.

[5] REVIEW / cookie-attribute-review
  An imported Set-Cookie value lacks: secure, httponly, samesite.
  evidence: https://api.example.test/v1/demo / HTTP 200; Set-Cookie: session=demo
  next step: Confirm cookie purpose, transport requirements, and program impact standards without using other users' data.

[6] REVIEW / cors-policy-review
  The imported response uses Access-Control-Allow-Origin: *.
  evidence: https://api.example.test/v1/demo / HTTP 200
  next step: Review whether a sensitive unauthenticated response is readable cross-origin. Wildcard CORS alone does not establish impact.

[7] REVIEW / cors-credentials-policy-review
  The imported response combines wildcard CORS with Access-Control-Allow-Credentials: true.
  evidence: https://api.example.test/v1/demo / HTTP 200
  next step: Review the deployment configuration and browser behavior in an authorized context. This header combination alone is not a confirmed cross-origin data exposure.

[8] INFORMATIONAL / technology-metadata
  The response exposes the server header.
  evidence: https://api.example.test/v1/demo / HTTP 200; server: Example
  next step: Treat this as inventory metadata unless it directly contributes to a validated security impact.

```

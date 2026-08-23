from hunt_sift.core.http_review import normalise_headers, review_headers


def test_sequence_header_values_are_normalized_individually():
    headers = {"Content-Security-Policy": ("default-src 'self'", "default-src *")}
    normalized = normalise_headers(headers)
    assert normalized["content-security-policy"] == ["default-src 'self'", "default-src *"]


def test_conflicting_sequence_security_headers_are_detected():
    leads = review_headers(
        "test",
        "https://example.test/",
        "HTTP/1.1 200 OK",
        {"Strict-Transport-Security": ("max-age=60", "max-age=31536000")},
    )
    assert any(lead.category == "conflicting-security-header-review" for lead in leads)


def test_cookie_values_are_redacted_from_evidence():
    leads = review_headers(
        "test",
        "https://example.test/",
        "HTTP/1.1 200 OK",
        {"Set-Cookie": "session=super-secret-token"},
    )
    cookie_leads = [lead for lead in leads if lead.category == "cookie-attribute-review"]
    assert cookie_leads
    assert "super-secret-token" not in cookie_leads[0].evidence
    assert "<value redacted>" in cookie_leads[0].evidence


def test_scalar_header_values_keep_existing_behavior():
    normalized = normalise_headers({"X-Test": "value"})
    assert normalized == {"x-test": ["value"]}

from hunt_sift.core.request_review import analyze_request, safe_test_templates


def test_request_review_detects_object_identifier():
    leads = analyze_request("GET /api/orders/42?user_id=42 HTTP/1.1\nHost: example.test\n\n")
    assert any(lead.category == "idor-review" for lead in leads)


def test_request_review_detects_injection_shaped_input_without_exposing_value():
    leads = analyze_request("GET /search?q=union%20select%20name%20from%20users HTTP/1.1\nHost: example.test\n\n")
    assert any(lead.category == "sql-injection-review" for lead in leads)
    assert all("users" not in lead.evidence for lead in leads if lead.category == "sql-injection-review")


def test_request_review_detects_sensitive_fields():
    leads = analyze_request("POST /api/profile HTTP/1.1\nHost: example.test\nContent-Type: application/x-www-form-urlencoded\n\nrole=admin&email=test@example.test")
    assert any(lead.category == "mass-assignment-review" for lead in leads)


def test_templates_are_inert_manual_review_guidance():
    templates = safe_test_templates("GET /api/item?id=1 HTTP/1.1\nHost: example.test\n\n")
    assert templates
    assert all("replay" not in item["template"].lower() for item in templates)

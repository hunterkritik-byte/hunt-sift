from hunt_sift.core.source_review import analyze_source


def test_source_review_flags_dom_sink():
    leads = analyze_source("element.innerHTML = userInput;")
    assert any(lead.category == "dom-xss-sink" for lead in leads)


def test_source_review_flags_message_listener():
    leads = analyze_source("window.addEventListener('message', handler);")
    assert any(lead.category == "weak-postmessage-origin" for lead in leads)


def test_source_review_redacts_matching_source():
    leads = analyze_source("const apiKey = 'super-secret-value';")
    assert any(lead.category == "hardcoded-secret-review" for lead in leads)
    assert all("super-secret-value" not in lead.evidence for lead in leads)

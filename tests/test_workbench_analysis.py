from hunt_sift.core.endpoint_map import endpoint_dicts
from hunt_sift.core.parameter_miner import mine_parameters
from hunt_sift.core.response_diff import compare_responses


def test_response_diff_redacts_sensitive_headers():
    before = "HTTP/1.1 200 OK\nX-Test: a\nSet-Cookie: secret=one\n\nhello"
    after = "HTTP/1.1 403 Forbidden\nX-Test: b\nSet-Cookie: secret=two\n\nnope"
    leads = compare_responses(before, after)
    assert any(x.category == "status-change" for x in leads)
    assert all("secret=one" not in x.evidence and "secret=two" not in x.evidence for x in leads)


def test_endpoint_map_deduplicates_paths_and_collects_parameters():
    data = "GET https://example.test/api/user?id=1 HTTP/1.1\nGET https://example.test/api/user?role=user HTTP/1.1\n"
    endpoints = endpoint_dicts(data)
    assert endpoints == [{"method": "GET", "path": "/api/user", "parameters": ["id", "role"], "sources": ["artifact"]}]


def test_parameter_miner_classifies_authorization_and_identity():
    result = mine_parameters("/api/item?id=1&role=user&redirect=/home")
    assert "id" in result["classes"]["identity"]
    assert "role" in result["classes"]["authorization"]
    assert "redirect" in result["classes"]["redirect"]

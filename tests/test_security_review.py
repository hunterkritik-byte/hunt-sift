from hunt_sift.core.graphql_review import analyze_graphql
from hunt_sift.core.jwt_review import analyze_jwt
from hunt_sift.core.openapi_review import analyze_openapi
from hunt_sift.core.secrets_review import analyze_secrets


def test_jwt_review_never_exposes_token_value():
    token = "eyJhbGciOiJub25lIn0.eyJyb2xlIjoiYWRtaW4ifQ.signature"
    leads = analyze_jwt(token)
    assert any(lead.category == "jwt-algorithm-review" for lead in leads)
    assert all(token not in lead.evidence for lead in leads)


def test_graphql_introspection_review():
    leads = analyze_graphql("query { __schema { types { name } } }")
    assert any(lead.category == "graphql-introspection-review" for lead in leads)


def test_openapi_empty_security_review():
    spec = '{"openapi":"3.0.0","paths":{"/admin":{"get":{"security":[]}}}}'
    leads = analyze_openapi(spec)
    assert any(lead.category == "openapi-auth-review" for lead in leads)


def test_secret_values_are_redacted():
    leads = analyze_secrets("API_KEY = 'super-secret-value-12345'", "fixture.js")
    assert leads
    assert "super-secret-value-12345" not in leads[0].evidence

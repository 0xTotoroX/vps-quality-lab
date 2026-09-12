import json

from vps_quality_lab.security import redact_urls, safe_output


def test_auth_query_parameters_are_removed():
    value = "Request failed https://example.com/novnc?url=wss%3A%2F%2Fexample.com%2Fws%3Ftoken%3Dinner-secret&password=private-password&host_token=private-host-token"
    redacted = redact_urls(value)
    for secret in ["inner-secret", "private-password", "private-host-token"]:
        assert secret not in redacted
    assert "example.com/novnc" in redacted


def test_url_userinfo_is_removed():
    assert "passphrase" not in redact_urls("https://user:passphrase@example.com/api")


def test_nested_diagnostic_strings_are_redacted():
    result = safe_output({"error": ["https://example.com/?access_token=test-secret"], "password": "secret", "host_token": "sensitive-value"})
    assert "test-secret" not in json.dumps(result)
    assert result["password"] == "[redacted]"
    assert result["host_token"] == "[redacted]"

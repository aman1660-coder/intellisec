from app.scanners.http_scanner import analyze_cookies, analyze_headers


def test_missing_security_headers_generate_structured_findings():
    findings, observations = analyze_headers({})
    types = {finding["finding_type"] for finding in findings}
    assert "missing_hsts" in types
    assert "missing_csp" in types
    assert "missing_x_frame_options" in types
    assert all("finding_id" in finding for finding in findings)
    assert len(observations) >= 8


def test_cookie_flag_analysis_is_deterministic():
    findings, observations = analyze_cookies(["sessionid=abc123; Path=/"])
    assert observations[0]["missing_flags"] == ["Secure", "HttpOnly", "SameSite"]
    assert findings[0]["finding_type"] == "insecure_cookie_flags"
    assert findings[0]["deterministic_status"] == "assessed"


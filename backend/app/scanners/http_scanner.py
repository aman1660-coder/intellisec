from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.utils.findings import make_finding
from app.utils.target_validator import ValidatedTarget, validate_redirect

logger = logging.getLogger(__name__)

HEADER_POLICIES = {
    "strict-transport-security": {
        "title": "Strict-Transport-Security is missing",
        "type": "missing_hsts",
        "severity": "medium",
        "score": 6.5,
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "description": "Without HSTS, browsers may accept downgraded HTTP connections after first contact.",
        "cwe": "CWE-319",
    },
    "content-security-policy": {
        "title": "Content-Security-Policy is missing",
        "type": "missing_csp",
        "severity": "medium",
        "score": 6.2,
        "recommended": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "description": "A missing CSP reduces defense in depth against injected script and content-loading abuse.",
        "cwe": "CWE-693",
    },
    "x-frame-options": {
        "title": "X-Frame-Options is missing",
        "type": "missing_x_frame_options",
        "severity": "medium",
        "score": 5.5,
        "recommended": "DENY or SAMEORIGIN",
        "description": "Missing frame restrictions increase clickjacking exposure for sensitive screens.",
        "cwe": "CWE-1021",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options is missing",
        "type": "missing_x_content_type_options",
        "severity": "low",
        "score": 3.2,
        "recommended": "nosniff",
        "description": "Browsers may MIME-sniff responses, weakening content-type boundaries.",
        "cwe": "CWE-16",
    },
    "referrer-policy": {
        "title": "Referrer-Policy is missing",
        "type": "missing_referrer_policy",
        "severity": "low",
        "score": 2.4,
        "recommended": "strict-origin-when-cross-origin",
        "description": "A missing referrer policy can leak URL context to third-party origins.",
        "cwe": "CWE-116",
    },
    "permissions-policy": {
        "title": "Permissions-Policy is missing",
        "type": "missing_permissions_policy",
        "severity": "low",
        "score": 2.2,
        "recommended": "camera=(), microphone=(), geolocation=()",
        "description": "A missing permissions policy leaves browser feature access less explicitly constrained.",
        "cwe": "CWE-16",
    },
    "cross-origin-opener-policy": {
        "title": "Cross-Origin-Opener-Policy is missing",
        "type": "missing_coop",
        "severity": "low",
        "score": 1.8,
        "recommended": "same-origin",
        "description": "A missing COOP can reduce cross-origin isolation for high-risk applications.",
        "cwe": "CWE-16",
    },
    "cross-origin-resource-policy": {
        "title": "Cross-Origin-Resource-Policy is missing",
        "type": "missing_corp",
        "severity": "low",
        "score": 1.8,
        "recommended": "same-origin or same-site",
        "description": "A missing CORP can weaken resource isolation for sensitive responses.",
        "cwe": "CWE-16",
    },
    "cross-origin-embedder-policy": {
        "title": "Cross-Origin-Embedder-Policy is missing",
        "type": "missing_coep",
        "severity": "low",
        "score": 1.6,
        "recommended": "require-corp where cross-origin isolation is required",
        "description": "A missing COEP can prevent strict cross-origin isolation where needed.",
        "cwe": "CWE-16",
    },
}

# Sensitive paths that should not appear in robots.txt
_SENSITIVE_ROBOT_PATHS = {
    "/admin", "/backup", "/config", "/database", "/debug",
    "/phpmyadmin", "/wp-admin", "/api/", "/internal",
    "/.env", "/.git", "/server-status", "/cpanel",
    "/wp-config", "/passwd", "/secret", "/private",
}


def _header_finding(header: str, policy: dict[str, Any], observed: str | None, source: str) -> dict[str, Any]:
    return make_finding(
        finding_type=policy["type"],
        title=policy["title"] if observed is None else f"Unsafe {header} configuration",
        category="HTTP security headers",
        description=policy["description"],
        evidence={"header": header, "observed_value": observed, "recommended_value": policy["recommended"]},
        severity=policy["severity"],
        base_score=policy["score"],
        remediation=f"Configure {header} as: {policy['recommended']}.",
        affected_component=f"HTTP header: {header}",
        source=source,
        cwe=policy.get("cwe"),
    )


def analyze_headers(headers: httpx.Headers | dict[str, str], source: str = "live-scan") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    lower_headers = {k.lower(): v for k, v in dict(headers).items()}
    for header, policy in HEADER_POLICIES.items():
        value = lower_headers.get(header)
        state = {"header": header, "present": value is not None, "observed_value": value, "recommended_value": policy["recommended"]}
        observations.append(state)
        if value is None:
            findings.append(_header_finding(header, policy, None, source))
            continue
        lowered = value.lower()
        unsafe = False
        if header == "strict-transport-security":
            unsafe = "max-age=0" in lowered or "max-age" not in lowered
        elif header == "content-security-policy":
            unsafe = "*" in lowered or "unsafe-inline" in lowered and "nonce-" not in lowered and "sha" not in lowered
        elif header == "x-frame-options":
            unsafe = lowered not in {"deny", "sameorigin"}
        elif header == "x-content-type-options":
            unsafe = lowered != "nosniff"
        elif header == "referrer-policy":
            unsafe = lowered in {"unsafe-url", "no-referrer-when-downgrade"}
        if unsafe:
            findings.append(_header_finding(header, policy, value, source))
    return findings, observations


def analyze_cookies(set_cookie_headers: list[str], source: str = "live-scan") -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    observations: list[dict[str, Any]] = []
    for raw in set_cookie_headers:
        parts = [p.strip() for p in raw.split(";") if p.strip()]
        if not parts or "=" not in parts[0]:
            continue
        name = parts[0].split("=", 1)[0]
        attrs = {p.lower().split("=", 1)[0]: p for p in parts[1:]}
        missing = []
        if "secure" not in attrs:
            missing.append("Secure")
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if "samesite" not in attrs:
            missing.append("SameSite")
        observations.append({"cookie": name, "missing_flags": missing, "raw_attributes": list(attrs.values())})
        if missing:
            score = 6.6 if "Secure" in missing or "HttpOnly" in missing else 4.0
            findings.append(
                make_finding(
                    finding_type="insecure_cookie_flags",
                    title=f"Cookie {name} is missing security flags",
                    category="Cookie security",
                    description="Observable Set-Cookie metadata is missing one or more defensive flags.",
                    evidence={"cookie": name, "missing_flags": missing},
                    severity="medium" if score < 7 else "high",
                    base_score=score,
                    remediation="Set Secure, HttpOnly, and SameSite=Lax or Strict for session cookies where compatible.",
                    affected_component=f"Set-Cookie: {name}",
                    source=source,
                    metadata={"missing_flags": missing},
                    cwe="CWE-614",
                )
            )
    return findings, observations


# ---------------------------------------------------------------------------
# New check functions (genuine HTTP probes)
# ---------------------------------------------------------------------------

async def _check_cors(client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
    """Send a request with a spoofed Origin and check CORS headers."""
    findings: list[dict[str, Any]] = []
    try:
        resp = await client.get(url, headers={"Origin": "https://evil.com"})
        acao = (resp.headers.get("access-control-allow-origin") or "").strip()
        acac = (resp.headers.get("access-control-allow-credentials") or "").strip().lower()

        if acao == "https://evil.com":
            findings.append(make_finding(
                "cors_origin_reflection", "CORS origin reflection detected",
                "CORS security", "The server reflects arbitrary Origin values in Access-Control-Allow-Origin, allowing any website to make authenticated cross-origin requests.",
                {"origin_sent": "https://evil.com", "acao_received": acao, "acac": acac},
                "high", "Validate Origins against an explicit allowlist. Never reflect arbitrary origins.",
                "CORS configuration", 8.5, cwe="CWE-942",
            ))
        elif acao == "*" and acac == "true":
            findings.append(make_finding(
                "cors_misconfiguration", "CORS wildcard with credentials enabled",
                "CORS security", "Access-Control-Allow-Origin is set to '*' while credentials are allowed. This is a critical misconfiguration that browsers should block, but older implementations may not.",
                {"acao": acao, "acac": acac},
                "high", "Set a specific allowed origin instead of '*' when credentials are required.",
                "CORS configuration", 8.0, cwe="CWE-942",
            ))
        elif acao == "*":
            findings.append(make_finding(
                "cors_wildcard", "CORS wildcard origin allowed",
                "CORS security", "Access-Control-Allow-Origin is set to '*', allowing any website to read responses from this origin.",
                {"acao": acao},
                "medium", "Restrict CORS to specific trusted origins instead of using a wildcard.",
                "CORS configuration", 5.5, cwe="CWE-942",
            ))
    except Exception:
        pass
    return findings


async def _check_disclosure(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Check for server and technology information disclosure headers."""
    findings: list[dict[str, Any]] = []
    lower = {k.lower(): v for k, v in headers.items()}

    server = lower.get("server", "")
    if server and any(c.isdigit() for c in server):
        findings.append(make_finding(
            "server_info_disclosure", "Server version information disclosed",
            "Information disclosure", f"The Server header reveals '{server}', which helps attackers identify known vulnerabilities for this specific version.",
            {"header": "Server", "value": server},
            "low", "Remove the version from the Server header or suppress it entirely.",
            "HTTP header: Server", 3.0, cwe="CWE-200",
        ))

    for hdr in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        val = lower.get(hdr, "")
        if val:
            findings.append(make_finding(
                "technology_disclosure", f"Technology stack disclosed via {hdr}",
                "Information disclosure", f"The {hdr} header reveals '{val}', aiding targeted attacks against the identified technology.",
                {"header": hdr, "value": val},
                "low", f"Remove the {hdr} header from server responses.",
                f"HTTP header: {hdr}", 3.0, cwe="CWE-200",
            ))
            break  # one finding is enough

    return findings


async def _check_methods(client: httpx.AsyncClient, url: str) -> list[dict[str, Any]]:
    """Send OPTIONS request and check for dangerous HTTP methods."""
    findings: list[dict[str, Any]] = []
    try:
        resp = await client.options(url)
        allow = resp.headers.get("allow", "")
        methods = {m.strip().upper() for m in allow.split(",") if m.strip()}

        if "TRACE" in methods:
            findings.append(make_finding(
                "trace_method_enabled", "HTTP TRACE method enabled",
                "HTTP methods", "TRACE is enabled on the server. This can be exploited for Cross-Site Tracing (XST) attacks to steal credentials and session tokens.",
                {"allowed_methods": sorted(methods)},
                "medium", "Disable the TRACE method on the web server.",
                "HTTP method configuration", 5.5, cwe="CWE-16",
            ))

        dangerous = methods & {"PUT", "DELETE"}
        if dangerous:
            findings.append(make_finding(
                "dangerous_methods_enabled", f"Dangerous HTTP methods enabled: {', '.join(sorted(dangerous))}",
                "HTTP methods", f"The server allows {', '.join(sorted(dangerous))} methods which could enable unauthorized file manipulation or deletion.",
                {"allowed_methods": sorted(methods), "dangerous_methods": sorted(dangerous)},
                "medium", "Restrict HTTP methods to GET, POST, and HEAD unless explicitly required.",
                "HTTP method configuration", 5.0, cwe="CWE-16",
            ))
    except Exception:
        pass
    return findings


async def _check_https_redirect(client: httpx.AsyncClient, target: ValidatedTarget) -> list[dict[str, Any]]:
    """Check if HTTP version of site redirects to HTTPS."""
    findings: list[dict[str, Any]] = []
    if target.scheme != "https":
        return findings
    http_url = f"http://{target.host}:{80}"
    if target.port == 443:
        http_url = f"http://{target.host}"
    try:
        resp = await client.get(http_url, follow_redirects=False, timeout=5.0)
        location = resp.headers.get("location", "")
        if resp.is_redirect and location.startswith("https://"):
            pass  # Good — HTTP redirects to HTTPS
        else:
            findings.append(make_finding(
                "no_https_redirect", "HTTP does not redirect to HTTPS",
                "Transport security", "The HTTP version of this site does not redirect to HTTPS. Users connecting via HTTP will transmit data in cleartext, vulnerable to interception.",
                {"http_url": http_url, "status_code": resp.status_code, "location": location or None},
                "high", "Configure the web server to redirect all HTTP requests to HTTPS with a 301 redirect.",
                "HTTP to HTTPS redirect", 7.0, cwe="CWE-319",
            ))
    except Exception:
        pass  # HTTP port might be closed — not a finding
    return findings


async def _check_security_txt(client: httpx.AsyncClient, base_url: str) -> list[dict[str, Any]]:
    """Check for /.well-known/security.txt."""
    findings: list[dict[str, Any]] = []
    try:
        parsed = urlparse(base_url)
        url = f"{parsed.scheme}://{parsed.netloc}/.well-known/security.txt"
        resp = await client.get(url, timeout=5.0)
        if resp.status_code != 200:
            findings.append(make_finding(
                "missing_security_txt", "No security.txt vulnerability disclosure policy",
                "Security policy", "No security.txt file was found at /.well-known/security.txt. This file helps security researchers responsibly disclose vulnerabilities.",
                {"url": url, "status_code": resp.status_code},
                "info", "Create a security.txt file at /.well-known/security.txt with contact and policy information per RFC 9116.",
                "Vulnerability disclosure policy", 1.0, cwe="CWE-1059",
            ))
    except Exception:
        pass
    return findings


async def _check_robots_txt(client: httpx.AsyncClient, base_url: str) -> list[dict[str, Any]]:
    """Check robots.txt for sensitive path disclosures."""
    findings: list[dict[str, Any]] = []
    try:
        parsed = urlparse(base_url)
        url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        resp = await client.get(url, timeout=5.0)
        if resp.status_code == 200:
            text = resp.text.lower()
            sensitive_found = []
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    for sensitive in _SENSITIVE_ROBOT_PATHS:
                        if sensitive in path:
                            sensitive_found.append(path)
                            break
            if sensitive_found:
                findings.append(make_finding(
                    "sensitive_paths_in_robots", "Sensitive paths disclosed in robots.txt",
                    "Information disclosure", f"The robots.txt file reveals {len(sensitive_found)} potentially sensitive path(s). Attackers commonly check robots.txt for hidden admin panels, backups, and configuration files.",
                    {"url": url, "sensitive_paths": sensitive_found},
                    "low", "Remove sensitive paths from robots.txt. Use authentication and proper access controls instead of relying on obscurity.",
                    "robots.txt", 3.5, cwe="CWE-538",
                ))
    except Exception:
        pass
    return findings


def _check_csp_detail(headers: dict[str, str]) -> list[dict[str, Any]]:
    """Perform detailed CSP analysis when CSP header exists."""
    findings: list[dict[str, Any]] = []
    lower = {k.lower(): v for k, v in headers.items()}
    csp = lower.get("content-security-policy", "")
    if not csp:
        return findings

    csp_lower = csp.lower()

    if "unsafe-eval" in csp_lower:
        findings.append(make_finding(
            "csp_unsafe_eval", "CSP allows unsafe-eval",
            "HTTP security headers", "The Content-Security-Policy includes 'unsafe-eval', which allows JavaScript eval() and similar dynamic code execution, weakening XSS protections.",
            {"csp": csp, "dangerous_directive": "unsafe-eval"},
            "medium", "Remove 'unsafe-eval' from CSP. Refactor code to avoid eval() and new Function().",
            "Content-Security-Policy", 6.0, cwe="CWE-94",
        ))

    if "data:" in csp_lower and "script-src" in csp_lower:
        findings.append(make_finding(
            "csp_data_uri", "CSP allows data: URIs in scripts",
            "HTTP security headers", "The CSP script-src directive allows 'data:' URIs, which can be used to inject and execute arbitrary JavaScript.",
            {"csp": csp, "dangerous_directive": "data:"},
            "medium", "Remove 'data:' from script-src. Use nonce or hash-based CSP instead.",
            "Content-Security-Policy", 5.5, cwe="CWE-94",
        ))

    xfo = lower.get("x-frame-options", "")
    if "frame-ancestors" not in csp_lower and not xfo:
        findings.append(make_finding(
            "csp_missing_frame_ancestors", "CSP missing frame-ancestors directive",
            "HTTP security headers", "The CSP does not include frame-ancestors and no X-Frame-Options header is set. This leaves the site vulnerable to clickjacking attacks.",
            {"csp": csp, "x_frame_options": xfo or None},
            "medium", "Add 'frame-ancestors' directive to CSP (e.g., frame-ancestors 'self') or set X-Frame-Options.",
            "Content-Security-Policy", 5.0, cwe="CWE-1021",
        ))

    return findings


def _check_cache_control(headers: dict[str, str], is_https: bool) -> list[dict[str, Any]]:
    """Check for missing cache control on HTTPS responses."""
    findings: list[dict[str, Any]] = []
    if not is_https:
        return findings
    lower = {k.lower(): v for k, v in headers.items()}
    cc = lower.get("cache-control", "").lower()
    pragma = lower.get("pragma", "").lower()
    if "no-store" not in cc and "no-cache" not in cc and "no-cache" not in pragma:
        findings.append(make_finding(
            "missing_cache_control", "Missing cache control for HTTPS response",
            "HTTP security headers", "The HTTPS response does not include Cache-Control: no-store or no-cache. Sensitive data may be cached by proxies or browsers.",
            {"cache_control": cc or None, "pragma": pragma or None},
            "low", "Add 'Cache-Control: no-store, no-cache, must-revalidate' to responses containing sensitive data.",
            "HTTP header: Cache-Control", 2.8, cwe="CWE-525",
        ))
    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def inspect_http(target: ValidatedTarget) -> dict[str, Any]:
    current = target.normalized_url
    redirects: list[str] = []
    transport_warning = None
    async with httpx.AsyncClient(timeout=settings.scan_timeout, follow_redirects=False, headers={"User-Agent": "IntelliSec defensive scanner/1.0"}) as client:
        for _ in range(settings.max_redirects + 1):
            try:
                async with client.stream("GET", current) as response:
                    content_read = 0
                    async for chunk in response.aiter_bytes():
                        content_read += len(chunk)
                        if content_read >= settings.max_response_bytes:
                            break
                    if response.is_redirect and response.headers.get("location"):
                        next_target = validate_redirect(current, response.headers["location"])
                        redirects.append(next_target.normalized_url)
                        current = next_target.normalized_url
                        continue
                    header_findings, header_observations = analyze_headers(response.headers)
                    cookie_findings, cookie_observations = analyze_cookies(response.headers.get_list("set-cookie"))

                    # --- New genuine checks (real HTTP probes) ---
                    resp_headers = dict(response.headers)
                    extra_findings: list[dict[str, Any]] = []

                    cors_findings = await _check_cors(client, current)
                    disclosure_findings = await _check_disclosure(resp_headers)
                    method_findings = await _check_methods(client, current)
                    redirect_findings = await _check_https_redirect(client, target)
                    sec_txt_findings = await _check_security_txt(client, current)
                    robots_findings = await _check_robots_txt(client, current)
                    csp_findings = _check_csp_detail(resp_headers)
                    cache_findings = _check_cache_control(resp_headers, current.startswith("https://"))

                    extra_findings = (
                        cors_findings + disclosure_findings + method_findings +
                        redirect_findings + sec_txt_findings + robots_findings +
                        csp_findings + cache_findings
                    )

                    return {
                        "final_url": current,
                        "status_code": response.status_code,
                        "redirect_chain": redirects,
                        "headers": header_observations,
                        "cookies": cookie_observations,
                        "findings": header_findings + cookie_findings + extra_findings,
                        "transport_warning": transport_warning,
                    }
            except httpx.HTTPError as exc:
                return {
                    "final_url": current,
                    "status_code": None,
                    "redirect_chain": redirects,
                    "headers": [],
                    "cookies": [],
                    "findings": [],
                    "error": f"HTTP inspection failed: {exc.__class__.__name__}",
                    "transport_warning": transport_warning,
                }
        return {
            "final_url": current,
            "status_code": None,
            "redirect_chain": redirects,
            "headers": [],
            "cookies": [],
            "findings": [],
            "error": "Redirect limit exceeded.",
            "transport_warning": transport_warning,
        }

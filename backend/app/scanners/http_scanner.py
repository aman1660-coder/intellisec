from __future__ import annotations

from typing import Any

import httpx

from app.core.config import settings
from app.utils.findings import make_finding
from app.utils.target_validator import ValidatedTarget, validate_redirect


HEADER_POLICIES = {
    "strict-transport-security": {
        "title": "Strict-Transport-Security is missing",
        "type": "missing_hsts",
        "severity": "medium",
        "score": 6.5,
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "description": "Without HSTS, browsers may accept downgraded HTTP connections after first contact.",
    },
    "content-security-policy": {
        "title": "Content-Security-Policy is missing",
        "type": "missing_csp",
        "severity": "medium",
        "score": 6.2,
        "recommended": "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        "description": "A missing CSP reduces defense in depth against injected script and content-loading abuse.",
    },
    "x-frame-options": {
        "title": "X-Frame-Options is missing",
        "type": "missing_x_frame_options",
        "severity": "medium",
        "score": 5.5,
        "recommended": "DENY or SAMEORIGIN",
        "description": "Missing frame restrictions increase clickjacking exposure for sensitive screens.",
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options is missing",
        "type": "missing_x_content_type_options",
        "severity": "low",
        "score": 3.2,
        "recommended": "nosniff",
        "description": "Browsers may MIME-sniff responses, weakening content-type boundaries.",
    },
    "referrer-policy": {
        "title": "Referrer-Policy is missing",
        "type": "missing_referrer_policy",
        "severity": "low",
        "score": 2.4,
        "recommended": "strict-origin-when-cross-origin",
        "description": "A missing referrer policy can leak URL context to third-party origins.",
    },
    "permissions-policy": {
        "title": "Permissions-Policy is missing",
        "type": "missing_permissions_policy",
        "severity": "low",
        "score": 2.2,
        "recommended": "camera=(), microphone=(), geolocation=()",
        "description": "A missing permissions policy leaves browser feature access less explicitly constrained.",
    },
    "cross-origin-opener-policy": {
        "title": "Cross-Origin-Opener-Policy is missing",
        "type": "missing_coop",
        "severity": "low",
        "score": 1.8,
        "recommended": "same-origin",
        "description": "A missing COOP can reduce cross-origin isolation for high-risk applications.",
    },
    "cross-origin-resource-policy": {
        "title": "Cross-Origin-Resource-Policy is missing",
        "type": "missing_corp",
        "severity": "low",
        "score": 1.8,
        "recommended": "same-origin or same-site",
        "description": "A missing CORP can weaken resource isolation for sensitive responses.",
    },
    "cross-origin-embedder-policy": {
        "title": "Cross-Origin-Embedder-Policy is missing",
        "type": "missing_coep",
        "severity": "low",
        "score": 1.6,
        "recommended": "require-corp where cross-origin isolation is required",
        "description": "A missing COEP can prevent strict cross-origin isolation where needed.",
    },
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
                )
            )
    return findings, observations


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
                    return {
                        "final_url": current,
                        "status_code": response.status_code,
                        "redirect_chain": redirects,
                        "headers": header_observations,
                        "cookies": cookie_observations,
                        "findings": header_findings + cookie_findings,
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


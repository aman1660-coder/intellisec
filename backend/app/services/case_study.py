from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.ai.service import fallback_interpretation
from app.compliance.mapper import map_findings, summarize_mappings
from app.correlation.engine import discover_attack_paths
from app.pqc.engine import assess_pqc
from app.reports.generator import generate_reports
from app.scoring.risk import score_contextual_risk
from app.utils.findings import make_finding


def _case_finding(*args: Any, **kwargs: Any) -> dict[str, Any]:
    kwargs["source"] = "research-case-study"
    return make_finding(*args, **kwargs)


def build_case_study_scan() -> dict[str, Any]:
    findings = [
        _case_finding("deprecated_tls", "TLS 1.1 support detected", "TLS and cryptography", "Representative target supports TLS 1.1 alongside TLS 1.2/1.3.", {"protocol": "TLS 1.1"}, "medium", "Disable TLS 1.1.", "TLS protocol configuration", 6.8),
        _case_finding("weak_tls_cipher", "RC4 cipher suite example present", "TLS and cryptography", "Representative target includes an RC4 cipher example.", {"cipher": "RC4"}, "medium", "Remove RC4 and all weak suites.", "TLS cipher configuration", 6.6),
        _case_finding("non_forward_secret_cipher", "TLS_RSA_WITH_AES_128_CBC_SHA example present", "TLS and cryptography", "Representative target includes a non-forward-secret RSA key exchange suite.", {"cipher": "TLS_RSA_WITH_AES_128_CBC_SHA"}, "medium", "Use ECDHE suites.", "TLS key exchange", 6.4),
        _case_finding("classical_crypto_dependency", "RSA-2048 SHA-256 certificate dependency", "PQC readiness", "Representative target uses RSA-2048 with SHA-256.", {"public_key": {"algorithm": "RSA", "size": 2048}, "signature_algorithm": "sha256WithRSAEncryption"}, "low", "Plan hybrid/PQC migration.", "TLS certificate", 3.5),
        _case_finding("missing_hsts", "Strict-Transport-Security is missing", "HTTP security headers", "HSTS is absent in the representative configuration.", {"header": "Strict-Transport-Security", "observed_value": None}, "medium", "Set HSTS with long max-age.", "HTTP header", 6.5),
        _case_finding("missing_csp", "Content-Security-Policy is missing", "HTTP security headers", "CSP is absent in the representative configuration.", {"header": "Content-Security-Policy", "observed_value": None}, "medium", "Deploy a restrictive CSP.", "HTTP header", 5.84),
        _case_finding("missing_x_frame_options", "X-Frame-Options is missing", "HTTP security headers", "Frame protection is absent in the representative configuration.", {"header": "X-Frame-Options", "observed_value": None}, "medium", "Set X-Frame-Options or frame-ancestors.", "HTTP header", 5.5),
        _case_finding("insecure_cookie_flags", "Session cookie lacks Secure and HttpOnly", "Cookie security", "Representative Set-Cookie metadata is missing Secure and HttpOnly flags.", {"cookie": "sessionid", "missing_flags": ["Secure", "HttpOnly"]}, "medium", "Set Secure, HttpOnly, and SameSite.", "Set-Cookie", 6.4, metadata={"missing_flags": ["Secure", "HttpOnly"]}),
    ]
    tls = {
        "assessed": True,
        "protocols": {"TLS 1.1": {"supported": True}, "TLS 1.2": {"supported": True}, "TLS 1.3": {"supported": True}},
        "negotiated": {"protocol": "TLSv1.3", "cipher": {"name": "TLS_AES_256_GCM_SHA384", "bits": 256}},
        "certificate": {
            "issuer": "Research Case Study CA",
            "subject": "CN=case-study.intellisec.local",
            "serial_number": "0x2026",
            "valid_not_before": "2026-01-01T00:00:00+00:00",
            "valid_not_after": "2027-01-01T00:00:00+00:00",
            "days_until_expiry": 174,
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key": {"algorithm": "RSA", "size": 2048},
            "hostname_match": True,
            "trust_status": "trusted",
            "classical_crypto_dependency": True,
        },
        "findings": [f for f in findings if f["category"] in {"TLS and cryptography", "Certificate intelligence", "PQC readiness"}],
    }
    http = {
        "final_url": "https://case-study.intellisec.local/",
        "status_code": 200,
        "headers": [],
        "cookies": [{"cookie": "sessionid", "missing_flags": ["Secure", "HttpOnly"]}],
        "findings": [f for f in findings if f["category"] in {"HTTP security headers", "Cookie security"}],
    }
    correlation = discover_attack_paths(findings)
    primary = None
    secondary = None
    for path in correlation["attack_paths"]:
        types = [node["finding_type"] for node in path["ordered_nodes"]]
        if types == ["deprecated_tls", "missing_hsts", "insecure_cookie_flags"]:
            primary = {**path, "case_study_label": "Primary chain: downgrade to cookie theft"}
        if types == ["missing_csp", "insecure_cookie_flags"]:
            secondary = {**path, "case_study_label": "Secondary chain: XSS to session exposure"}
    case_paths = [p for p in [primary, secondary] if p]
    compliance = map_findings(findings)
    risk = score_contextual_risk(
        findings,
        case_paths,
        {"data_sensitivity": "high", "exposure_type": "public", "authentication_status": "none", "business_criticality": "high"},
    )
    pqc = assess_pqc(tls, {"data_sensitivity": "high"})
    scan = {
        "id": "research-case-study",
        "user_id": None,
        "target": "Research Paper Case Study Dataset",
        "normalized_target": "https://case-study.intellisec.local/",
        "scan_mode": "RESEARCH CASE STUDY",
        "status": "completed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "context": {"data_sensitivity": "high", "exposure_type": "public", "authentication_status": "none", "business_criticality": "high"},
        "findings": findings,
        "attack_paths": case_paths,
        "attack_graph": correlation["graph"],
        "risk_assessment": risk,
        "compliance_mappings": compliance,
        "compliance_summary": summarize_mappings(compliance),
        "pqc_readiness": pqc,
        "tls": tls,
        "http": http,
        "ai_interpretation": fallback_interpretation({"findings": findings, "attack_paths": case_paths, "risk_scores": risk, "compliance_mappings": compliance, "pqc_readiness": pqc}),
        "data_mode_notice": "Research Paper Case Study Dataset. This is simulated from the paper and is not a live scan.",
        "execution_time_ms": 0,
    }
    scan["intellisec_score"] = max(0, round(100 - risk["final_score"] * 8 - len([f for f in findings if f["severity"] == "high"]) * 4))
    scan["reports"] = generate_reports(scan)
    return scan

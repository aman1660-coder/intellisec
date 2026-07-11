from __future__ import annotations

from typing import Any

from app.utils.findings import severity_from_score


HIGH_CRYPTO_TYPES = {
    "deprecated_tls",
    "weak_tls_cipher",
    "sha1_certificate_signature",
    "rsa_key_below_2048",
    "expired_certificate",
    "untrusted_certificate",
}


def _context_value(context: dict[str, Any], key: str, default: str) -> str:
    return str(context.get(key) or default).lower()


def score_contextual_risk(findings: list[dict[str, Any]], attack_paths: list[dict[str, Any]], context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    auth = _context_value(context, "authentication_status", "unknown")
    data = _context_value(context, "data_sensitivity", "moderate")
    exposure = _context_value(context, "exposure_type", "public")
    criticality = _context_value(context, "business_criticality", "moderate")

    d1 = 2.0 if auth in {"none", "public", "unauthenticated", "unknown"} else 1.1
    d2 = {"low": 0.5, "moderate": 1.0, "medium": 1.0, "high": 1.6, "critical": 2.0}.get(data, 1.0)
    if criticality in {"high", "critical"}:
        d2 = min(2.0, d2 + 0.25)
    has_high_crypto = any(f.get("finding_type") in HIGH_CRYPTO_TYPES for f in findings)
    has_crypto = any("TLS" in f.get("category", "") or "Certificate" in f.get("category", "") for f in findings)
    d3 = 2.0 if has_high_crypto else (1.0 if has_crypto else 0.4)
    d4 = {"public": 2.0, "internet": 2.0, "external": 1.8, "partner": 1.1, "internal": 0.5}.get(exposure, 1.5)
    max_alpha = max([float(path.get("amplification_factor", 1)) for path in attack_paths] or [1.0])
    d5 = min(2.0, max(0.0, (max_alpha - 1.0) * 5.0))
    dimensions = {
        "D1_exploitability": {"score": round(d1, 2), "reasoning": f"Authentication context: {auth}."},
        "D2_data_sensitivity": {"score": round(d2, 2), "reasoning": f"Data sensitivity and business criticality: {data}/{criticality}."},
        "D3_cryptographic_weakness_depth": {"score": round(d3, 2), "reasoning": "Highest observed cryptographic weakness depth across deterministic findings."},
        "D4_exposure_surface": {"score": round(d4, 2), "reasoning": f"Exposure type: {exposure}."},
        "D5_chain_amplification": {"score": round(d5, 2), "reasoning": "Derived from the strongest discovered attack-path amplification factor."},
    }
    final = sum(item["score"] for item in dimensions.values())
    isolated_mean = sum(float(f.get("base_score", 0)) for f in findings) / max(len(findings), 1)
    return {
        "dimensions": dimensions,
        "normalization": "Each dimension is scored 0-2; the five-factor sum is already on a 0-10 scale.",
        "final_score": round(min(10.0, final), 2),
        "severity": severity_from_score(final),
        "base_severity_mean": round(isolated_mean, 2),
        "contextual_delta": round(min(10.0, final) - isolated_mean, 2),
    }


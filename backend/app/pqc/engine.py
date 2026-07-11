from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


CONFIG = json.loads(Path(__file__).with_name("config.json").read_text(encoding="utf-8"))


def _classification(score: float) -> str:
    for threshold in CONFIG["thresholds"]:
        if score <= threshold["max"]:
            return threshold["classification"]
    return "PQC Ready"


def _signature_score(cert: dict[str, Any] | None) -> tuple[float, str]:
    if not cert:
        return 0.0, "Certificate was unavailable, so signature readiness could not be established."
    sig = (cert.get("signature_algorithm") or "").lower()
    key_alg = (cert.get("public_key") or {}).get("algorithm", "")
    if "sha1" in sig or "md5" in sig:
        return 0.0, "Deprecated signature hash observed."
    if "ml-dsa" in sig or "dilithium" in sig:
        return 10.0, "PQC signature algorithm observed."
    if key_alg == "ECDSA/ECDH":
        return 7.0, "ECDSA certificate is modern classical cryptography, not PQC."
    if key_alg == "RSA":
        return 4.0, "RSA/SHA-2 certificate is classical and quantum-vulnerable in the long term."
    return 5.0, "Classical certificate signature dependency observed."


def _key_exchange_score(tls: dict[str, Any]) -> tuple[float, str]:
    negotiated = tls.get("negotiated") or {}
    cipher_name = ((negotiated.get("cipher") or {}).get("name") or "").upper()
    protocol = negotiated.get("protocol")
    if "MLKEM" in cipher_name or "KYBER" in cipher_name or "HYBRID" in cipher_name:
        return 10.0, "Hybrid/PQC key exchange marker observed in negotiated cipher metadata."
    if protocol == "TLSv1.3" or "ECDHE" in cipher_name:
        return 3.0, "ECDHE/TLS 1.3 is a migration prerequisite but remains classical."
    if "DHE" in cipher_name:
        return 1.5, "Classical finite-field Diffie-Hellman dependency observed."
    return 0.0, "RSA or non-ephemeral classical key exchange dependency observed or key exchange unavailable."


def assess_pqc(tls: dict[str, Any], context: dict[str, Any] | None = None) -> dict[str, Any]:
    context = context or {}
    weights = CONFIG["weights"]
    protocols = tls.get("protocols") or {}
    cert = tls.get("certificate")
    key_score, key_reason = _key_exchange_score(tls)
    tls13_supported = bool(protocols.get("TLS 1.3", {}).get("supported"))
    tls13_score = 8.0 if tls13_supported else 2.0
    sig_score, sig_reason = _signature_score(cert)
    migration_year = int(CONFIG["nist_migration_year"])
    current_year = datetime.now(timezone.utc).year
    years_remaining = max(0, migration_year - current_year)
    sensitivity = str(context.get("data_sensitivity", "moderate")).lower()
    hndl_penalty = 2.0 if sensitivity in {"high", "critical"} else 0.0
    window_score = max(0.0, min(10.0, years_remaining - hndl_penalty))
    dimensions = {
        "key_exchange": {"score": key_score, "reasoning": key_reason},
        "tls13_adoption": {"score": tls13_score, "reasoning": "TLS 1.3 is present." if tls13_supported else "TLS 1.3 was not confirmed."},
        "certificate_signature": {"score": sig_score, "reasoning": sig_reason},
        "quantum_risk_window": {
            "score": round(window_score, 2),
            "reasoning": f"{years_remaining} years remain until the {migration_year} migration target; harvest-now-decrypt-later sensitivity is {sensitivity}.",
        },
    }
    score = sum(dimensions[name]["score"] * weights[name] for name in weights)
    return {
        "score": round(score, 2),
        "classification": _classification(score),
        "dimensions": dimensions,
        "weights": weights,
        "nist_migration_year": migration_year,
        "years_until_2035": years_remaining,
        "status": "classical" if score < 8.5 else "hybrid-ready-or-better",
        "pqc_observed": key_score == 10.0 or sig_score == 10.0,
        "recommendations": [
            "Maintain TLS 1.3 support as a prerequisite for hybrid key exchange.",
            "Inventory RSA and classical ECDH dependencies across certificates and edge services.",
            "Track browser, CDN, CA, and load-balancer support for hybrid ML-KEM and PQC signatures.",
            "Prioritize high-sensitivity and long-retention data flows for quantum migration planning.",
        ],
    }


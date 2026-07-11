from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

from app.core.config import settings
from app.utils.findings import make_finding
from app.utils.target_validator import ValidatedTarget


TLS_VERSIONS = [
    ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


def _connect(host: str, port: int, context: ssl.SSLContext) -> ssl.SSLSocket:
    raw_sock = socket.create_connection((host, port), timeout=settings.scan_timeout)
    return context.wrap_socket(raw_sock, server_hostname=host)


def _test_version(host: str, port: int, version: ssl.TLSVersion | None) -> dict[str, Any]:
    if version is None:
        return {"supported": False, "status": "not_assessed", "reason": "Runtime does not expose this TLS version."}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = version
    context.maximum_version = version
    try:
        context.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with _connect(host, port, context) as tls:
            cipher = tls.cipher()
            return {
                "supported": True,
                "status": "assessed",
                "negotiated_protocol": tls.version(),
                "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
            }
    except Exception as exc:
        return {"supported": False, "status": "assessed", "reason": exc.__class__.__name__}


def _fetch_certificate(host: str, port: int) -> tuple[bytes | None, dict[str, Any] | None, bool, str | None, dict[str, Any] | None]:
    context = ssl.create_default_context()
    try:
        with _connect(host, port, context) as tls:
            der = tls.getpeercert(binary_form=True)
            dict_cert = tls.getpeercert()
            cipher = tls.cipher()
            negotiated = {"protocol": tls.version(), "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None}
            return der, dict_cert, True, None, negotiated
    except Exception as verified_exc:
        fallback = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        fallback.check_hostname = False
        fallback.verify_mode = ssl.CERT_NONE
        try:
            with _connect(host, port, fallback) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                negotiated = {"protocol": tls.version(), "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None}
                return der, None, False, verified_exc.__class__.__name__, negotiated
        except Exception as fallback_exc:
            return None, None, False, fallback_exc.__class__.__name__, None


def _name_value(cert: x509.Certificate, oid: NameOID) -> str | None:
    values = cert.subject.get_attributes_for_oid(oid)
    return values[0].value if values else None


def _public_key_metadata(cert: x509.Certificate) -> dict[str, Any]:
    key = cert.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return {"algorithm": "RSA", "size": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        return {"algorithm": "ECDSA/ECDH", "size": key.key_size, "curve": key.curve.name}
    if isinstance(key, dsa.DSAPublicKey):
        return {"algorithm": "DSA", "size": key.key_size}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return {"algorithm": "Ed25519", "size": 256}
    if isinstance(key, ed448.Ed448PublicKey):
        return {"algorithm": "Ed448", "size": 448}
    return {"algorithm": key.__class__.__name__, "size": None}


def _parse_certificate(der: bytes, host: str, dict_cert: dict[str, Any] | None, trusted: bool, trust_error: str | None) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    not_after = getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc))
    not_before = getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc))
    key = _public_key_metadata(cert)
    hostname_match = None
    hostname_error = None
    if dict_cert:
        try:
            ssl.match_hostname(dict_cert, host)
            hostname_match = True
        except Exception as exc:
            hostname_match = False
            hostname_error = exc.__class__.__name__
    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()
    return {
        "issuer": issuer,
        "subject": subject,
        "common_name": _name_value(cert, NameOID.COMMON_NAME),
        "serial_number": hex(cert.serial_number),
        "valid_not_before": not_before.isoformat(),
        "valid_not_after": not_after.isoformat(),
        "days_until_expiry": (not_after - now).days,
        "expired": now > not_after,
        "signature_algorithm": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else cert.signature_algorithm_oid._name,
        "public_key": key,
        "hostname_match": hostname_match,
        "hostname_error": hostname_error,
        "trust_status": "trusted" if trusted else "untrusted_or_not_verified",
        "trust_error": trust_error,
        "self_signed": issuer == subject,
        "classical_crypto_dependency": key.get("algorithm") in {"RSA", "DSA", "ECDSA/ECDH"},
    }


def _cipher_is_forward_secret(cipher_name: str | None, protocol: str | None) -> bool:
    if protocol == "TLSv1.3":
        return True
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return "ECDHE" in upper or upper.startswith("DHE-") or "-DHE-" in upper


def _cipher_is_weak(cipher_name: str | None) -> bool:
    if not cipher_name:
        return False
    upper = cipher_name.upper()
    return any(marker in upper for marker in ["RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "ADH"])


def _build_tls_findings(protocols: dict[str, Any], cert: dict[str, Any] | None, negotiated: dict[str, Any] | None) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for version in ["TLS 1.0", "TLS 1.1"]:
        if protocols.get(version, {}).get("supported"):
            findings.append(
                make_finding(
                    "deprecated_tls",
                    f"Deprecated {version} is supported",
                    "TLS and cryptography",
                    "The server negotiated a deprecated TLS protocol version during deterministic probing.",
                    {"protocol": version, "probe": protocols[version]},
                    "high",
                    "Disable TLS 1.0 and TLS 1.1. Require TLS 1.2 or TLS 1.3 with modern AEAD cipher suites.",
                    "TLS protocol configuration",
                    7.2,
                )
            )
    cipher = (negotiated or {}).get("cipher") or {}
    cipher_name = cipher.get("name")
    protocol = (negotiated or {}).get("protocol")
    if _cipher_is_weak(cipher_name):
        findings.append(
            make_finding(
                "weak_tls_cipher",
                "Weak TLS cipher negotiated",
                "TLS and cryptography",
                "The negotiated cipher contains a deprecated primitive such as RC4, DES, EXPORT, NULL, MD5, or anonymous DH.",
                {"cipher": cipher, "protocol": protocol},
                "high",
                "Remove weak cipher suites and prefer TLS 1.3 or TLS 1.2 AEAD suites with ECDHE.",
                "TLS cipher configuration",
                7.4,
            )
        )
    if cipher_name and not _cipher_is_forward_secret(cipher_name, protocol):
        findings.append(
            make_finding(
                "non_forward_secret_cipher",
                "Negotiated cipher lacks forward secrecy",
                "TLS and cryptography",
                "The selected TLS cipher does not show ephemeral ECDHE/DHE key exchange.",
                {"cipher": cipher, "protocol": protocol},
                "medium",
                "Prefer ECDHE suites for TLS 1.2 and TLS 1.3-only configurations where possible.",
                "TLS key exchange",
                6.4,
            )
        )
    if cert:
        if cert["expired"]:
            findings.append(
                make_finding("expired_certificate", "Certificate is expired", "Certificate intelligence", "The X.509 certificate validity window has elapsed.", cert, "critical", "Renew and deploy a trusted certificate.", "TLS certificate", 9.0)
            )
        elif cert["days_until_expiry"] <= 30:
            findings.append(
                make_finding("certificate_expiring_soon", "Certificate expires soon", "Certificate intelligence", "The certificate is within 30 days of expiration.", {"days_until_expiry": cert["days_until_expiry"]}, "medium", "Renew the certificate before expiry.", "TLS certificate", 5.0)
            )
        if cert["hostname_match"] is False:
            findings.append(
                make_finding("hostname_mismatch", "Certificate hostname mismatch", "Certificate intelligence", "The certificate identity does not match the target hostname.", {"hostname_error": cert["hostname_error"], "subject": cert["subject"]}, "high", "Deploy a certificate containing the target hostname in SAN/CN.", "TLS certificate", 8.0)
            )
        if cert["trust_status"] != "trusted":
            findings.append(
                make_finding("untrusted_certificate", "Certificate trust could not be verified", "Certificate intelligence", "The default trust store could not validate the certificate chain.", {"trust_error": cert["trust_error"], "issuer": cert["issuer"]}, "high", "Use a certificate chaining to a trusted public root CA.", "TLS certificate chain", 7.8)
            )
        if cert["self_signed"]:
            findings.append(
                make_finding("self_signed_certificate", "Self-signed certificate detected", "Certificate intelligence", "The certificate issuer and subject are identical.", {"issuer": cert["issuer"], "subject": cert["subject"]}, "high", "Use a publicly trusted CA certificate for public web endpoints.", "TLS certificate", 7.5)
            )
        sig = (cert.get("signature_algorithm") or "").lower()
        if "sha1" in sig or sig == "md5":
            findings.append(
                make_finding("sha1_certificate_signature", "Deprecated certificate signature algorithm", "Certificate intelligence", "The certificate uses a deprecated signature hash.", {"signature_algorithm": cert["signature_algorithm"]}, "high", "Reissue the certificate using SHA-256 or stronger.", "TLS certificate", 7.0)
            )
        key = cert.get("public_key", {})
        if key.get("algorithm") == "RSA" and (key.get("size") or 0) < 2048:
            findings.append(
                make_finding("rsa_key_below_2048", "RSA key below 2048 bits", "Certificate intelligence", "The certificate public key is below the recommended minimum size.", {"public_key": key}, "high", "Reissue with RSA-2048 or stronger, or ECDSA where appropriate.", "TLS certificate key", 7.0)
            )
        if cert.get("classical_crypto_dependency"):
            findings.append(
                make_finding(
                    "classical_crypto_dependency",
                    "Classical certificate cryptography dependency",
                    "PQC readiness",
                    "The certificate uses classical public-key cryptography. This is normal today, but it is a PQC migration dependency.",
                    {"public_key": key, "signature_algorithm": cert.get("signature_algorithm")},
                    "low",
                    "Plan hybrid/PQC migration as ecosystem support matures; do not treat TLS 1.3 alone as PQC adoption.",
                    "TLS certificate and key exchange",
                    3.5,
                )
            )
    return findings


def inspect_tls(target: ValidatedTarget) -> dict[str, Any]:
    if target.scheme != "https":
        return {
            "assessed": False,
            "reason": "TLS was not assessed because the normalized target uses HTTP.",
            "findings": [],
            "protocols": {},
            "certificate": None,
            "negotiated": None,
        }
    protocols = {label: _test_version(target.host, target.port, version) for label, version in TLS_VERSIONS}
    der, dict_cert, trusted, trust_error, negotiated = _fetch_certificate(target.host, target.port)
    cert = _parse_certificate(der, target.host, dict_cert, trusted, trust_error) if der else None
    findings = _build_tls_findings(protocols, cert, negotiated)
    return {
        "assessed": True,
        "protocols": protocols,
        "certificate": cert,
        "negotiated": negotiated,
        "findings": findings,
        "not_assessed": [] if der else [{"check": "certificate", "reason": trust_error or "certificate unavailable"}],
    }


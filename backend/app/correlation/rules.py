from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationRule:
    source_types: tuple[str, ...]
    target_types: tuple[str, ...]
    relationship: str
    narrative: str


RULES = [
    CorrelationRule(
        ("deprecated_tls", "weak_tls_cipher", "non_forward_secret_cipher"),
        ("missing_hsts",),
        "downgrade amplification",
        "Weak or deprecated transport settings amplify missing HSTS because browsers have less protection against downgrade paths.",
    ),
    CorrelationRule(
        ("missing_hsts",),
        ("insecure_cookie_flags",),
        "session-token exposure amplification",
        "Missing HSTS increases the value of missing Secure cookie flags by making downgraded transport paths more plausible.",
    ),
    CorrelationRule(
        ("missing_csp",),
        ("insecure_cookie_flags",),
        "client-side compromise amplification",
        "Missing CSP can amplify missing HttpOnly cookie protection because successful script injection can target readable session tokens.",
    ),
    CorrelationRule(
        ("missing_csp",),
        ("missing_x_frame_options",),
        "browser-control weakness cluster",
        "Missing script and framing controls indicate a broader lack of browser-side defensive policy.",
    ),
    CorrelationRule(
        ("sha1_certificate_signature", "rsa_key_below_2048", "expired_certificate", "untrusted_certificate"),
        ("missing_hsts",),
        "cryptographic trust erosion",
        "Certificate weaknesses become more consequential when transport enforcement is also absent.",
    ),
]


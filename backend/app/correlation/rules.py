from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrelationRule:
    source_types: tuple[str, ...]
    target_types: tuple[str, ...]
    relationship: str
    narrative: str


RULES = [
    # --- Original rules ---
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

    # --- New rules: CORS chains ---
    CorrelationRule(
        ("cors_misconfiguration", "cors_origin_reflection", "cors_wildcard"),
        ("insecure_cookie_flags",),
        "cross-origin session theft amplification",
        "CORS misconfigurations combined with insecure cookie flags create a viable cross-origin session hijacking attack path.",
    ),
    CorrelationRule(
        ("missing_csp",),
        ("cors_misconfiguration", "cors_origin_reflection"),
        "injection-to-exfiltration chain",
        "Missing CSP allows script injection, and permissive CORS enables the injected script to exfiltrate data to attacker-controlled origins.",
    ),

    # --- New rules: HTTPS redirect chains ---
    CorrelationRule(
        ("no_https_redirect",),
        ("missing_hsts",),
        "cleartext exposure amplification",
        "Without HTTPS redirect or HSTS, users are fully exposed to traffic interception on initial connection.",
    ),
    CorrelationRule(
        ("no_https_redirect",),
        ("insecure_cookie_flags",),
        "credential interception chain",
        "HTTP traffic without HTTPS redirect combined with missing Secure cookie flags allows session tokens to be transmitted in cleartext.",
    ),

    # --- New rules: Information disclosure chains ---
    CorrelationRule(
        ("server_info_disclosure", "technology_disclosure"),
        ("deprecated_tls", "weak_tls_cipher"),
        "targeted exploitation chain",
        "Server/technology version disclosure combined with known TLS weaknesses enables attackers to select version-specific exploits.",
    ),

    # --- New rules: Network exposure chains ---
    CorrelationRule(
        ("database_port_exposed", "critical_port_exposed"),
        ("missing_hsts", "no_https_redirect"),
        "network-to-application attack escalation",
        "Exposed database/critical ports combined with weak transport security create multiple attack vectors from network-level to application-level compromise.",
    ),

    # --- New rules: DNS chains ---
    CorrelationRule(
        ("missing_spf", "permissive_spf", "missing_dmarc"),
        ("missing_csp",),
        "phishing amplification chain",
        "Weak email authentication combined with missing CSP amplifies phishing attack effectiveness — attackers can spoof emails and the target site lacks script injection defenses.",
    ),

    # --- New rules: HTTP method chains ---
    CorrelationRule(
        ("trace_method_enabled",),
        ("insecure_cookie_flags",),
        "cross-site tracing attack chain",
        "TRACE method enabled with insecure cookie flags allows attackers to steal HttpOnly cookies via XST attacks.",
    ),
]

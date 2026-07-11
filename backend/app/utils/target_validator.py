from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse


class TargetValidationError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedTarget:
    original_url: str
    normalized_url: str
    scheme: str
    host: str
    port: int
    resolved_ips: list[str]


BLOCKED_HOSTS = {
    "localhost",
    "metadata.google.internal",
    "169.254.169.254",
    "100.100.100.200",
    "metadata",
}


def _normalize(raw_url: str) -> str:
    value = (raw_url or "").strip()
    if not value:
        raise TargetValidationError("Target URL is required.")
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise TargetValidationError("Only http and https targets are supported.")
    if not parsed.hostname:
        raise TargetValidationError("Target host is missing.")
    if parsed.username or parsed.password:
        raise TargetValidationError("URLs with embedded credentials are not allowed.")
    netloc = parsed.hostname.lower()
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, parsed.params, parsed.query, ""))


def _is_public_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return True


def validate_target(raw_url: str) -> ValidatedTarget:
    normalized = _normalize(raw_url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    host_lower = host.lower().rstrip(".")
    if host_lower in BLOCKED_HOSTS or host_lower.endswith(".local"):
        raise TargetValidationError("Local, metadata, and private targets are blocked for SSRF protection.")
    try:
        direct_ip = ipaddress.ip_address(host_lower)
        if not _is_public_ip(str(direct_ip)):
            raise TargetValidationError("Private, loopback, link-local, and reserved IP targets are blocked.")
        ips = [str(direct_ip)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host_lower, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise TargetValidationError(f"DNS resolution failed for {host_lower}.") from exc
        ips = sorted({info[4][0] for info in infos})
        if not ips:
            raise TargetValidationError("No DNS records were resolved for the target.")
        blocked = [ip for ip in ips if not _is_public_ip(ip)]
        if blocked:
            raise TargetValidationError("Target resolves to private or restricted network addresses.")
    return ValidatedTarget(
        original_url=raw_url,
        normalized_url=normalized,
        scheme=parsed.scheme,
        host=host_lower,
        port=parsed.port or (443 if parsed.scheme == "https" else 80),
        resolved_ips=ips,
    )


def validate_redirect(current_url: str, location: str) -> ValidatedTarget:
    return validate_target(urljoin(current_url, location))


"""TCP port scanner – performs real connect scans against the top-20 service ports."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from app.utils.findings import make_finding
from app.utils.target_validator import ValidatedTarget

logger = logging.getLogger(__name__)

# ── port table ──────────────────────────────────────────────────────────────
#   port → (service_name, description, severity_hint)

PORTS: dict[int, tuple[str, str, str]] = {
    21:    ("FTP",        "File transfer",           "high"),
    22:    ("SSH",        "Remote access",           "info"),
    23:    ("Telnet",     "Unencrypted remote access","critical"),
    25:    ("SMTP",       "Mail server",             "medium"),
    53:    ("DNS",        "Domain name service",     "medium"),
    80:    ("HTTP",       "Web server",              "info"),
    110:   ("POP3",       "Email retrieval",         "medium"),
    143:   ("IMAP",       "Email access",            "medium"),
    443:   ("HTTPS",      "Secure web server",       "info"),
    445:   ("SMB",        "File sharing",            "high"),
    993:   ("IMAPS",      "Secure email",            "info"),
    995:   ("POP3S",      "Secure email",            "info"),
    1433:  ("MSSQL",      "Database",                "high"),
    3306:  ("MySQL",      "Database",                "high"),
    3389:  ("RDP",        "Remote desktop",          "high"),
    5432:  ("PostgreSQL", "Database",                "high"),
    6379:  ("Redis",      "Cache/database",          "critical"),
    8080:  ("HTTP-Alt",   "Alternate web server",    "low"),
    8443:  ("HTTPS-Alt",  "Alternate secure web",    "info"),
    27017: ("MongoDB",    "Database",                "critical"),
}

# Classification groups
CRITICAL_PORTS = {23, 6379, 27017}
DATABASE_PORTS = {1433, 3306, 5432}
DANGEROUS_PORTS = {21, 445, 3389}
MAIL_PORTS = {25, 110, 143}
EXPECTED_PORTS = {80, 443, 8080, 8443}

CONNECT_TIMEOUT = 1.5   # seconds
BANNER_TIMEOUT = 1.0    # seconds
CATEGORY = "Network exposure"


# ── single-port probe ──────────────────────────────────────────────────────

async def _probe_port(
    host: str,
    port: int,
) -> dict[str, Any] | None:
    """Try to connect to *host:port*. Return a result dict or ``None``."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=CONNECT_TIMEOUT,
        )
    except (asyncio.TimeoutError, OSError):
        return None

    banner = ""
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=BANNER_TIMEOUT)
        banner = data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass

    service, description, _ = PORTS[port]
    result: dict[str, Any] = {
        "port": port,
        "service": service,
        "description": description,
        "state": "open",
    }
    if banner:
        result["banner"] = banner
    return result


# ── finding builders ────────────────────────────────────────────────────────

def _build_critical_finding(
    host: str, ports: list[dict[str, Any]],
) -> dict[str, Any]:
    port_labels = [f"{p['port']}/{p['service']}" for p in ports]
    return make_finding(
        finding_type="critical_port_exposed",
        title="Critical service port(s) exposed to the internet",
        category=CATEGORY,
        description=(
            f"The following critical-risk ports are reachable on {host}: "
            f"{', '.join(port_labels)}. These services are high-value targets "
            "for attackers and should never be exposed directly."
        ),
        evidence={
            "host": host,
            "open_ports": [
                {k: v for k, v in p.items()} for p in ports
            ],
        },
        severity="critical",
        remediation=(
            "Block these ports at the firewall/security-group level. If the "
            "service is required, restrict access to trusted IPs or place it "
            "behind a VPN."
        ),
        affected_component=host,
        base_score=9.2,
        metadata={"cwe": "CWE-284"},
    )


def _build_database_finding(
    host: str, ports: list[dict[str, Any]],
) -> dict[str, Any]:
    port_labels = [f"{p['port']}/{p['service']}" for p in ports]
    return make_finding(
        finding_type="database_port_exposed",
        title="Database port(s) exposed to the internet",
        category=CATEGORY,
        description=(
            f"Database ports are reachable on {host}: "
            f"{', '.join(port_labels)}. Direct database exposure allows "
            "brute-force attacks and potential data exfiltration."
        ),
        evidence={
            "host": host,
            "open_ports": [{k: v for k, v in p.items()} for p in ports],
        },
        severity="high",
        remediation=(
            "Restrict database access to application servers only. Use "
            "firewall rules, VPC peering, or SSH tunnels instead of public "
            "exposure."
        ),
        affected_component=host,
        base_score=8.0,
        metadata={"cwe": "CWE-284"},
    )


def _build_dangerous_finding(
    host: str, ports: list[dict[str, Any]],
) -> dict[str, Any]:
    port_labels = [f"{p['port']}/{p['service']}" for p in ports]
    return make_finding(
        finding_type="dangerous_service_exposed",
        title="Dangerous service port(s) exposed to the internet",
        category=CATEGORY,
        description=(
            f"Dangerous service ports are reachable on {host}: "
            f"{', '.join(port_labels)}. These services carry known security "
            "risks when publicly accessible."
        ),
        evidence={
            "host": host,
            "open_ports": [{k: v for k, v in p.items()} for p in ports],
        },
        severity="high",
        remediation=(
            "Disable unnecessary services. For required services, restrict "
            "access via firewall rules and use encrypted alternatives where "
            "available (e.g., SFTP instead of FTP)."
        ),
        affected_component=host,
        base_score=7.5,
        metadata={"cwe": "CWE-284"},
    )


def _build_mail_finding(
    host: str, ports: list[dict[str, Any]],
) -> dict[str, Any]:
    port_labels = [f"{p['port']}/{p['service']}" for p in ports]
    return make_finding(
        finding_type="mail_service_exposed",
        title="Mail service port(s) exposed to the internet",
        category=CATEGORY,
        description=(
            f"Mail-related ports are reachable on {host}: "
            f"{', '.join(port_labels)}. Open mail ports may allow spam relay "
            "or credential harvesting if not properly secured."
        ),
        evidence={
            "host": host,
            "open_ports": [{k: v for k, v in p.items()} for p in ports],
        },
        severity="medium",
        remediation=(
            "Ensure mail services require authentication. Consider using "
            "secure variants (IMAPS/POP3S) and restrict SMTP relay to "
            "authorized senders."
        ),
        affected_component=host,
        base_score=5.0,
        metadata={"cwe": "CWE-200"},
    )


# ── main entry point ───────────────────────────────────────────────────────

async def inspect_ports(target: ValidatedTarget) -> dict[str, Any]:
    """Scan the top-20 TCP ports on *target* and return structured results."""
    host = target.host
    target_port = target.port  # the port the user's site runs on — skip it

    # Launch all probes in parallel
    tasks = {
        port: asyncio.ensure_future(_probe_port(host, port))
        for port in PORTS
    }
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    open_ports: list[dict[str, Any]] = []
    for port, result in zip(tasks.keys(), results):
        if isinstance(result, Exception):
            logger.debug("Probe %s:%d raised %s", host, port, result)
            continue
        if result is not None:
            open_ports.append(result)

    # Classify open ports into finding groups (skip expected & target port)
    critical: list[dict[str, Any]] = []
    database: list[dict[str, Any]] = []
    dangerous: list[dict[str, Any]] = []
    mail: list[dict[str, Any]] = []

    for entry in open_ports:
        p = entry["port"]
        if p == target_port or p in EXPECTED_PORTS:
            continue
        if p in CRITICAL_PORTS:
            critical.append(entry)
        elif p in DATABASE_PORTS:
            database.append(entry)
        elif p in DANGEROUS_PORTS:
            dangerous.append(entry)
        elif p in MAIL_PORTS:
            mail.append(entry)

    # Build grouped findings
    findings: list[dict[str, Any]] = []
    if critical:
        findings.append(_build_critical_finding(host, critical))
    if database:
        findings.append(_build_database_finding(host, database))
    if dangerous:
        findings.append(_build_dangerous_finding(host, dangerous))
    if mail:
        findings.append(_build_mail_finding(host, mail))

    scan_summary = {
        "host": host,
        "ports_scanned": len(PORTS),
        "open_count": len(open_ports),
        "finding_count": len(findings),
    }

    return {
        "assessed": True,
        "findings": findings,
        "open_ports": open_ports,
        "scan_summary": scan_summary,
    }

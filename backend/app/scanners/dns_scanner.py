from __future__ import annotations

import asyncio
import logging
from typing import Any

import dns.dnssec
import dns.name
import dns.rdatatype
import dns.resolver

from app.utils.findings import make_finding
from app.utils.target_validator import ValidatedTarget

logger = logging.getLogger(__name__)

_DNS_TIMEOUT = 5.0
_CATEGORY = "DNS security"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_base_domain(hostname: str) -> str:
    """Strip leading sub-domain labels to get the registrable domain.

    Simple heuristic: return the last two labels (e.g. ``www.example.com`` →
    ``example.com``).  For two-part TLDs such as ``co.uk`` this is imperfect,
    but it is good enough for SPF/DMARC lookups in the vast majority of cases.
    """
    parts = hostname.rstrip(".").split(".")
    if len(parts) <= 2:
        return hostname.rstrip(".")
    return ".".join(parts[-2:])


def _query_dns(qname: str, rdtype: str | int) -> dns.resolver.Answer | None:
    """Perform a blocking DNS query with a fixed timeout.

    Returns ``None`` when the name or record type does not exist (NXDOMAIN /
    NoAnswer / NoNameservers).  Any other exception propagates.
    """
    resolver = dns.resolver.Resolver()
    resolver.lifetime = _DNS_TIMEOUT
    resolver.timeout = _DNS_TIMEOUT
    try:
        return resolver.resolve(qname, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_spf(domain: str, findings: list[dict], dns_records: dict, observations: list[str]) -> None:
    """Query TXT records for an SPF policy and evaluate its ``all`` mechanism."""
    answer = _query_dns(domain, "TXT")
    spf_records: list[str] = []
    if answer:
        for rdata in answer:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=spf1"):
                spf_records.append(txt)

    dns_records["spf"] = spf_records

    if not spf_records:
        findings.append(
            make_finding(
                finding_type="missing_spf",
                title="Missing SPF record",
                category=_CATEGORY,
                description=(
                    "No SPF (Sender Policy Framework) TXT record was found for "
                    f"the domain {domain}. Without SPF, any server can send "
                    "email on behalf of this domain, increasing spoofing risk."
                ),
                evidence={"domain": domain, "spf_records": []},
                severity="medium",
                remediation=(
                    "Publish an SPF TXT record (e.g. "
                    '"v=spf1 include:_spf.google.com -all") to restrict '
                    "which servers may send mail for this domain."
                ),
                affected_component=f"DNS TXT @ {domain}",
                base_score=5.8,
                metadata={"cwe": "CWE-290"},
            )
        )
        observations.append(f"No SPF record found for {domain}.")
        return

    observations.append(f"SPF record(s) found for {domain}: {spf_records}")

    for spf in spf_records:
        spf_lower = spf.lower()
        if "+all" in spf_lower:
            findings.append(
                make_finding(
                    finding_type="permissive_spf",
                    title="Overly permissive SPF record (+all)",
                    category=_CATEGORY,
                    description=(
                        "The SPF record uses the '+all' mechanism, which "
                        "explicitly authorises every host to send mail for "
                        f"{domain}.  This effectively disables SPF."
                    ),
                    evidence={"domain": domain, "spf_record": spf},
                    severity="high",
                    remediation=(
                        "Replace '+all' with '-all' (hard fail) to restrict "
                        "email sending to authorised hosts only."
                    ),
                    affected_component=f"DNS TXT @ {domain}",
                    base_score=7.5,
                    metadata={"cwe": "CWE-290"},
                )
            )
        elif "~all" in spf_lower:
            findings.append(
                make_finding(
                    finding_type="weak_spf",
                    title="SPF record uses soft-fail (~all)",
                    category=_CATEGORY,
                    description=(
                        "The SPF record uses '~all' (soft fail) instead of "
                        "'-all' (hard fail).  Receiving servers may still "
                        "accept spoofed messages."
                    ),
                    evidence={"domain": domain, "spf_record": spf},
                    severity="medium",
                    remediation=(
                        "Tighten the SPF policy to '-all' once all "
                        "legitimate sending sources are included."
                    ),
                    affected_component=f"DNS TXT @ {domain}",
                    base_score=5.0,
                    metadata={"cwe": "CWE-290"},
                )
            )


def _check_dmarc(domain: str, findings: list[dict], dns_records: dict, observations: list[str]) -> None:
    """Query the ``_dmarc`` sub-domain for a DMARC policy."""
    dmarc_domain = f"_dmarc.{domain}"
    answer = _query_dns(dmarc_domain, "TXT")
    dmarc_records: list[str] = []
    if answer:
        for rdata in answer:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.lower().startswith("v=dmarc1"):
                dmarc_records.append(txt)

    dns_records["dmarc"] = dmarc_records

    if not dmarc_records:
        findings.append(
            make_finding(
                finding_type="missing_dmarc",
                title="Missing DMARC record",
                category=_CATEGORY,
                description=(
                    f"No DMARC record was found at {dmarc_domain}. "
                    "Without DMARC, domain owners have no visibility into "
                    "or control over email authentication failures."
                ),
                evidence={"domain": domain, "dmarc_domain": dmarc_domain, "dmarc_records": []},
                severity="medium",
                remediation=(
                    'Publish a DMARC TXT record (e.g. "v=DMARC1; p=reject; '
                    'rua=mailto:dmarc@example.com") at _dmarc.<domain>.'
                ),
                affected_component=f"DNS TXT @ {dmarc_domain}",
                base_score=5.5,
                metadata={"cwe": "CWE-290"},
            )
        )
        observations.append(f"No DMARC record found at {dmarc_domain}.")
        return

    observations.append(f"DMARC record(s) found at {dmarc_domain}: {dmarc_records}")

    for dmarc in dmarc_records:
        dmarc_lower = dmarc.lower()
        # Parse the p= tag
        for part in dmarc_lower.replace(";", " ").split():
            if part.startswith("p="):
                policy = part.split("=", 1)[1].strip()
                if policy == "none":
                    findings.append(
                        make_finding(
                            finding_type="dmarc_policy_none",
                            title="DMARC policy set to none",
                            category=_CATEGORY,
                            description=(
                                "The DMARC policy is 'p=none', meaning no "
                                "action is taken on messages that fail "
                                "authentication.  This provides monitoring "
                                "only, not protection."
                            ),
                            evidence={"domain": domain, "dmarc_record": dmarc, "policy": policy},
                            severity="medium",
                            remediation=(
                                "After reviewing DMARC aggregate reports, "
                                "upgrade the policy to 'p=quarantine' or "
                                "'p=reject'."
                            ),
                            affected_component=f"DNS TXT @ {dmarc_domain}",
                            base_score=5.0,
                            metadata={"cwe": "CWE-290"},
                        )
                    )
                break


def _check_caa(domain: str, findings: list[dict], dns_records: dict, observations: list[str]) -> None:
    """Query for CAA records that restrict certificate issuance."""
    answer = _query_dns(domain, "CAA")
    caa_records: list[str] = []
    if answer:
        for rdata in answer:
            caa_records.append(rdata.to_text())

    dns_records["caa"] = caa_records

    if not caa_records:
        findings.append(
            make_finding(
                finding_type="missing_caa",
                title="Missing CAA record",
                category=_CATEGORY,
                description=(
                    f"No CAA (Certificate Authority Authorization) record was "
                    f"found for {domain}.  Any publicly trusted CA may issue "
                    "certificates for this domain."
                ),
                evidence={"domain": domain, "caa_records": []},
                severity="low",
                remediation=(
                    "Publish CAA records to restrict which CAs are "
                    'permitted to issue certificates (e.g. \'0 issue "letsencrypt.org"\').'
                ),
                affected_component=f"DNS CAA @ {domain}",
                base_score=2.5,
                metadata={"cwe": "CWE-295"},
            )
        )
        observations.append(f"No CAA records found for {domain}.")
    else:
        observations.append(f"CAA records found for {domain}: {caa_records}")


def _check_dnssec(domain: str, findings: list[dict], dns_records: dict, observations: list[str]) -> None:
    """Check whether DNSSEC is enabled by looking for RRSIG records."""
    dnssec_enabled = False
    rrsig_data: list[str] = []

    try:
        answer = _query_dns(domain, "RRSIG")
        if answer:
            dnssec_enabled = True
            rrsig_data = [rdata.to_text() for rdata in answer]
    except Exception:
        pass

    # Fallback: try querying DNSKEY at the domain
    if not dnssec_enabled:
        try:
            answer = _query_dns(domain, "DNSKEY")
            if answer:
                dnssec_enabled = True
                rrsig_data = [rdata.to_text() for rdata in answer]
        except Exception:
            pass

    dns_records["dnssec"] = {
        "enabled": dnssec_enabled,
        "rrsig_records": rrsig_data,
    }

    if not dnssec_enabled:
        findings.append(
            make_finding(
                finding_type="dnssec_not_enabled",
                title="DNSSEC not enabled",
                category=_CATEGORY,
                description=(
                    f"No DNSSEC signatures (RRSIG/DNSKEY) were detected for "
                    f"{domain}.  Without DNSSEC, DNS responses can be spoofed "
                    "by on-path attackers."
                ),
                evidence={"domain": domain, "rrsig_records": [], "dnskey_found": False},
                severity="info",
                remediation=(
                    "Enable DNSSEC signing for the zone and publish DS "
                    "records with the parent registrar."
                ),
                affected_component=f"DNS zone @ {domain}",
                base_score=1.5,
                metadata={"cwe": "CWE-350"},
            )
        )
        observations.append(f"DNSSEC does not appear to be enabled for {domain}.")
    else:
        observations.append(f"DNSSEC signatures detected for {domain}.")


# ---------------------------------------------------------------------------
# Blocking orchestrator – run inside asyncio.to_thread()
# ---------------------------------------------------------------------------

def _run_all_checks(domain: str) -> dict[str, Any]:
    """Execute every DNS check sequentially (called from a thread)."""
    findings: list[dict[str, Any]] = []
    dns_records: dict[str, Any] = {}
    observations: list[str] = []

    _check_spf(domain, findings, dns_records, observations)
    _check_dmarc(domain, findings, dns_records, observations)
    _check_caa(domain, findings, dns_records, observations)
    _check_dnssec(domain, findings, dns_records, observations)

    return {
        "assessed": True,
        "findings": findings,
        "dns_records": dns_records,
        "observations": observations,
    }


# ---------------------------------------------------------------------------
# Public async entry point
# ---------------------------------------------------------------------------

async def inspect_dns(target: ValidatedTarget) -> dict[str, Any]:
    """Perform a comprehensive DNS security assessment for *target*.

    All blocking ``dnspython`` calls are offloaded to a worker thread via
    :func:`asyncio.to_thread` so the event-loop is never blocked.
    """
    domain = _extract_base_domain(target.host)
    logger.info("Starting DNS security scan for %s (base domain: %s)", target.host, domain)

    try:
        result = await asyncio.to_thread(_run_all_checks, domain)
    except Exception as exc:
        logger.exception("DNS scan failed for %s", domain)
        return {
            "assessed": False,
            "error": f"DNS scan failed: {exc}",
            "findings": [],
            "dns_records": {},
            "observations": [],
        }

    logger.info(
        "DNS scan complete for %s — %d finding(s)",
        domain,
        len(result["findings"]),
    )
    return result

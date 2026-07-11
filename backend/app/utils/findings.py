from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_from_score(score: float) -> str:
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def make_finding(
    finding_type: str,
    title: str,
    category: str,
    description: str,
    evidence: dict[str, Any],
    severity: str,
    remediation: str,
    affected_component: str,
    base_score: float,
    deterministic_status: str = "assessed",
    source: str = "live-scan",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "finding_id": f"F-{uuid.uuid4().hex[:10]}",
        "finding_type": finding_type,
        "title": title,
        "category": category,
        "description": description,
        "evidence": evidence,
        "severity": severity,
        "base_score": round(float(base_score), 2),
        "deterministic_status": deterministic_status,
        "remediation": remediation,
        "affected_component": affected_component,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "metadata": metadata or {},
    }


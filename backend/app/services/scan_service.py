from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

from app.ai.service import interpret
from app.compliance.mapper import map_findings, summarize_mappings
from app.correlation.engine import discover_attack_paths
from app.core.storage import storage
from app.pqc.engine import assess_pqc
from app.reports.generator import generate_reports
from app.scanners.http_scanner import inspect_http
from app.scanners.tls_scanner import inspect_tls
from app.scoring.risk import score_contextual_risk
from app.utils.target_validator import TargetValidationError, validate_target


def _score_posture(risk_score: float, findings: list[dict[str, Any]], attack_paths: list[dict[str, Any]], pqc_score: float) -> int:
    severity_penalty = {"critical": 12, "high": 8, "medium": 4, "low": 1, "info": 0}
    penalty = risk_score * 5 + sum(severity_penalty.get(f.get("severity", "info"), 0) for f in findings) + len(attack_paths) * 4 + max(0, 7 - pqc_score) * 2
    return max(0, min(100, round(100 - penalty)))


async def run_scan(user_id: str, target_url: str, context: dict[str, Any] | None, authorization_confirmed: bool) -> dict[str, Any]:
    if not authorization_confirmed:
        raise TargetValidationError("Authorization confirmation is required before scanning.")
    started = time.perf_counter()
    target = validate_target(target_url)
    tls_task = asyncio.to_thread(inspect_tls, target)
    http_task = inspect_http(target)
    tls, http = await asyncio.gather(tls_task, http_task)
    findings = list(tls.get("findings", [])) + list(http.get("findings", []))
    correlation = discover_attack_paths(findings)
    compliance = map_findings(findings)
    risk = score_contextual_risk(findings, correlation["attack_paths"], context or {})
    pqc = assess_pqc(tls, context or {})
    ai_payload = {
        "findings": findings,
        "attack_paths": correlation["attack_paths"],
        "risk_scores": risk,
        "compliance_mappings": compliance,
        "pqc_readiness": pqc,
    }
    ai = await interpret(ai_payload)
    scan = {
        "user_id": user_id,
        "target": target_url,
        "normalized_target": target.normalized_url,
        "scan_mode": "LIVE SCAN",
        "status": "completed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "context": context or {},
        "findings": findings,
        "attack_paths": correlation["attack_paths"],
        "attack_graph": correlation["graph"],
        "risk_assessment": risk,
        "compliance_mappings": compliance,
        "compliance_summary": summarize_mappings(compliance),
        "pqc_readiness": pqc,
        "tls": tls,
        "http": http,
        "ai_interpretation": ai,
        "data_mode_notice": "LIVE SCAN. Results are derived from deterministic observations collected from the authorized target.",
        "execution_time_ms": round((time.perf_counter() - started) * 1000),
    }
    scan["intellisec_score"] = _score_posture(risk["final_score"], findings, correlation["attack_paths"], pqc["score"])
    scan["reports"] = generate_reports(scan)
    return storage.add_scan(scan)


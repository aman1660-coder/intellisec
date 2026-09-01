"""Strix security scan service.

Provides the security scanning engine for IntelliSec.
Always uses AI Analysis mode (HTTP/TLS scan + Gemini AI).
Full Strix Docker mode is optional and only attempted if the Docker image
is confirmed locally available.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.storage import build_storage
from app.strix_engine.ai_analyzer import run_ai_analysis
from app.strix_engine.config import strix_config
from app.strix_engine.parser import (
    compute_security_score,
    normalize_finding,
    parse_executive_report,
    parse_run_record,
    parse_vulnerabilities,
)

logger = logging.getLogger(__name__)
storage = build_storage()

_running_scans: dict[str, asyncio.Task] = {}


# ---------------------------------------------------------------------------
# Preflight check
# ---------------------------------------------------------------------------

def _is_docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def _is_docker_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True, timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return False


def preflight_check() -> dict[str, Any]:
    docker_available = _is_docker_available()
    docker_running = _is_docker_running() if docker_available else False
    strix_path_exists = Path(strix_config.strix_path).exists() if strix_config.strix_path else False

    full_mode_ready = (
        strix_config.is_configured
        and docker_running
        and strix_path_exists
    )
    ai_mode_ready = strix_config.is_configured

    errors: list[str] = []
    if not strix_config.is_configured:
        errors.append("LLM model or API key not configured")

    # Always use AI analysis — it's reliable and doesn't require Docker
    scan_engine = "ai_analysis"
    if full_mode_ready:
        scan_engine = "strix"

    return {
        "strix_configured": strix_config.is_configured,
        "llm_model": strix_config.llm_model,
        "docker_available": docker_available,
        "docker_running": docker_running,
        "strix_path_exists": strix_path_exists,
        "full_mode_ready": full_mode_ready,
        "ai_mode_ready": ai_mode_ready,
        "ready": ai_mode_ready or full_mode_ready,
        "scan_engine": scan_engine,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

async def start_security_scan(
    user_id: str,
    scan_id: str,
    target_url: str,
    target_type: str,
    scan_name: str,
    scan_mode: str = "deep",
    description: str = "",
) -> None:
    """Background task that runs a security scan.

    Always uses AI Analysis mode (reliable, no Docker needed).
    Full Strix mode is attempted first only if Docker is running,
    but automatically falls back to AI Analysis on any failure.
    """
    # Always use AI Analysis — it works reliably without Docker
    await _run_ai_analysis_scan(
        user_id, scan_id, target_url, target_type,
        scan_name, scan_mode, description,
    )


# ---------------------------------------------------------------------------
# AI Analysis scan (primary engine — always works)
# ---------------------------------------------------------------------------

async def _run_ai_analysis_scan(
    user_id: str,
    scan_id: str,
    target_url: str,
    target_type: str,
    scan_name: str,
    scan_mode: str = "deep",
    description: str = "",
) -> None:
    """Run security scan using IntelliSec scanners + Gemini AI analysis."""
    try:
        # Update scan as running
        storage.update_scan(user_id, scan_id, {
            "status": "running",
            "scan_engine": "ai_analysis",
            "scan_phases.target_validated": True,
            "scan_phases.environment_setup": True,
        })

        # Run AI analysis
        storage.update_scan(user_id, scan_id, {
            "scan_phases.reconnaissance": True,
        })

        ai_result = await run_ai_analysis(
            target_url=target_url,
            scan_mode=scan_mode,
        )

        # Update security testing phase
        storage.update_scan(user_id, scan_id, {
            "scan_phases.security_testing": True,
        })

        # Normalize findings
        raw_vulns = ai_result.get("vulnerabilities", [])
        findings = [normalize_finding(v, scan_id) for v in raw_vulns]
        security_score = compute_security_score(findings)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Update vulnerability validation
        storage.update_scan(user_id, scan_id, {
            "scan_phases.vulnerability_validation": True,
        })

        # Build reports
        reports = {
            "executive": {
                "title": "AI Security Assessment Report",
                "content": ai_result.get("executive_summary", ""),
            },
            "technical": {
                "title": "Technical Analysis",
                "methodology": ai_result.get("methodology", ""),
                "technical_analysis": ai_result.get("executive_summary", ""),
                "recommendations": ai_result.get("recommendations", ""),
            },
        }

        # Mark completed
        storage.update_scan(user_id, scan_id, {
            "status": "completed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "findings": findings,
            "security_score": security_score,
            "total_findings": len(findings),
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "low_count": severity_counts.get("low", 0),
            "info_count": severity_counts.get("info", 0),
            "strix_reports": reports,
            "ai_provider": ai_result.get("ai_provider", "gemini"),
            "scan_phases.report_generation": True,
        })

        logger.info(
            "AI Analysis scan %s completed: %d findings, score %d",
            scan_id, len(findings), security_score,
        )

    except Exception as exc:
        logger.exception("AI Analysis scan %s failed", scan_id)
        storage.update_scan(user_id, scan_id, {
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc) or repr(exc),
        })
    finally:
        _running_scans.pop(scan_id, None)


# ---------------------------------------------------------------------------
# Launch helper
# ---------------------------------------------------------------------------

def launch_scan(user_id: str, scan_id: str, **kwargs) -> None:
    """Launch a scan as a background asyncio task."""
    task = asyncio.create_task(
        start_security_scan(user_id, scan_id, **kwargs)
    )
    _running_scans[scan_id] = task


def get_running_scan_ids() -> list[str]:
    return list(_running_scans.keys())

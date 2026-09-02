"""Strix security scan service.

Provides the security scanning engine for IntelliSec.
Two modes:
  1. Full Strix (Docker) — autonomous AI pentesting in a Kali sandbox
  2. AI Analysis (fallback) — HTTP/TLS scan + Gemini AI analysis
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import sys
import traceback
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


def _is_strix_image_available() -> bool:
    """Check if the Strix sandbox Docker image exists locally."""
    image = strix_config.docker_image
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def preflight_check() -> dict[str, Any]:
    docker_available = _is_docker_available()
    docker_running = _is_docker_running() if docker_available else False
    strix_path_exists = Path(strix_config.strix_path).exists() if strix_config.strix_path else False
    image_available = _is_strix_image_available() if docker_running else False

    full_mode_ready = (
        strix_config.is_configured
        and docker_running
        and strix_path_exists
        and image_available
    )
    ai_mode_ready = strix_config.is_configured

    errors: list[str] = []
    if not strix_config.is_configured:
        errors.append("LLM model or API key not configured")

    scan_engine = "ai_analysis"
    if full_mode_ready:
        scan_engine = "strix"

    return {
        "strix_configured": strix_config.is_configured,
        "llm_model": strix_config.llm_model,
        "docker_available": docker_available,
        "docker_running": docker_running,
        "strix_path_exists": strix_path_exists,
        "strix_image_available": image_available,
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

    Uses full Strix Docker mode if available, otherwise falls back to
    AI Analysis mode. If full Strix fails, automatically retries with
    AI Analysis.
    """
    strix_path_exists = Path(strix_config.strix_path).exists() if strix_config.strix_path else False
    use_full_strix = (
        strix_config.is_configured
        and _is_docker_running()
        and strix_path_exists
        and _is_strix_image_available()
    )

    if use_full_strix:
        try:
            await _run_full_strix_scan(
                user_id, scan_id, target_url, target_type,
                scan_name, scan_mode, description,
            )
            return  # Success
        except Exception as exc:
            logger.warning(
                "Full Strix scan %s failed (%s), falling back to AI Analysis",
                scan_id, exc,
            )
            # Reset scan for fallback
            storage.update_scan(user_id, scan_id, {
                "status": "running",
                "scan_engine": "ai_analysis",
                "error": None,
            })

    # Fallback: AI Analysis mode
    await _run_ai_analysis_scan(
        user_id, scan_id, target_url, target_type,
        scan_name, scan_mode, description,
    )


# ---------------------------------------------------------------------------
# Full Strix scan (Docker-based autonomous pentesting)
# ---------------------------------------------------------------------------

def _find_strix_python() -> str:
    """Find the Python executable that can run Strix."""
    strix_venv = Path(strix_config.strix_path) / ".venv"
    if strix_venv.exists():
        python = strix_venv / "Scripts" / "python.exe"  # Windows
        if python.exists():
            return str(python)
        python = strix_venv / "bin" / "python"  # Linux/Mac
        if python.exists():
            return str(python)
    return sys.executable


async def _run_full_strix_scan(
    user_id: str,
    scan_id: str,
    target_url: str,
    target_type: str,
    scan_name: str,
    scan_mode: str = "deep",
    description: str = "",
) -> None:
    """Run full Strix autonomous pentesting via Docker sandbox."""
    strix_run_dir = strix_config.runs_dir / scan_id
    strix_run_dir.mkdir(parents=True, exist_ok=True)

    storage.update_scan(user_id, scan_id, {
        "status": "running",
        "scan_engine": "strix",
        "scan_phases.target_validated": True,
        "scan_phases.environment_setup": True,
    })

    # Build scan config for Strix
    if target_type == "repository":
        targets = [{"type": "repository", "details": {"target_repo": target_url}}]
    else:
        targets = [{"type": "url", "details": {"target_url": target_url}}]

    scan_config = {
        "targets": targets,
        "scan_mode": scan_mode,
        "user_instructions": f"Security assessment of {target_url}. Scan name: {scan_name}. {description}",
        "non_interactive": True,
        "skills": [],
    }

    # Create runner script
    runner_script = strix_run_dir / "_run_strix.py"
    runner_script.write_text(f'''#!/usr/bin/env python3
"""Auto-generated Strix scan runner for {scan_id}."""
import asyncio
import json
import os
import sys
import logging

# Add Strix to path
strix_path = os.environ.get("STRIX_PATH", r"{strix_config.strix_path}")
sys.path.insert(0, strix_path)

os.chdir(r"{strix_run_dir}")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

async def main():
    try:
        from strix.core.runner import run_strix_scan

        scan_config = json.loads({json.dumps(json.dumps(scan_config))})

        result = await run_strix_scan(
            scan_config=scan_config,
            scan_id="{scan_id}",
            image=os.environ.get("STRIX_DOCKER_IMAGE", "{strix_config.docker_image}"),
            max_turns={strix_config.max_turns},
            interactive=False,
        )
        print("STRIX_SCAN_COMPLETED")
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"STRIX_SCAN_ERROR: {{e}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
''', encoding="utf-8")

    storage.update_scan(user_id, scan_id, {
        "scan_phases.reconnaissance": True,
    })

    # Run Strix in its own Python venv
    strix_python = _find_strix_python()
    env = os.environ.copy()
    env["STRIX_PATH"] = strix_config.strix_path
    env["STRIX_LLM"] = strix_config.llm_model
    env["LLM_API_KEY"] = strix_config.llm_api_key
    env["GEMINI_API_KEY"] = strix_config.llm_api_key
    env["STRIX_DOCKER_IMAGE"] = strix_config.docker_image

    logger.info("Starting Strix subprocess: %s %s", strix_python, runner_script)

    process = await asyncio.create_subprocess_exec(
        strix_python, str(runner_script),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(strix_run_dir),
        env=env,
    )

    storage.update_scan(user_id, scan_id, {
        "scan_phases.security_testing": True,
    })

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=strix_config.scan_timeout,
        )
    except asyncio.TimeoutError:
        process.kill()
        raise RuntimeError(f"Strix scan timed out after {strix_config.scan_timeout}s")

    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")

    # Save logs
    (strix_run_dir / "stdout.log").write_text(stdout_text, encoding="utf-8")
    (strix_run_dir / "stderr.log").write_text(stderr_text, encoding="utf-8")

    if process.returncode != 0:
        raise RuntimeError(
            f"Strix process exited with code {process.returncode}: "
            f"{stderr_text[:500] or stdout_text[:500]}"
        )

    storage.update_scan(user_id, scan_id, {
        "scan_phases.vulnerability_validation": True,
    })

    # Parse Strix output
    run_record = parse_run_record(strix_run_dir)
    vulnerabilities = parse_vulnerabilities(strix_run_dir)
    executive_report = parse_executive_report(strix_run_dir)

    findings = [normalize_finding(v, scan_id) for v in vulnerabilities]
    security_score = compute_security_score(findings)

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    reports = {}
    if executive_report:
        reports["executive"] = {
            "title": "Executive Security Report",
            "content": executive_report,
        }
    if run_record and run_record.get("scan_results"):
        sr = run_record["scan_results"]
        reports["technical"] = {
            "title": "Technical Analysis Report",
            "methodology": sr.get("methodology", ""),
            "technical_analysis": sr.get("technical_analysis", ""),
            "recommendations": sr.get("recommendations", ""),
        }

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
        "strix_run_record": run_record,
        "report_path": str(strix_run_dir),
        "ai_provider": "strix",
        "scan_phases.report_generation": True,
    })

    logger.info("Strix scan %s completed: %d findings, score %d", scan_id, len(findings), security_score)


# ---------------------------------------------------------------------------
# AI Analysis scan (fallback — always works without Docker)
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
        storage.update_scan(user_id, scan_id, {
            "status": "running",
            "scan_engine": "ai_analysis",
            "scan_phases.target_validated": True,
            "scan_phases.environment_setup": True,
        })

        storage.update_scan(user_id, scan_id, {
            "scan_phases.reconnaissance": True,
        })

        ai_result = await run_ai_analysis(
            target_url=target_url,
            scan_mode=scan_mode,
        )

        storage.update_scan(user_id, scan_id, {
            "scan_phases.security_testing": True,
        })

        raw_vulns = ai_result.get("vulnerabilities", [])
        findings = [normalize_finding(v, scan_id) for v in raw_vulns]
        security_score = compute_security_score(findings)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        storage.update_scan(user_id, scan_id, {
            "scan_phases.vulnerability_validation": True,
        })

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

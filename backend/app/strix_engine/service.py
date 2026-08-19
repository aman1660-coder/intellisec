from __future__ import annotations
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.storage import storage
from app.strix_engine.config import strix_config
from app.strix_engine.parser import (
    compute_security_score,
    normalize_finding,
    parse_executive_report,
    parse_run_record,
    parse_vulnerabilities,
)

logger = logging.getLogger(__name__)

# Track running scan tasks
_running_scans: dict[str, asyncio.Task] = {}


def preflight_check() -> dict[str, Any]:
    """Check if Strix and Docker are properly configured."""
    docker_available = False
    docker_running = False

    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=10
        )
        docker_available = True
        docker_running = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    strix_path_exists = Path(strix_config.strix_path).exists() if strix_config.strix_path else False
    full_mode_ready = strix_config.is_configured and docker_running and strix_path_exists

    # AI Analysis mode works with just an API key (no Docker needed)
    from app.core.config import settings
    ai_mode_ready = bool(settings.ai_api_key)

    checks = {
        "strix_configured": strix_config.is_configured,
        "llm_model": strix_config.llm_model or "Not configured",
        "docker_available": docker_available,
        "docker_running": docker_running,
        "strix_path_exists": strix_path_exists,
        "full_mode_ready": full_mode_ready,
        "ai_mode_ready": ai_mode_ready,
        "ready": full_mode_ready or ai_mode_ready,
        "scan_engine": "strix" if full_mode_ready else ("ai_analysis" if ai_mode_ready else "none"),
        "errors": [],
    }

    if not checks["ready"]:
        if not ai_mode_ready:
            checks["errors"].append("AI_API_KEY environment variable must be set for AI security scanning.")
        if not docker_running:
            checks["errors"].append("Docker not available. Using AI Analysis mode instead of full Strix engine.")

    return checks


def _is_docker_available() -> bool:
    """Quick check if Docker is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


async def start_security_scan(
    user_id: str,
    scan_id: str,
    target_url: str,
    target_type: str,
    scan_name: str,
    scan_mode: str = "deep",
    description: str = "",
) -> None:
    """Background task that runs a security scan and updates the database.

    Automatically chooses the best available engine:
    1. Full Strix engine (if Docker + Strix source available)
    2. AI Analysis mode (if Gemini API key available, no Docker needed)
    """
    strix_path_exists = Path(strix_config.strix_path).exists() if strix_config.strix_path else False
    use_full_strix = (
        strix_config.is_configured
        and _is_docker_available()
        and strix_path_exists
    )

    if use_full_strix:
        await _run_full_strix_scan(
            user_id, scan_id, target_url, target_type,
            scan_name, scan_mode, description,
        )
    else:
        await _run_ai_analysis_scan(
            user_id, scan_id, target_url, target_type,
            scan_name, scan_mode, description,
        )


async def _run_ai_analysis_scan(
    user_id: str,
    scan_id: str,
    target_url: str,
    target_type: str,
    scan_name: str,
    scan_mode: str = "deep",
    description: str = "",
) -> None:
    """Run AI-powered security analysis without Docker."""
    try:
        # Phase 1: Target validation
        storage.update_scan(user_id, scan_id, {
            "status": "running",
            "scan_engine": "ai_analysis",
            "scan_phases": {
                "target_validated": True,
                "environment_setup": True,
                "reconnaissance": False,
                "security_testing": False,
                "vulnerability_validation": False,
                "report_generation": False,
            }
        })

        # Phase 2: Reconnaissance (real HTTP/TLS scanning)
        storage.update_scan(user_id, scan_id, {
            "scan_phases.reconnaissance": True,
        })

        # Phase 3: AI Security Analysis
        from app.strix_engine.ai_analyzer import run_ai_analysis

        storage.update_scan(user_id, scan_id, {
            "scan_phases.security_testing": True,
        })

        ai_result = await run_ai_analysis(target_url, scan_mode)

        # Phase 4: Normalize findings
        storage.update_scan(user_id, scan_id, {
            "scan_phases.vulnerability_validation": True,
        })

        vulnerabilities = ai_result.get("vulnerabilities", [])
        findings = [normalize_finding(v, scan_id) for v in vulnerabilities]
        security_score = compute_security_score(findings)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build reports
        reports = {}
        exec_summary = ai_result.get("executive_summary", "")
        if exec_summary:
            reports["executive"] = {
                "title": "AI Security Assessment Report",
                "content": exec_summary,
            }
        reports["technical"] = {
            "title": "Technical Analysis",
            "methodology": ai_result.get("methodology", ""),
            "technical_analysis": exec_summary,
            "recommendations": ai_result.get("recommendations", ""),
        }

        # Phase 5: Complete
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
            "error": str(exc),
        })
    finally:
        _running_scans.pop(scan_id, None)


async def _run_full_strix_scan(
    user_id: str,
    scan_id: str,
    target_url: str,
    target_type: str,
    scan_name: str,
    scan_mode: str = "deep",
    description: str = "",
) -> None:
    """Run full Strix scan with Docker sandbox."""
    run_dir = strix_config.runs_dir / scan_id
    run_dir.mkdir(parents=True, exist_ok=True)

    try:
        # Update status to RUNNING
        storage.update_scan(user_id, scan_id, {
            "status": "running",
            "scan_engine": "strix",
            "scan_phases": {
                "target_validated": True,
                "environment_setup": True,
                "reconnaissance": False,
                "security_testing": False,
                "vulnerability_validation": False,
                "report_generation": False,
            }
        })

        # Build scan configuration
        targets = []
        if target_type == "web_application":
            targets.append({"type": "url", "details": {"url": target_url}})
        elif target_type == "repository":
            targets.append({"type": "repository", "details": {"target_repo": target_url}})
        else:
            targets.append({"type": "url", "details": {"url": target_url}})

        scan_config = {
            "targets": targets,
            "scan_mode": scan_mode,
            "user_instructions": f"Security assessment of {target_url}. Scan name: {scan_name}. {description}",
            "non_interactive": True,
            "skills": [],
        }

        # Set environment for Strix
        env = os.environ.copy()
        env["STRIX_LLM"] = strix_config.llm_model
        env["LLM_API_KEY"] = strix_config.llm_api_key
        env["STRIX_PATH"] = strix_config.strix_path
        # LiteLLM uses provider-specific key names for routing
        if strix_config.llm_model.startswith("gemini/"):
            env["GEMINI_API_KEY"] = strix_config.llm_api_key
        elif strix_config.llm_model.startswith("anthropic/") or "claude" in strix_config.llm_model:
            env["ANTHROPIC_API_KEY"] = strix_config.llm_api_key
        else:
            env["OPENAI_API_KEY"] = strix_config.llm_api_key

        # Run Strix as a subprocess to avoid dependency conflicts
        strix_script = _create_strix_runner_script(scan_config, scan_id, str(run_dir))
        script_path = run_dir / "_run_strix.py"
        script_path.write_text(strix_script, encoding="utf-8")

        # Update phase: reconnaissance
        storage.update_scan(user_id, scan_id, {
            "scan_phases.reconnaissance": True,
        })

        # Execute Strix scan as subprocess
        strix_python = _find_strix_python()
        process = await asyncio.create_subprocess_exec(
            strix_python, str(script_path),
            env=env,
            cwd=str(strix_config.runs_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Wait with timeout
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=strix_config.scan_timeout,
            )
            logger.info("Strix scan %s completed with code %d", scan_id, process.returncode)
            if stderr:
                logger.warning("Strix stderr: %s", stderr.decode(errors='replace')[:2000])
        except asyncio.TimeoutError:
            process.kill()
            raise TimeoutError(f"Scan timed out after {strix_config.scan_timeout} seconds")

        # Update phases
        storage.update_scan(user_id, scan_id, {
            "scan_phases.security_testing": True,
            "scan_phases.vulnerability_validation": True,
        })

        # Parse results
        strix_run_dir = run_dir
        actual_run_dir = strix_config.runs_dir / "strix_runs" / scan_id
        if actual_run_dir.exists():
            strix_run_dir = actual_run_dir

        vulnerabilities = parse_vulnerabilities(strix_run_dir)
        run_record = parse_run_record(strix_run_dir)
        executive_report = parse_executive_report(strix_run_dir)

        # Normalize findings
        findings = [normalize_finding(v, scan_id) for v in vulnerabilities]
        security_score = compute_security_score(findings)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Build reports
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

        # Update scan as completed
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
            "scan_phases.report_generation": True,
        })

        logger.info("Scan %s completed: %d findings, score %d", scan_id, len(findings), security_score)

    except Exception as exc:
        logger.exception("Strix scan %s failed", scan_id)
        storage.update_scan(user_id, scan_id, {
            "status": "failed",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "error": str(exc),
        })
    finally:
        _running_scans.pop(scan_id, None)


def launch_scan(user_id: str, scan_id: str, **kwargs) -> None:
    """Launch a scan as a background asyncio task."""
    task = asyncio.create_task(
        start_security_scan(user_id, scan_id, **kwargs)
    )
    _running_scans[scan_id] = task


def get_running_scan_ids() -> list[str]:
    return list(_running_scans.keys())


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


def _create_strix_runner_script(scan_config: dict, scan_id: str, run_dir: str) -> str:
    """Create a Python script that runs a Strix scan."""
    config_json = json.dumps(scan_config)
    return f'''#!/usr/bin/env python3
"""Auto-generated Strix scan runner for {scan_id}."""
import asyncio
import json
import os
import sys

# Add Strix to path
strix_path = os.environ.get("STRIX_PATH", r"{strix_config.strix_path}")
sys.path.insert(0, strix_path)

os.chdir(r"{run_dir}")

async def main():
    try:
        from strix.core.runner import run_strix_scan
        from strix.config import load_settings

        scan_config = json.loads({repr(config_json)})

        result = await run_strix_scan(
            scan_config=scan_config,
            scan_id="{scan_id}",
            image=os.environ.get("STRIX_DOCKER_IMAGE", "ghcr.io/strix-labs/strix-sandbox:latest"),
            max_turns={strix_config.max_turns},
            interactive=False,
            cleanup_on_exit=True,
        )
        print("STRIX_SCAN_COMPLETED")
    except Exception as e:
        print(f"STRIX_SCAN_ERROR: {{e}}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
'''

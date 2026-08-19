"""AI-powered security analysis engine.

This module provides AI security scanning that works WITHOUT Docker.
It uses IntelliSec's existing HTTP/TLS scanners to gather real data,
then sends it to Gemini AI for deep penetration-testing-style analysis.

Used as a fallback when Docker is not available (e.g., Render, Vercel),
and as the primary engine for cloud deployments.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)

# Gemini API endpoint
_GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}"

_SECURITY_ANALYSIS_PROMPT = """You are an expert penetration tester and application security engineer conducting a security assessment.

You have been given real scan data from a target. Analyze it like a professional pentest and identify ALL security vulnerabilities.

RULES:
- Only report vulnerabilities supported by evidence in the provided scan data
- Do NOT invent findings that aren't supported by the data
- Assign accurate CVSS 3.1 scores
- Provide actionable remediation steps
- Classify severity as: critical, high, medium, low, or info

For each vulnerability found, provide this EXACT JSON structure:
{
  "id": "VULN-0001",
  "title": "Short descriptive title",
  "severity": "critical|high|medium|low|info",
  "cvss": 7.5,
  "description": "What the vulnerability is",
  "impact": "What an attacker could do",
  "technical_analysis": "Detailed technical explanation with evidence from the scan data",
  "evidence": "Specific evidence from the scan that proves this vulnerability",
  "remediation_steps": "Step-by-step fix instructions",
  "cwe": "CWE-XXX",
  "endpoint": "affected URL or component",
  "finding_class": "vulnerability category"
}

Return a JSON object with this structure:
{
  "vulnerabilities": [ ...list of vulnerability objects... ],
  "executive_summary": "2-3 paragraph executive summary of the security posture",
  "methodology": "Brief description of analysis methodology",
  "recommendations": "Top 5 prioritized security recommendations"
}

SCAN DATA:
"""


async def run_ai_analysis(
    target_url: str,
    scan_mode: str = "deep",
) -> dict[str, Any]:
    """Run AI-powered security analysis using existing scanners + Gemini.

    1. Gather real data via IntelliSec's HTTP and TLS scanners
    2. Send to Gemini for AI penetration testing analysis
    3. Return structured vulnerability findings
    """
    from app.scanners.http_scanner import inspect_http
    from app.scanners.tls_scanner import inspect_tls
    from app.utils.target_validator import validate_target

    # Phase 1: Validate and scan target
    target = validate_target(target_url)

    # Phase 2: Gather real data from target
    import asyncio
    tls_data = await asyncio.to_thread(inspect_tls, target)
    http_data = await inspect_http(target)

    # Combine scan data for AI analysis
    scan_payload = {
        "target": target_url,
        "scan_mode": scan_mode,
        "tls": _sanitize_for_prompt(tls_data),
        "http": _sanitize_for_prompt(http_data),
        "deterministic_findings": (
            list(tls_data.get("findings", []))
            + list(http_data.get("findings", []))
        ),
    }

    # Phase 3: Send to Gemini for AI analysis
    api_key = settings.ai_api_key
    model = settings.ai_model or "gemini-2.5-flash"

    if not api_key:
        # No API key — return deterministic findings only
        return _deterministic_only_result(scan_payload, target_url)

    prompt_text = _SECURITY_ANALYSIS_PROMPT + json.dumps(scan_payload, indent=2, default=str)

    url = _GEMINI_URL.format(model=model, key=api_key)

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                url,
                json={
                    "contents": [{"parts": [{"text": prompt_text}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "topP": 0.8,
                        "maxOutputTokens": 8192,
                    },
                },
            )
            response.raise_for_status()
            raw_text = response.json()["candidates"][0]["content"]["parts"][0]["text"]

            # Parse the AI response — handle markdown code fences
            cleaned = raw_text.strip()
            if cleaned.startswith("```"):
                # Remove ```json ... ``` wrapper
                lines = cleaned.split("\n")
                cleaned = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

            try:
                ai_result = json.loads(cleaned)
            except json.JSONDecodeError:
                logger.warning("AI response was not valid JSON, wrapping as text")
                ai_result = {
                    "vulnerabilities": [],
                    "executive_summary": raw_text,
                    "methodology": "AI analysis via Gemini",
                    "recommendations": "See executive summary",
                }

    except Exception as exc:
        logger.exception("Gemini AI analysis failed: %s", exc)
        return _deterministic_only_result(scan_payload, target_url)

    # Phase 4: Merge AI findings with deterministic findings
    vulnerabilities = ai_result.get("vulnerabilities", [])

    # Assign IDs if missing
    for i, vuln in enumerate(vulnerabilities):
        if not vuln.get("id"):
            vuln["id"] = f"AI-VULN-{i + 1:04d}"

    return {
        "vulnerabilities": vulnerabilities,
        "executive_summary": ai_result.get("executive_summary", ""),
        "methodology": ai_result.get("methodology", "AI-powered analysis using Gemini"),
        "recommendations": ai_result.get("recommendations", ""),
        "tls_data": tls_data,
        "http_data": http_data,
        "deterministic_findings": scan_payload["deterministic_findings"],
        "ai_provider": "gemini",
    }


def _sanitize_for_prompt(data: dict) -> dict:
    """Remove overly large or binary fields to keep prompt within token limits."""
    sanitized = {}
    for key, value in data.items():
        if key in ("raw_response_body", "raw_certificate_der"):
            continue
        if isinstance(value, str) and len(value) > 3000:
            sanitized[key] = value[:3000] + "... [truncated]"
        elif isinstance(value, bytes):
            continue
        else:
            sanitized[key] = value
    return sanitized


def _deterministic_only_result(scan_payload: dict, target_url: str) -> dict[str, Any]:
    """Return only deterministic findings when AI is not available."""
    findings = scan_payload.get("deterministic_findings", [])
    return {
        "vulnerabilities": [
            {
                "id": f.get("finding_id", f"DET-{i}"),
                "title": f.get("title", "Unknown"),
                "severity": f.get("severity", "info"),
                "description": f.get("description", ""),
                "evidence": f.get("evidence", ""),
                "remediation_steps": f.get("remediation", ""),
                "cvss": f.get("base_score", 0),
                "endpoint": target_url,
                "finding_class": f.get("category", "deterministic"),
            }
            for i, f in enumerate(findings)
        ],
        "executive_summary": f"Deterministic scan found {len(findings)} issues. AI analysis unavailable (no API key configured).",
        "methodology": "Deterministic HTTP header and TLS analysis only",
        "recommendations": "Configure AI_API_KEY for deeper AI-powered analysis.",
        "ai_provider": "none",
    }

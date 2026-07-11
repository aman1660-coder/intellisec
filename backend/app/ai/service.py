from __future__ import annotations

import json
from typing import Any

import httpx

from app.core.config import settings


def fallback_interpretation(payload: dict[str, Any]) -> dict[str, Any]:
    findings = payload.get("findings", [])
    attack_paths = payload.get("attack_paths", [])
    pqc = payload.get("pqc_readiness", {})
    critical = [f for f in findings if f.get("severity") == "critical"]
    high = [f for f in findings if f.get("severity") == "high"]
    top_path = attack_paths[0] if attack_paths else None
    return {
        "provider": "deterministic-fallback",
        "available": False,
        "executive_summary": (
            f"IntelliSec found {len(findings)} deterministic findings, including {len(critical)} critical and {len(high)} high findings. "
            f"{'The leading correlated path is ' + top_path.get('technical_narrative', '') + '.' if top_path else 'No multi-finding attack path was constructed from the current observations.'} "
            f"PQC readiness is {pqc.get('score', 'not assessed')}/10 ({pqc.get('classification', 'not assessed')})."
        ),
        "developer_guidance": [f.get("remediation") for f in findings[:6]],
        "compliance_summary": "Compliance mappings are technical indicators only and do not constitute legal certification.",
        "pqc_guidance": pqc.get("recommendations", []),
        "constraints": "Generated without an AI API key or after provider failure. It uses only deterministic IntelliSec outputs.",
    }


async def interpret(payload: dict[str, Any]) -> dict[str, Any]:
    if not settings.ai_api_key:
        return fallback_interpretation(payload)
    if settings.ai_provider.lower() != "gemini":
        fallback = fallback_interpretation(payload)
        fallback["constraints"] = f"Configured provider {settings.ai_provider} is not implemented; fallback used."
        return fallback
    prompt = {
        "instruction": (
            "Use only the supplied JSON. Do not invent findings, compliance violations, exploitation, or benchmark claims. "
            "Return concise JSON with executive_summary, developer_guidance, compliance_summary, and pqc_guidance."
        ),
        "intellisec_payload": payload,
    }
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.ai_model}:generateContent?key={settings.ai_api_key}"
    try:
        async with httpx.AsyncClient(timeout=12) as client:
            response = await client.post(url, json={"contents": [{"parts": [{"text": json.dumps(prompt)}]}]})
            response.raise_for_status()
            text = response.json()["candidates"][0]["content"]["parts"][0]["text"]
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                parsed = {"executive_summary": text}
            parsed["provider"] = "gemini"
            parsed["available"] = True
            return parsed
    except Exception:
        return fallback_interpretation(payload)


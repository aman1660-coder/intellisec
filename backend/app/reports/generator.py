from __future__ import annotations

from copy import deepcopy
from typing import Any


def generate_reports(scan: dict[str, Any]) -> dict[str, Any]:
    findings = scan.get("findings", [])
    attack_paths = scan.get("attack_paths", [])
    compliance = scan.get("compliance_mappings", [])
    pqc = scan.get("pqc_readiness", {})
    top_findings = sorted(findings, key=lambda f: f.get("base_score", 0), reverse=True)[:8]
    developer = {
        "title": "Developer Remediation Report",
        "summary": f"{len(findings)} deterministic findings require review. Prioritize configuration fixes that break attack chains.",
        "items": [
            {
                "finding": f.get("title"),
                "evidence": f.get("evidence"),
                "severity": f.get("severity"),
                "remediation": f.get("remediation"),
                "affected_component": f.get("affected_component"),
            }
            for f in top_findings
        ],
        "attack_paths": attack_paths,
    }
    compliance_report = {
        "title": "Compliance-Oriented Technical Mapping",
        "disclaimer": "Automated mapping assists assessment and is not legal certification.",
        "mapped_controls": compliance,
    }
    executive = {
        "title": "Executive Security Posture Summary",
        "summary": (
            f"Overall IntelliSec score is {scan.get('intellisec_score')}/100. "
            f"Contextual risk is {scan.get('risk_assessment', {}).get('final_score')}/10. "
            f"PQC readiness is {pqc.get('score')}/10 ({pqc.get('classification')})."
        ),
        "major_risks": [path.get("technical_narrative") for path in attack_paths[:3]] or [f.get("title") for f in top_findings[:3]],
        "recommended_actions": [f.get("remediation") for f in top_findings[:5]],
    }
    export_payload = deepcopy({key: value for key, value in scan.items() if key != "reports"})
    return {"developer": developer, "compliance": compliance_report, "executive": executive, "json_export": export_payload}

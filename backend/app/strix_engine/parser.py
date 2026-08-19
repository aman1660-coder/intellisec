import json
from pathlib import Path

def parse_run_record(run_dir: Path) -> dict:
    run_file = run_dir / "run.json"
    if run_file.exists():
        try:
            return json.loads(run_file.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def parse_vulnerabilities(run_dir: Path) -> list[dict]:
    vuln_file = run_dir / "vulnerabilities.json"
    if vuln_file.exists():
        try:
            return json.loads(vuln_file.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []

def parse_executive_report(run_dir: Path) -> str | None:
    report_file = run_dir / "report.md"
    if report_file.exists():
        try:
            return report_file.read_text(encoding="utf-8")
        except Exception:
            return None
    return None

def normalize_finding(strix_vuln: dict, scan_id: str) -> dict:
    severity = strix_vuln.get("severity", "info").lower()
    
    # severity-based default base_score
    default_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
    cvss = strix_vuln.get("cvss")
    base_score = cvss if cvss is not None else default_scores.get(severity, 0.0)

    return {
        "finding_id": strix_vuln.get("id"),
        "title": strix_vuln.get("title"),
        "severity": severity,
        "description": strix_vuln.get("description"),
        "evidence": strix_vuln.get("evidence") or strix_vuln.get("technical_analysis"),
        "remediation": strix_vuln.get("remediation_steps"),
        "category": "AI Security Analysis",
        "affected_component": strix_vuln.get("endpoint") or strix_vuln.get("target"),
        "base_score": base_score,
        "finding_type": strix_vuln.get("finding_class", "dynamic"),
        "deterministic_status": "AI-Validated",
        
        # Strix-specific fields
        "impact": strix_vuln.get("impact"),
        "technical_analysis": strix_vuln.get("technical_analysis"),
        "poc_description": strix_vuln.get("poc_description"),
        "cvss": cvss,
        "cvss_breakdown": strix_vuln.get("cvss_breakdown"),
        "cve": strix_vuln.get("cve"),
        "cwe": strix_vuln.get("cwe"),
        "endpoint": strix_vuln.get("endpoint"),
        "method": strix_vuln.get("method"),
        "source": "strix",
        "scan_id": scan_id
    }

def compute_security_score(findings: list[dict]) -> int:
    severity_penalty = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
    total_penalty = sum(severity_penalty.get(f.get("severity", "info"), 0) for f in findings)
    return max(0, min(100, 100 - total_penalty))

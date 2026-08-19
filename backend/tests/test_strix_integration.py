"""Tests for Strix integration components."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Test the parser
class TestStrixParser:
    def setup_method(self):
        self.tmpdir = Path(tempfile.mkdtemp())
    
    def _write_json(self, filename: str, data: any) -> None:
        (self.tmpdir / filename).write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )
    
    def test_parse_vulnerabilities_empty(self):
        from app.strix_engine.parser import parse_vulnerabilities
        result = parse_vulnerabilities(self.tmpdir)
        assert result == []
    
    def test_parse_vulnerabilities_with_data(self):
        from app.strix_engine.parser import parse_vulnerabilities
        vulns = [
            {
                "id": "vuln-0001",
                "title": "SQL Injection",
                "severity": "critical",
                "description": "SQL injection in login form",
                "cvss": 9.8,
                "endpoint": "/api/login",
                "remediation_steps": "Use parameterized queries",
            }
        ]
        self._write_json("vulnerabilities.json", vulns)
        result = parse_vulnerabilities(self.tmpdir)
        assert len(result) == 1
        assert result[0]["title"] == "SQL Injection"
    
    def test_parse_run_record(self):
        from app.strix_engine.parser import parse_run_record
        record = {
            "run_id": "scan-123",
            "status": "completed",
            "start_time": "2024-01-01T00:00:00Z",
        }
        self._write_json("run.json", record)
        result = parse_run_record(self.tmpdir)
        assert result["status"] == "completed"
    
    def test_parse_run_record_missing(self):
        from app.strix_engine.parser import parse_run_record
        result = parse_run_record(self.tmpdir)
        assert result == {}
    
    def test_parse_executive_report(self):
        from app.strix_engine.parser import parse_executive_report
        (self.tmpdir / "report.md").write_text("# Executive Summary\nTest report", encoding="utf-8")
        result = parse_executive_report(self.tmpdir)
        assert "Executive Summary" in result
    
    def test_parse_executive_report_missing(self):
        from app.strix_engine.parser import parse_executive_report
        result = parse_executive_report(self.tmpdir)
        assert result is None
    
    def test_normalize_finding(self):
        from app.strix_engine.parser import normalize_finding
        strix_vuln = {
            "id": "vuln-0001",
            "title": "XSS Vulnerability",
            "severity": "high",
            "description": "Reflected XSS in search",
            "cvss": 7.5,
            "endpoint": "/search",
            "method": "GET",
            "remediation_steps": "Sanitize input",
            "evidence": "<script>alert(1)</script>",
            "impact": "Session hijacking",
            "cwe": "CWE-79",
        }
        result = normalize_finding(strix_vuln, "scan-123")
        assert result["finding_id"] == "vuln-0001"
        assert result["title"] == "XSS Vulnerability"
        assert result["severity"] == "high"
        assert result["base_score"] == 7.5
        assert result["source"] == "strix"
        assert result["scan_id"] == "scan-123"
        assert result["category"] == "AI Security Analysis"
    
    def test_normalize_finding_default_score(self):
        from app.strix_engine.parser import normalize_finding
        strix_vuln = {
            "id": "vuln-0002",
            "title": "Info Disclosure",
            "severity": "medium",
        }
        result = normalize_finding(strix_vuln, "scan-456")
        assert result["base_score"] == 5.0  # medium default
    
    def test_compute_security_score_no_findings(self):
        from app.strix_engine.parser import compute_security_score
        assert compute_security_score([]) == 100
    
    def test_compute_security_score_with_findings(self):
        from app.strix_engine.parser import compute_security_score
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        score = compute_security_score(findings)
        assert 0 <= score <= 100
        assert score < 100  # Must have penalty
    
    def test_compute_security_score_many_criticals(self):
        from app.strix_engine.parser import compute_security_score
        findings = [{"severity": "critical"} for _ in range(10)]
        score = compute_security_score(findings)
        assert score == 0  # Capped at 0


class TestStrixConfig:
    def test_config_defaults(self):
        from app.strix_engine.config import StrixConfig
        with patch.dict(os.environ, {}, clear=True):
            config = StrixConfig()
            assert config.max_turns == 100
            assert config.scan_timeout == 1800
            assert not config.is_configured
    
    def test_config_is_configured(self):
        from app.strix_engine.config import StrixConfig
        # Frozen dataclass defaults are evaluated at definition time,
        # so we pass values directly rather than using env vars.
        config = StrixConfig(llm_model="gpt-4o", llm_api_key="test-key")
        assert config.is_configured


class TestPreflightCheck:
    def test_preflight_not_configured(self):
        from app.strix_engine.service import preflight_check
        with patch.dict(os.environ, {"STRIX_LLM": "", "LLM_API_KEY": ""}, clear=False):
            # Force reload config
            from app.strix_engine import config as strix_cfg
            original = strix_cfg.strix_config
            strix_cfg.strix_config = strix_cfg.StrixConfig()
            try:
                result = preflight_check()
                assert not result["ready"]
                assert len(result["errors"]) > 0
            finally:
                strix_cfg.strix_config = original

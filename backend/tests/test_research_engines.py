import math

from app.compliance.mapper import map_findings
from app.correlation.engine import chain_amplification, discover_attack_paths
from app.pqc.engine import assess_pqc
from app.scoring.risk import score_contextual_risk
from app.services.case_study import build_case_study_scan
from app.utils.findings import make_finding


def _finding(finding_type, score):
    return make_finding(
        finding_type,
        finding_type,
        "test",
        "test",
        {},
        "medium",
        "fix",
        "component",
        score,
        source="test",
    )


def test_chain_amplification_formula_matches_paper_equation_not_printed_example():
    alpha = chain_amplification(3)
    assert round(alpha, 2) == 1.38
    assert round(3.83 * alpha, 1) == 5.3
    assert not math.isclose(3.83 * alpha, 9.1)


def test_attack_graph_discovers_downgrade_cookie_chain():
    findings = [_finding("deprecated_tls", 6.8), _finding("missing_hsts", 6.5), _finding("insecure_cookie_flags", 6.4)]
    result = discover_attack_paths(findings)
    assert result["graph"]["edges"]
    assert result["attack_paths"][0]["chain_length"] == 3
    assert result["attack_paths"][0]["severity"] == "critical"


def test_five_factor_scoring_and_compliance_mapping():
    findings = [_finding("missing_hsts", 6.5), _finding("insecure_cookie_flags", 6.4)]
    paths = discover_attack_paths(findings)["attack_paths"]
    risk = score_contextual_risk(findings, paths, {"data_sensitivity": "high", "exposure_type": "public", "authentication_status": "none"})
    mappings = map_findings(findings)
    assert risk["final_score"] > 5
    assert any(mapping["framework"] == "GDPR" for mapping in mappings)
    assert all("not legal certification" in mapping["disclaimer"] for mapping in mappings)


def test_pqc_scoring_distinguishes_tls13_from_pqc():
    tls = {
        "protocols": {"TLS 1.3": {"supported": True}},
        "negotiated": {"protocol": "TLSv1.3", "cipher": {"name": "TLS_AES_256_GCM_SHA384"}},
        "certificate": {"public_key": {"algorithm": "RSA", "size": 2048}, "signature_algorithm": "sha256WithRSAEncryption"},
    }
    result = assess_pqc(tls, {"data_sensitivity": "high"})
    assert result["score"] < 8.5
    assert result["pqc_observed"] is False
    assert "TLS 1.3" in result["dimensions"]["tls13_adoption"]["reasoning"]


def test_case_study_output_is_labeled_and_complete():
    scan = build_case_study_scan()
    assert scan["scan_mode"] == "RESEARCH CASE STUDY"
    assert len(scan["findings"]) == 8
    assert len(scan["attack_paths"]) == 2
    assert scan["reports"]["developer"]
    assert scan["pqc_readiness"]["score"] > 0


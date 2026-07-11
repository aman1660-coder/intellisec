from __future__ import annotations

import json
from pathlib import Path
from typing import Any


MAPPING_PATH = Path(__file__).with_name("mappings.json")
DISCLAIMER = "Automated mapping assists technical assessment. It is not legal certification or a formal compliance determination."


def load_mapping_registry() -> dict[str, list[dict[str, Any]]]:
    return json.loads(MAPPING_PATH.read_text(encoding="utf-8"))


def map_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    registry = load_mapping_registry()
    mappings: list[dict[str, Any]] = []
    for finding in findings:
        for entry in registry.get(finding.get("finding_type"), []):
            mappings.append(
                {
                    "mapping_id": f"CM-{finding['finding_id']}-{entry['framework']}-{entry['control']}".replace(" ", "-"),
                    "finding_id": finding["finding_id"],
                    "finding_type": finding.get("finding_type"),
                    "finding_title": finding.get("title"),
                    "framework": entry["framework"],
                    "control": entry["control"],
                    "explanation": entry["explanation"],
                    "remediation": entry["remediation"],
                    "confidence": entry["confidence"],
                    "type": "potential technical alignment issue",
                    "disclaimer": DISCLAIMER,
                }
            )
    return mappings


def summarize_mappings(mappings: list[dict[str, Any]]) -> dict[str, Any]:
    by_framework: dict[str, int] = {}
    for item in mappings:
        by_framework[item["framework"]] = by_framework.get(item["framework"], 0) + 1
    return {
        "total_mappings": len(mappings),
        "by_framework": by_framework,
        "disclaimer": DISCLAIMER,
    }


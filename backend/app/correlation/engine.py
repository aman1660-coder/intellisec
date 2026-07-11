from __future__ import annotations

import math
import uuid
from typing import Any

import networkx as nx

from app.correlation.rules import RULES
from app.utils.findings import severity_from_score


def chain_amplification(length: int) -> float:
    if length < 2:
        return 1.0
    return 1 + 0.35 * math.log(length)


def _node_label(finding: dict[str, Any]) -> str:
    return f"{finding.get('title')} ({finding.get('severity')})"


def build_attack_graph(findings: list[dict[str, Any]]) -> nx.DiGraph:
    graph = nx.DiGraph()
    by_type: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        graph.add_node(finding["finding_id"], **finding, label=_node_label(finding))
        by_type.setdefault(finding.get("finding_type", ""), []).append(finding)
    for rule in RULES:
        sources = [item for source_type in rule.source_types for item in by_type.get(source_type, [])]
        targets = [item for target_type in rule.target_types for item in by_type.get(target_type, [])]
        for source in sources:
            for target in targets:
                if source["finding_id"] != target["finding_id"]:
                    graph.add_edge(
                        source["finding_id"],
                        target["finding_id"],
                        relationship=rule.relationship,
                        narrative=rule.narrative,
                    )
    return graph


def _score_path(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    length = len(nodes)
    mean_base = sum(float(node.get("base_score", 0)) for node in nodes) / max(length, 1)
    alpha = chain_amplification(length)
    # The paper prints alpha(3)=1.38 and mean=3.83, then reports 9.1/10.
    # The equation itself yields 5.3. IntelliSec implements the equation
    # exactly and documents the paper-example discrepancy in the README.
    final = min(10.0, mean_base * alpha)
    return {
        "chain_length": length,
        "mean_base_score": round(mean_base, 2),
        "amplification_factor": round(alpha, 3),
        "final_composite_score": round(final, 2),
        "severity": severity_from_score(final),
    }


def discover_attack_paths(findings: list[dict[str, Any]]) -> dict[str, Any]:
    graph = build_attack_graph(findings)
    candidate_paths: list[list[str]] = []
    for source in graph.nodes:
        if graph.out_degree(source) == 0:
            continue
        sinks = [node for node in graph.nodes if node != source and graph.out_degree(node) == 0]
        for sink in sinks:
            for path in nx.all_simple_paths(graph, source, sink, cutoff=4):
                if len(path) >= 2:
                    candidate_paths.append(path)
    deduped: list[list[str]] = []
    seen = set()
    for path in sorted(candidate_paths, key=lambda p: (-len(p), p)):
        signature = tuple(graph.nodes[node].get("finding_type") for node in path)
        if signature not in seen:
            seen.add(signature)
            deduped.append(path)
    attack_paths: list[dict[str, Any]] = []
    for path in deduped[:12]:
        nodes = [dict(graph.nodes[node]) for node in path]
        edges = []
        for source, target in zip(path, path[1:]):
            edge = dict(graph.edges[source, target])
            edges.append({"source": source, "target": target, **edge})
        score = _score_path(nodes)
        attack_paths.append(
            {
                "chain_id": f"CH-{uuid.uuid4().hex[:8]}",
                "ordered_nodes": [
                    {
                        "finding_id": node["finding_id"],
                        "title": node.get("title"),
                        "finding_type": node.get("finding_type"),
                        "severity": node.get("severity"),
                        "base_score": node.get("base_score"),
                    }
                    for node in nodes
                ],
                "edges": edges,
                **score,
                "technical_narrative": " -> ".join(node.get("title", "Finding") for node in nodes),
                "business_impact": "Correlated findings may increase the practical likelihood or impact of session compromise, data exposure, or policy failure.",
                "remediation_priority": "Address the earliest transport or browser-control weakness first, then harden session-token handling.",
            }
        )
    graph_payload = {
        "nodes": [
            {
                "id": node,
                "label": data.get("title"),
                "type": data.get("finding_type"),
                "severity": data.get("severity"),
                "score": data.get("base_score"),
            }
            for node, data in graph.nodes(data=True)
        ],
        "edges": [{"source": s, "target": t, **data} for s, t, data in graph.edges(data=True)],
    }
    return {"graph": graph_payload, "attack_paths": attack_paths}


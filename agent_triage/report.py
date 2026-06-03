"""Render triage results to Markdown or JSON."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

_PRIORITY_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}


def sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort triaged findings by priority band then by descending score."""
    return sorted(
        findings,
        key=lambda f: (_PRIORITY_ORDER.get(f.get("priority", "P4"), 3), -f.get("score", 0)),
    )


def render_markdown(result: dict[str, Any]) -> str:
    """Produce a human-readable Markdown remediation report."""
    target = result.get("target", "unknown")
    findings = sort_findings(result.get("findings", []))
    counts = {"P1": 0, "P2": 0, "P3": 0, "P4": 0}
    for f in findings:
        counts[f.get("priority", "P4")] = counts.get(f.get("priority", "P4"), 0) + 1

    lines: list[str] = []
    lines.append(f"# Vulnerability Triage Report — {target}")
    lines.append("")
    lines.append(f"_Generated {datetime.now():%Y-%m-%d %H:%M} · {len(findings)} findings_")
    lines.append("")
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"- **P1 (critical):** {counts['P1']}  ·  **P2 (high):** {counts['P2']}  "
        f"·  **P3 (medium):** {counts['P3']}  ·  **P4 (low):** {counts['P4']}"
    )
    if result.get("summary"):
        lines.append("")
        lines.append(result["summary"])
    lines.append("")
    lines.append("## Prioritized Findings")
    lines.append("")

    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. [{f.get('priority')}] {f.get('service', 'Unknown service')} "
                     f"(port {f.get('port', '?')})")
        lines.append("")
        lines.append(f"- **Risk score:** {f.get('score')}/100 — {f.get('sla', '')}")
        if f.get("cve"):
            lines.append(f"- **CVE:** {f.get('cve')}")
        if f.get("summary_cve"):
            lines.append(f"- **Context:** {f.get('summary_cve')}")
        if f.get("impact"):
            lines.append(f"- **Impact:** {f.get('impact')}")
        lines.append(f"- **Remediation:** {f.get('fix') or 'Review and patch the affected service.'}")
        lines.append("")

    lines.append("---")
    lines.append("_Produced by the AI Security Triage Agent. Findings are advisory; "
                 "validate before acting in production._")
    return "\n".join(lines)


def render_json(result: dict[str, Any]) -> str:
    """Produce a machine-readable JSON report."""
    result = dict(result)
    result["findings"] = sort_findings(result.get("findings", []))
    result["generated_at"] = datetime.now().isoformat(timespec="seconds")
    return json.dumps(result, indent=2)

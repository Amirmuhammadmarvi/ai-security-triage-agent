"""
The triage agent.

Two execution paths share the same tools:

* **Live mode** (an OpenAI-compatible key is configured): a genuine agent loop.
  The LLM is given the findings and the tool schemas; it autonomously decides
  to call `lookup_cve` and `score_risk`, receives the results, and writes the
  final remediation report. This is the classic perceive -> decide -> act loop.

* **Demo mode** (`--demo`, or no key present): a deterministic pipeline that
  calls the same tools directly and renders the report from a template, so the
  project is fully runnable offline and easy to review.
"""

from __future__ import annotations

import json
from typing import Any

from .llm import LLMClient
from .tools import TOOL_SCHEMAS, call_tool, lookup_cve, score_risk

SYSTEM_PROMPT = """You are a security triage agent. You are given the findings \
from a vulnerability scan. For every finding you must:
  1. Call lookup_cve when a CVE id is present, to obtain context and a known fix.
  2. Call score_risk to assign a deterministic priority and SLA.
Use the tool results, never invent CVSS scores or fixes. After processing all \
findings, write a concise Markdown remediation report: an executive summary with \
priority counts, then findings ordered from most to least urgent, each with its \
risk score, CVE context, impact, and remediation step."""

MAX_STEPS = 12


class TriageAgent:
    """Coordinates an LLM and a set of tools to triage scan findings."""

    def __init__(self, llm: LLMClient | None = None, verbose: bool = False):
        self.llm = llm or LLMClient()
        self.verbose = verbose

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run(self, scan: dict[str, Any], demo: bool = False) -> dict[str, Any]:
        """Triage a scan. Falls back to demo mode if no LLM key is available."""
        if demo or not self.llm.available:
            if self.verbose and not demo:
                print("[i] No API key found — running deterministic demo pipeline.")
            return self._run_demo(scan)
        return self._run_agent(scan)

    # ------------------------------------------------------------------ #
    # Deterministic pipeline (offline)
    # ------------------------------------------------------------------ #
    def _run_demo(self, scan: dict[str, Any]) -> dict[str, Any]:
        triaged: list[dict[str, Any]] = []
        for finding in scan.get("findings", []):
            cve_info = lookup_cve(finding.get("cve"))
            risk = score_risk(
                finding.get("severity", "info"),
                finding.get("exposure", "internal"),
                bool(finding.get("has_public_exploit", finding.get("cve") in _EXPLOITED)),
            )
            if self.verbose:
                print(f"[tool] lookup_cve({finding.get('cve')}) -> known={cve_info['known']}")
                print(f"[tool] score_risk(...) -> {risk['priority']} ({risk['score']})")
            triaged.append({
                "port": finding.get("port"),
                "service": finding.get("service"),
                "cve": cve_info.get("cve"),
                "summary_cve": cve_info.get("summary"),
                "impact": cve_info.get("impact"),
                "fix": cve_info.get("fix"),
                **risk,
            })
        return {
            "target": scan.get("target", "unknown"),
            "mode": "demo",
            "findings": triaged,
            "summary": _exec_summary(triaged),
        }

    # ------------------------------------------------------------------ #
    # Real agent loop (LLM + tool calling)
    # ------------------------------------------------------------------ #
    def _run_agent(self, scan: dict[str, Any]) -> dict[str, Any]:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Triage these scan findings:\n"
                                        + json.dumps(scan, indent=2)},
        ]

        for step in range(MAX_STEPS):
            response = self.llm.chat(messages, tools=TOOL_SCHEMAS)
            msg = response.choices[0].message

            if not msg.tool_calls:
                # Final answer from the model.
                return {
                    "target": scan.get("target", "unknown"),
                    "mode": "agent",
                    "report_markdown": msg.content,
                    # We still attach structured findings for JSON output.
                    "findings": self._run_demo(scan)["findings"],
                }

            # Record the assistant's tool-call turn, then execute each tool.
            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [tc.model_dump() for tc in msg.tool_calls],
            })
            for tc in msg.tool_calls:
                args = json.loads(tc.function.arguments or "{}")
                if self.verbose:
                    print(f"[step {step}] {tc.function.name}({args})")
                result = call_tool(tc.function.name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result),
                })

        raise RuntimeError("Agent exceeded maximum reasoning steps.")


# Findings we treat as having a public exploit available (Metasploit, etc.).
_EXPLOITED = {"CVE-2011-2523", "CVE-2014-0160"}


def _exec_summary(triaged: list[dict[str, Any]]) -> str:
    p1 = [f for f in triaged if f.get("priority") == "P1"]
    if p1:
        names = ", ".join(f"{f['service']} (port {f['port']})" for f in p1[:3])
        return (f"{len(p1)} critical (P1) issue(s) require immediate action, led by "
                f"{names}. Prioritize internet-exposed services with known public exploits.")
    return "No P1 issues detected. Address higher-priority findings first per the SLA bands below."

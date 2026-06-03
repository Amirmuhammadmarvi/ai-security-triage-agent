"""Command-line interface for the AI Security Triage Agent."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .agent import TriageAgent
from .llm import LLMClient
from .report import render_json, render_markdown


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="triage-agent",
        description="AI agent that triages vulnerability scan findings and "
                    "generates a prioritized remediation report.",
    )
    p.add_argument("--scan", required=True, help="Path to a scan findings JSON file.")
    p.add_argument("--out", help="Write the report to this file instead of stdout.")
    p.add_argument("--format", choices=["md", "json"], default="md", help="Output format.")
    p.add_argument("--demo", action="store_true",
                   help="Force the offline deterministic pipeline (no API calls).")
    p.add_argument("--model", help="Override the model (else $LLM_MODEL or gpt-4o-mini).")
    p.add_argument("--verbose", action="store_true", help="Print each tool call.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    scan_path = Path(args.scan)
    if not scan_path.exists():
        print(f"error: scan file not found: {scan_path}", file=sys.stderr)
        return 1

    try:
        scan = json.loads(scan_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON in {scan_path}: {exc}", file=sys.stderr)
        return 1

    agent = TriageAgent(llm=LLMClient(model=args.model), verbose=args.verbose)
    result = agent.run(scan, demo=args.demo)

    if args.format == "json":
        output = render_json(result)
    elif result.get("report_markdown"):
        output = result["report_markdown"]          # LLM-authored report
    else:
        output = render_markdown(result)            # templated report

    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"[+] Report written to {args.out}  (mode: {result.get('mode')})")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

<div align="center">

# 🛡️ AI Security Triage Agent

**An LLM-powered agent that triages vulnerability scan findings, retrieves CVE context, scores risk, and auto-generates a prioritized remediation report — using tool-calling.**

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![LLM](https://img.shields.io/badge/LLM-OpenAI%20Compatible-10A37F?style=for-the-badge&logo=openai&logoColor=white)]()
[![Agent](https://img.shields.io/badge/Pattern-Tool--Calling%20Agent-00875A?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

</div>

---

## 🔍 Overview

Security teams drown in scanner output. This project is an **autonomous AI agent** that takes raw vulnerability findings and does the analyst's first pass automatically:

1. **Looks up** each CVE for real context, impact, and a known fix
2. **Scores** every finding with a deterministic risk model (severity × exposure × exploit availability)
3. **Prioritizes** findings into P1–P4 bands with remediation SLAs
4. **Writes** a clean, ready-to-share remediation report

It is built as a genuine **tool-calling agent**: the language model is given the findings plus a set of tools and autonomously decides when to call them — the same `perceive → decide → act` loop used by frameworks like LangChain and CrewAI, implemented directly here so the internals are transparent and the dependency footprint stays tiny.

> Built by a security engineer — it bridges practical penetration-testing knowledge with modern AI agent design.

---

## ✨ Features

- 🤖 **Real agent loop** — LLM-driven tool calling, not a hard-coded script
- 🔌 **Provider-agnostic** — any OpenAI-compatible endpoint (OpenAI, Azure OpenAI, OpenRouter, or a local model via Ollama / LM Studio)
- 🧰 **Pluggable tools** — `lookup_cve` and `score_risk`, easy to extend with new ones
- 📴 **Runs offline** — a deterministic `--demo` mode needs no API key, so the project is instantly reviewable
- 📊 **Two output formats** — human-readable Markdown or machine-readable JSON
- 🔐 **No secrets in code** — all configuration via environment variables
- 🧩 **Modular architecture** — clean separation of LLM client, tools, agent, and reporting

---

## 🏗️ Architecture

```
                ┌──────────────────────────────────────────────┐
  scan.json ──► │                 TriageAgent                  │
                │                                              │
                │   ┌─────────┐   decide    ┌──────────────┐   │
                │   │   LLM   │ ──────────► │  Tool layer  │   │
                │   │ (gpt-4o)│ ◄────────── │              │   │
                │   └─────────┘   results   │ lookup_cve   │   │
                │        │                  │ score_risk   │   │
                │        │ final report     └──────────────┘   │
                └────────┼─────────────────────────────────────┘
                         ▼
              Markdown / JSON remediation report
```

```
ai-security-triage-agent/
├── agent_triage/
│   ├── agent.py      # agent loop (LLM + tool calling) and offline pipeline
│   ├── llm.py        # OpenAI-compatible client, configured via env vars
│   ├── tools.py      # lookup_cve + score_risk, with tool-calling schemas
│   ├── report.py     # Markdown / JSON rendering and prioritization
│   └── cli.py        # command-line interface
├── data/
│   └── sample_scan.json
├── examples/
│   ├── sample_report.md
│   └── sample_report.json
├── main.py
└── requirements.txt
```

---

## 🚀 Quick Start

```bash
git clone https://github.com/Amirmuhammadmarvi/ai-security-triage-agent.git
cd ai-security-triage-agent
pip install -r requirements.txt
```

### Run offline (no API key needed)

```bash
python main.py --scan data/sample_scan.json --demo
```

### Run as a live LLM agent

```bash
cp .env.example .env          # then add your OPENAI_API_KEY
export $(grep -v '^#' .env | xargs)
python main.py --scan data/sample_scan.json --verbose
```

### Options

| Flag | Description |
|------|-------------|
| `--scan PATH` | Scan findings JSON (required) |
| `--demo` | Force the offline deterministic pipeline |
| `--format md\|json` | Output format (default: `md`) |
| `--out PATH` | Write the report to a file |
| `--model NAME` | Override the model (default `$LLM_MODEL` or `gpt-4o-mini`) |
| `--verbose` | Print each tool call the agent makes |

---

## 📥 Input Format

```json
{
  "target": "192.168.148.130",
  "findings": [
    {
      "port": 21,
      "service": "vsftpd 2.3.4",
      "cve": "CVE-2011-2523",
      "severity": "critical",
      "exposure": "internet"
    }
  ]
}
```

`severity` ∈ critical / high / medium / low / info · `exposure` ∈ internet / external / dmz / internal. The format maps cleanly from Nmap + Nikto output.

---

## 📊 Example Output

```markdown
# Vulnerability Triage Report — 192.168.148.130

## Executive Summary
- P1 (critical): 2 · P2 (high): 2 · P3 (medium): 2 · P4 (low): 0

2 critical (P1) issues require immediate action, led by vsftpd 2.3.4 (port 21)
and OpenSSL 1.0.1 (port 443). Prioritize internet-exposed services with known
public exploits.

### 1. [P1] vsftpd 2.3.4 (port 21)
- Risk score: 100/100 — Remediate within 24 hours
- CVE: CVE-2011-2523
- Impact: Unauthenticated remote root command execution.
- Remediation: Upgrade vsftpd to a vendor-supported release (3.x) or migrate to SFTP.
```

Full samples: [`examples/sample_report.md`](examples/sample_report.md) · [`examples/sample_report.json`](examples/sample_report.json)

---

## 🧠 How the Agent Loop Works

In live mode the agent runs a standard reasoning loop:

1. The findings and the tool schemas are sent to the LLM.
2. The model returns **tool calls** (e.g. `lookup_cve("CVE-2011-2523")`, `score_risk("critical", "internet", true)`).
3. The tools execute locally and their results are fed back to the model.
4. Steps 2–3 repeat until the model has enough information.
5. The model writes the final remediation report.

This is exactly how production agent frameworks operate; doing it by hand here keeps the control flow, prompt design, and tool contracts fully visible.

---

## 🗺️ Roadmap

- [ ] Live CVE enrichment from the NVD API (replacing the local knowledge base)
- [ ] RAG over an internal asset inventory to refine exposure scoring
- [ ] `LangChain` and `n8n` integrations to embed the agent in automation workflows
- [ ] Slack / email delivery of generated reports

---

## ⚠️ Disclaimer

This tool performs **defensive analysis and remediation guidance only** — it does not scan, exploit, or attack any system. Use it on findings you are authorized to assess. Generated reports are advisory and should be validated before acting in production.

---

<div align="center">

**Author: [Amir Mohammad Marwi](https://amirmohammadmarwi.vercel.app)**

[![Portfolio](https://img.shields.io/badge/Portfolio-amirmohammadmarwi.vercel.app-00875A?style=flat-square)](https://amirmohammadmarwi.vercel.app)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-amir--mohammad--marwi-0A66C2?style=flat-square&logo=linkedin)](https://linkedin.com/in/amir-mohammad-marwi)
[![GitHub](https://img.shields.io/badge/GitHub-Amirmuhammadmarvi-181717?style=flat-square&logo=github)](https://github.com/Amirmuhammadmarvi)

</div>

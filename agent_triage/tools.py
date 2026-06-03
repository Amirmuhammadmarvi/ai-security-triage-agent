"""
Tools available to the agent.

Each tool is a plain Python function plus an OpenAI-style JSON schema so the
LLM can decide when to call it (function / tool calling). This is the same
pattern used by agent frameworks like LangChain and CrewAI, implemented
directly here to keep the dependency surface small and the logic transparent.

Two tools are exposed:
    * lookup_cve   - retrieve context and a known fix for a CVE identifier
    * score_risk   - compute a deterministic priority (P1-P4) for a finding
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# A tiny local knowledge base. In production this would be a vector store or a
# live feed (NVD / CVE API); kept local here so the project runs offline.
# ---------------------------------------------------------------------------
CVE_DB: dict[str, dict[str, str]] = {
    "CVE-2011-2523": {
        "summary": "vsftpd 2.3.4 contains a backdoor that opens a root shell on "
                   "port 6200 when a username ending in ':)' is supplied.",
        "impact": "Unauthenticated remote root command execution.",
        "fix": "Upgrade vsftpd to a vendor-supported release (3.x) or migrate to "
               "SFTP. Verify package integrity against official repositories.",
        "cvss": 10.0,
    },
    "CVE-2017-7679": {
        "summary": "Apache httpd mod_mime can read one byte past the end of a "
                   "buffer when handling a malicious Content-Type response header.",
        "impact": "Information disclosure / potential denial of service.",
        "fix": "Upgrade Apache httpd to 2.2.33, 2.4.26, or later.",
        "cvss": 7.5,
    },
    "CVE-2014-0160": {
        "summary": "OpenSSL Heartbleed: the TLS heartbeat extension leaks up to "
                   "64KB of process memory per request.",
        "impact": "Disclosure of private keys, session tokens, and credentials.",
        "fix": "Upgrade OpenSSL to 1.0.1g+, reissue certificates, and rotate "
               "any secrets that may have been exposed.",
        "cvss": 7.5,
    },
}

_SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
_EXPOSURE_MULTIPLIER = {"internet": 1.0, "external": 1.0, "dmz": 0.8, "internal": 0.6}


def lookup_cve(cve_id: str) -> dict[str, Any]:
    """Return known context and remediation for a CVE id, or a generic fallback."""
    if not cve_id:
        return {
            "cve": None,
            "known": False,
            "summary": "No CVE mapped to this finding.",
            "impact": "Depends on service exposure and configuration.",
            "fix": "Restrict network exposure, disable if unused, enforce encrypted "
                   "alternatives, and apply the latest vendor patches.",
        }
    entry = CVE_DB.get(cve_id.upper())
    if entry:
        return {"cve": cve_id.upper(), "known": True, **entry}
    return {
        "cve": cve_id.upper(),
        "known": False,
        "summary": "CVE not in local knowledge base; manual review recommended.",
        "impact": "Unknown — review the NVD entry for this CVE.",
        "fix": "Consult the NVD entry and the vendor advisory, then apply the patch.",
    }


def score_risk(severity: str, exposure: str = "internal", has_public_exploit: bool = False) -> dict[str, Any]:
    """
    Compute a deterministic priority for a finding.

    Returns a numeric score (0-100), a P1-P4 priority band, and a short rationale.
    """
    base = _SEVERITY_WEIGHT.get((severity or "info").lower(), 1)
    mult = _EXPOSURE_MULTIPLIER.get((exposure or "internal").lower(), 0.6)
    score = base * 10 * mult
    if has_public_exploit:
        score = min(100, score * 1.3)
    score = round(min(100, score), 1)

    if score >= 85:
        band, sla = "P1", "Remediate within 24 hours"
    elif score >= 60:
        band, sla = "P2", "Remediate within 7 days"
    elif score >= 35:
        band, sla = "P3", "Remediate within 30 days"
    else:
        band, sla = "P4", "Track and remediate in normal cycle"

    rationale = (
        f"severity={severity}, exposure={exposure}, "
        f"public_exploit={'yes' if has_public_exploit else 'no'}"
    )
    return {"score": score, "priority": band, "sla": sla, "rationale": rationale}


# ---------------------------------------------------------------------------
# Tool schemas (OpenAI tool-calling format) + dispatch table.
# ---------------------------------------------------------------------------
TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "lookup_cve",
            "description": "Look up context, impact, and a known fix for a CVE identifier.",
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "CVE id, e.g. CVE-2011-2523"}
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "score_risk",
            "description": "Compute a deterministic priority (P1-P4) and SLA for a finding.",
            "parameters": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                    },
                    "exposure": {
                        "type": "string",
                        "enum": ["internet", "external", "dmz", "internal"],
                    },
                    "has_public_exploit": {"type": "boolean"},
                },
                "required": ["severity"],
            },
        },
    },
]

DISPATCH = {"lookup_cve": lookup_cve, "score_risk": score_risk}


def call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """Execute a tool by name with keyword arguments."""
    fn = DISPATCH.get(name)
    if fn is None:
        return {"error": f"unknown tool '{name}'"}
    return fn(**arguments)

# Vulnerability Triage Report — 192.168.148.130

_Generated 2026-06-03 22:44 · 6 findings_

## Executive Summary

- **P1 (critical):** 2  ·  **P2 (high):** 2  ·  **P3 (medium):** 2  ·  **P4 (low):** 0

2 critical (P1) issue(s) require immediate action, led by vsftpd 2.3.4 (port 21), OpenSSL 1.0.1 (port 443). Prioritize internet-exposed services with known public exploits.

## Prioritized Findings

### 1. [P1] vsftpd 2.3.4 (port 21)

- **Risk score:** 100/100 — Remediate within 24 hours
- **CVE:** CVE-2011-2523
- **Context:** vsftpd 2.3.4 contains a backdoor that opens a root shell on port 6200 when a username ending in ':)' is supplied.
- **Impact:** Unauthenticated remote root command execution.
- **Remediation:** Upgrade vsftpd to a vendor-supported release (3.x) or migrate to SFTP. Verify package integrity against official repositories.

### 2. [P1] OpenSSL 1.0.1 (port 443)

- **Risk score:** 91.0/100 — Remediate within 24 hours
- **CVE:** CVE-2014-0160
- **Context:** OpenSSL Heartbleed: the TLS heartbeat extension leaks up to 64KB of process memory per request.
- **Impact:** Disclosure of private keys, session tokens, and credentials.
- **Remediation:** Upgrade OpenSSL to 1.0.1g+, reissue certificates, and rotate any secrets that may have been exposed.

### 3. [P2] Apache httpd 2.2.8 (port 80)

- **Risk score:** 70.0/100 — Remediate within 7 days
- **CVE:** CVE-2017-7679
- **Context:** Apache httpd mod_mime can read one byte past the end of a buffer when handling a malicious Content-Type response header.
- **Impact:** Information disclosure / potential denial of service.
- **Remediation:** Upgrade Apache httpd to 2.2.33, 2.4.26, or later.

### 4. [P2] Linux telnetd (port 23)

- **Risk score:** 70.0/100 — Remediate within 7 days
- **Context:** No CVE mapped to this finding.
- **Impact:** Depends on service exposure and configuration.
- **Remediation:** Restrict network exposure, disable if unused, enforce encrypted alternatives, and apply the latest vendor patches.

### 5. [P3] MySQL 5.0.51a (port 3306)

- **Risk score:** 42.0/100 — Remediate within 30 days
- **Context:** No CVE mapped to this finding.
- **Impact:** Depends on service exposure and configuration.
- **Remediation:** Restrict network exposure, disable if unused, enforce encrypted alternatives, and apply the latest vendor patches.

### 6. [P3] OpenSSH 4.7p1 (port 22)

- **Risk score:** 40.0/100 — Remediate within 30 days
- **Context:** No CVE mapped to this finding.
- **Impact:** Depends on service exposure and configuration.
- **Remediation:** Restrict network exposure, disable if unused, enforce encrypted alternatives, and apply the latest vendor patches.

---
_Produced by the AI Security Triage Agent. Findings are advisory; validate before acting in production._
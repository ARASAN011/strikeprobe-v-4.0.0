# ⚡ StrikeProbe v4.0.0

![Version](https://img.shields.io/badge/version-4.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Kali](https://img.shields.io/badge/Kali%20Linux-Supported-black)

**StrikeProbe** is an Enterprise-Grade, Object-Oriented Web Vulnerability Scanner designed for developers and security researchers. 

## 🎯 The Problem It Solves
Developers often lack the time to manually monitor every endpoint or don't have access to expensive AI-driven security tools to identify vulnerabilities during the build process. 

StrikeProbe automates the heavy lifting. It acts as an automated Red Team, allowing developers to run deep, non-destructive probes against their local environments or staging servers to identify the **OWASP Top 10:2025** vulnerabilities before deployment. 

## ✨ Key Features
* **Developer-Friendly Reporting:** Generates rich HTML reports with actionable "Remediation Playbooks" (Safe vs. Vulnerable code examples).
* **Kali Linux Ready:** Built to run seamlessly on Kali Linux for security investigations.
* **Deep Exploitation Phase (Password-Gated):**
  * **Time-Based Blind SQLi:** Bypasses suppressed errors using `SLEEP()`/`pg_sleep()`.
  * **WAF-Evasion XSS:** Uses Base64 and DOM-based payloads (`eval(atob(...))`) to bypass standard Web Application Firewalls.
  * **Cloud-Native SSRF:** Attempts AWS IMDSv2 token retrieval to test modern cloud metadata protections.
* **Agent-Ready OOP Architecture:** Highly modular, making it easy to integrate into CI/CD pipelines or AI agent workflows.

## ⚙️ Installation (Kali Linux / Debian)

Clone the repository and install the required dependencies:

```bash
# Clone the repo
git clone [https://github.com/ARASAN011/strikeprobe-v-4.0.0.git](https://github.com/ARASAN011/strikeprobe-v-4.0.0.git)
cd strikeprobe-v-4.0.0

# Install dependencies
pip3 install requests beautifulsoup4

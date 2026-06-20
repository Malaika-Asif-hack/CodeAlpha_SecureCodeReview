# 🔍 CodeAlpha - Secure Code Review & Vulnerability Scanner

## Task 3: Secure Coding Review

### Project Overview
A comprehensive vulnerability and CVE scanner that performs:
- Port scanning on common service ports
- Banner grabbing (HTTP, FTP, SSH, etc.)
- Service version detection
- CVE lookup via NVD API
- Security vulnerability assessment
- JSON report generation

### 📋 What This Scanner Detects

| Vulnerability Type | Detection Method | Risk Level |
|-------------------|------------------|------------|
| **SQL Injection** | Tests input fields with payloads | CRITICAL |
| **Cross-Site Scripting (XSS)** | Injects JavaScript payloads | HIGH |
| **Directory Traversal** | Tests path traversal patterns | HIGH |
| **CVE Vulnerabilities** | NVD API integration | VARIES |
| **Open Ports** | TCP port scanning | MEDIUM |
| **Service Versions** | Banner grabbing & analysis | MEDIUM |

---

### 🚀 Installation

```bash
git clone https://github.com/Malaika-Asif-hack/CodeAlpha_SecureCodeReview.git
cd CodeAlpha_SecureCodeReview
pip install -r requirements.txt
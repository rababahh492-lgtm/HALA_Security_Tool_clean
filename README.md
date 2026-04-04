# Hala-Scan: Mobile Security Auditor 🛡️📱

**Hala-Scan** is a Python-based CLI tool for **automated static analysis of Android APK files**.  
It helps security researchers and developers identify insecure configurations, hardcoded secrets, and unencrypted endpoints in seconds.

---

## 🆕 New Features (v2.0)
- Generates **JSON report** alongside TXT report.
- Adds **Risk Score system** (HIGH/LOW → 0-100).
- CLI improvements with colored output for better readability.
- Detects:
  - Hardcoded API keys
  - Passwords and tokens
  - Insecure HTTP URLs
- Reports are stored in a dedicated folder: `reports/`.

---

## 🛠️ Installation
1. Clone the repository:

```bash
git clone https://github.com/rababahh492-lgtm/Hala-Scan.git
cd Hala-Scan

pip install -r requirements.txt

python hala_scan.py <app.apk>




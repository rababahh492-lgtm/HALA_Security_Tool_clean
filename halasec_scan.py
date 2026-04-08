from androguard.misc import AnalyzeAPK
import os
import sys
import json
import hashlib
import requests

def ai_analyze(findings, permissions):
    try:
        prompt = f"""
You are a cybersecurity expert.

Analyze the following APK scan results:

Permissions:
{permissions}

Findings:
{findings}

Give:
1. Risk Level (LOW/MEDIUM/HIGH)
2. Short explanation
3. Security recommendations
"""

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "mistral",
                "prompt": prompt,
                "stream": False
            }
        )

        result = response.json()["response"]

        return result

    except Exception as e:
        return f"AI Error: {e}"

# -------- Smart Vulnerability Rules -------- #
RULES = {
    "android.permission.SEND_SMS": {
        "severity": "HIGH",
        "title": "SMS Abuse Risk",
        "description": "App can send SMS messages without user interaction.",
        "impact": "Attackers may send premium SMS or perform fraud.",
        "fix": "Remove permission or require explicit user interaction."
    },
    "android.permission.READ_CONTACTS": {
        "severity": "HIGH",
        "title": "Privacy Leak - Contacts",
        "description": "App can access user contacts.",
        "impact": "Sensitive user data can be exfiltrated.",
        "fix": "Limit access and request permission only when needed."
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "severity": "HIGH",
        "title": "Insecure Storage",
        "description": "App writes data to shared storage.",
        "impact": "Data may be accessed by other apps.",
        "fix": "Use internal storage or encrypt sensitive data."
    },
    "android.permission.INTERNET": {
        "severity": "LOW",
        "title": "Network Usage",
        "description": "App uses internet.",
        "impact": "Potential data transmission risk.",
        "fix": "Use HTTPS."
    }
}

# -------- Hash -------- #
def sha256(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()

# -------- MAIN ANALYZER -------- #
def analyze_apk(apk_path):
    print(f"\nScanning: {os.path.basename(apk_path)}")

    try:
        a, d, dx = AnalyzeAPK(apk_path)
    except Exception as e:
        print(f"Error analyzing APK: {e}")
        return None

    findings = []
    permissions = a.get_permissions()

    # -------- Permission Analysis -------- #
    for perm in permissions:
        if perm in RULES:
            rule = RULES[perm]
            findings.append({
                "Name": rule["title"],
                "OWASP": "Mobile Security",
                "Description": rule["description"],
                "Solution": rule["fix"],
                "Severity": rule["severity"]
            })

    # -------- Hardcoded Secrets -------- #
    secret_hits = 0
    for string in dx.get_strings():
        s = str(string)
        if any(x in s.lower() for x in ["password", "secret", "token", "key="]):
            if len(s) < 100:
                secret_hits += 1

    if secret_hits > 5:
        findings.append({
            "Name": "Hardcoded Secrets",
            "OWASP": "M2: Insecure Data Storage",
            "Description": "Hardcoded credentials detected.",
            "Solution": "Move secrets to backend.",
            "Severity": "HIGH"
        })

    # -------- Risk Calculation -------- #
    score = 0
    for f in findings:
        if f["Severity"] == "HIGH":
            score += 30
        elif f["Severity"] == "MEDIUM":
            score += 15
        else:
            score += 5

    score = min(score, 100)

    if score > 70:
        risk = "HIGH"
    elif score > 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    # -------- Clean Permissions -------- #
    clean_permissions = [p.split(".")[-1] for p in permissions]

    # -------- FINAL RESULT (🔥 مهم) -------- #
    result = {
        "APK Name": a.get_app_name(),
        "Risk Score": score,
        "Risk Level": risk,
        "Permissions": clean_permissions,
        "Vulnerabilities": findings
    }

    # -------- Save JSON -------- #
    os.makedirs("reports", exist_ok=True)
    with open(f"reports/{os.path.basename(apk_path)}.json", "w") as f:
        json.dump(result, f, indent=4)

    print(f"Risk: {risk} | Score: {score}")
    return result


# -------- Scan Directory -------- #
def scan_directory(path):
    results = []
    for file in os.listdir(path):
        if file.endswith(".apk"):
            res = analyze_apk(os.path.join(path, file))
            if res:
                results.append(res)
    return results


# -------- MAIN -------- #
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python halasec_scan.py <apk_folder>")
    else:
        scan_directory(sys.argv[1])

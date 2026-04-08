import os
from androguard.core.bytecodes.apk import APK
import json


DANGEROUS_PERMISSIONS = {
    "SEND_SMS": {"risk": 30, "fix": "Use runtime permission or remove if unnecessary"},
    "READ_CONTACTS": {"risk": 20, "fix": "Request runtime permission only when needed"},
    "ACCESS_COARSE_LOCATION": {"risk": 15, "fix": "Request permission only when needed"},
    "READ_PHONE_STATE": {"risk": 25, "fix": "Use temporary runtime permission"}
}

def scan_apk(file_path: str):
    """تحليل APK (Static Analysis)"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"APK file not found: {file_path}")

    try:
        apk = APK(file_path)
        permissions = apk.get_permissions() or []
    except Exception:
        permissions = []

    findings = []
    risk_score = 0

    
    for perm, data in DANGEROUS_PERMISSIONS.items():
        for p in permissions:
            if perm.lower() in p.lower():
                findings.append({
                    "permission": p,
                    "risk": data["risk"],
                    "ai_fix": data["fix"]
                })
                risk_score += data["risk"]

    if not findings:
        findings.append({"info": "No issues found"})

    
    risk_score = min(risk_score, 100)

    verdict = "HIGH RISK" if risk_score >= 40 else "LOW RISK"

    return {
        "name": os.path.basename(file_path),
        "risk_score": risk_score,
        "permissions": permissions,
        "findings": findings,
        "verdict": verdict
    }

def main(folder_path: str):
    results = []

    if not os.path.exists(folder_path):
        raise FileNotFoundError("Folder not found!")

    for filename in os.listdir(folder_path):
        if filename.endswith(".apk"):
            file_path = os.path.join(folder_path, filename)
            try:
                result = scan_apk(file_path)
                results.append(result)

               
                print(f"Scanned: {filename} → {result['verdict']} ({result['risk_score']}/100)")

            except Exception:
                print(f"Failed to scan: {filename}")
                continue

    
    os.makedirs("reports", exist_ok=True)

    
    with open("reports/scan_results.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\nAll APKs scanned! Full details saved in reports/scan_results.json")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python halasec_scan.py <folder_with_apks>")
    else:
        main(sys.argv[1])

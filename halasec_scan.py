import os
from androguard.core.bytecodes.apk import APK
from fpdf import FPDF
import json
from datetime import datetime
from colorama import Fore, init

init(autoreset=True)

# Directories
TEST_DIR = "test_files"
REPORT_DIR = "reports"
os.makedirs(REPORT_DIR, exist_ok=True)

# Security advice (English)
PERMISSION_ADVICE = {
    "android.permission.SEND_SMS": "Warning: can send SMS without permission!",
    "android.permission.READ_CONTACTS": "Warning: can read contacts!",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Warning: can write to storage!",
    "android.permission.ACCESS_COARSE_LOCATION": "Warning: can track location!",
    "android.permission.GET_ACCOUNTS": "Warning: can access accounts!",
    "android.permission.USE_CREDENTIALS": "Warning: can use credentials!"
}

def calculate_risk_level(score):
    if score <= 4:
        return "LOW"
    elif score <= 14:
        return "MEDIUM"
    else:
        return "HIGH"

def scan_apk(apk_path):
    result = {
        "app_name": "Unknown",
        "package_name": "Unknown",
        "version": "Unknown",
        "permissions": [],
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
        "risk_score": 0,
        "risk_level": "LOW",
        "scan_date": datetime.now().strftime("%Y-%m-%d"),
        "scan_time": datetime.now().strftime("%H:%M:%S"),
        "advice": []
    }

    try:
        apk = APK(apk_path)
        if not apk.is_valid_APK():
            print(Fore.RED + f"[!] Invalid APK file: {os.path.basename(apk_path)}")
            return None

        result["app_name"] = apk.get_app_name() or "Unknown"
        result["package_name"] = apk.package or "Unknown"
        try:
            result["version"] = apk.get_androidversion_name() or "Unknown"
        except:
            pass

        result["permissions"] = apk.get_permissions() or []
        result["activities"] = apk.get_activities() or []
        result["services"] = apk.get_services() or []
        result["receivers"] = apk.get_receivers() or []
        result["providers"] = apk.get_providers() or []

        # Risk score calculation
        score = 0
        advice_list = []
        for p in result["permissions"]:
            if p in PERMISSION_ADVICE:
                score += 5
                advice_list.append(f"{p}: {PERMISSION_ADVICE[p]}")
            else:
                score += 1

        result["risk_score"] = score
        result["risk_level"] = calculate_risk_level(score)
        result["advice"] = advice_list

    except Exception as e:
        print(Fore.RED + f"[!] Error scanning {os.path.basename(apk_path)}: {e}")
        return None

    return result

def format_report(result):
    text = []
    text.append(">>> HALA-SCAN SECURITY REPORT <<<\n")
    text.append(f"APK Name: {result['app_name']}")
    text.append(f"Package Name: {result['package_name']}")
    text.append(f"Version: {result['version']}")
    text.append(f"Scan Date: {result['scan_date']}")
    text.append(f"Scan Time: {result['scan_time']}")
    text.append(f"Risk Score: {result['risk_score']}")
    text.append(f"Risk Level: {result['risk_level']}\n")

    text.append("Permissions:")
    for p in result['permissions']:
        text.append(f" - {p}")

    text.append("\nActivities:")
    if result['activities']:
        for a in result['activities']:
            text.append(f" - {a}")
    else:
        text.append(" - None")

    text.append("\nServices:")
    if result['services']:
        for s in result['services']:
            text.append(f" - {s}")
    else:
        text.append(" - None")

    text.append("\nReceivers:")
    if result['receivers']:
        for r in result['receivers']:
            text.append(f" - {r}")
    else:
        text.append(" - None")

    text.append("\nProviders:")
    if result['providers']:
        for p in result['providers']:
            text.append(f" - {p}")
    else:
        text.append(" - None")

    if result['advice']:
        text.append("\nSecurity Advice:")
        for a in result['advice']:
            text.append(f" - {a}")

    return "\n".join(text)

def save_reports(result, apk_file):
    base_name = os.path.splitext(os.path.basename(apk_file))[0]
    apk_report_dir = os.path.join(REPORT_DIR, base_name)
    os.makedirs(apk_report_dir, exist_ok=True)

    # JSON
    json_path = os.path.join(apk_report_dir, f"{base_name}_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    # TXT
    txt_path = os.path.join(apk_report_dir, f"{base_name}_report.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(format_report(result))

    # PDF
    pdf_path = os.path.join(apk_report_dir, f"{base_name}_report.pdf")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 6, format_report(result))
    pdf.output(pdf_path)

    print(Fore.GREEN + f"[+] Reports saved in folder: {apk_report_dir}")

def print_summary(result):
    print(format_report(result))

def generate_readme():
    readme_path = os.path.join(REPORT_DIR, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write("# HALA-SCAN Reports\n\n")
        f.write("This file summarizes all scanned APKs and their risk levels.\n\n")
        f.write("| APK Name | Risk Score | Risk Level | Permissions | Reports |\n")
        f.write("|----------|------------|------------|-------------|---------|\n")

        for apk_folder in os.listdir(REPORT_DIR):
            folder_path = os.path.join(REPORT_DIR, apk_folder)
            if not os.path.isdir(folder_path):
                continue
            json_files = [f for f in os.listdir(folder_path) if f.endswith(".json")]
            if not json_files:
                continue
            json_path = os.path.join(folder_path, json_files[0])
            with open(json_path, "r", encoding="utf-8") as jf:
                data = json.load(jf)
            permissions_count = len(data.get("permissions", []))
            links = f"[PDF]({apk_folder}/{apk_folder}_report.pdf) | [TXT]({apk_folder}/{apk_folder}_report.txt) | [JSON]({apk_folder}/{apk_folder}_report.json)"
            f.write(f"| {data.get('app_name','Unknown')} | {data.get('risk_score','-')} | {data.get('risk_level','-')} | {permissions_count} | {links} |\n")

    print(Fore.GREEN + f"[+] README.md generated in {REPORT_DIR}/README.md")

def main():
    apk_files = [f for f in os.listdir(TEST_DIR) if f.lower().endswith(".apk")]

    if not apk_files:
        print(Fore.RED + "[!] No APK files found in test_files!")
        return

    for apk_file in apk_files:
        apk_path = os.path.join(TEST_DIR, apk_file)
        print(Fore.CYAN + f"\nScanning {apk_file} ...")
        result = scan_apk(apk_path)
        if result:
            print_summary(result)
            save_reports(result, apk_path)

    generate_readme()

if __name__ == "__main__":
    main()
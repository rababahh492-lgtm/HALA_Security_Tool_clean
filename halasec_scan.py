import os
from datetime import datetime
from androguard.core.bytecodes.apk import APK

def scan_apk(file_path):
    try:
        apk = APK(file_path)
    except Exception as e:
        return None, f"Invalid APK: {os.path.basename(file_path)}"


    try:
        apk_name = apk.get_app_name() or "Unknown"
    except:
        apk_name = "Unknown"

    try:
        apk_version = apk.get_androidversion_name() or "Unknown"
    except:
        apk_version = "Unknown"

    apk_info = {
        "APK Name": apk_name,
        "Package Name": apk.get_package() or "Unknown",
        "Version": apk_version,
        "Scan Date": datetime.now().strftime("%Y-%m-%d"),
        "Scan Time": datetime.now().strftime("%H:%M:%S"),
        "Permissions": apk.get_permissions() or [],
        "Activities": apk.get_activities() or [],
        "Services": apk.get_services() or [],
        "Receivers": apk.get_receivers() or [],
        "Providers": apk.get_providers() or [],
    }

    
    risk_score = len(apk_info["Permissions"]) * 5
    apk_info["Risk Score"] = min(risk_score, 100)
    apk_info["Risk Level"] = "HIGH" if risk_score >= 50 else "LOW"

    return apk_info, None

def save_reports(apk_info, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    base_name = apk_info["APK Name"].replace(" ", "_")

  
    txt_path = os.path.join(output_folder, f"{base_name}_report.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        for key, value in apk_info.items():
            f.write(f"{key}: {value}\n")

    
    import json
    json_path = os.path.join(output_folder, f"{base_name}_report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(apk_info, f, indent=4)

 
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
        pdf_path = os.path.join(output_folder, f"{base_name}_report.pdf")
        c = canvas.Canvas(pdf_path, pagesize=letter)
        y = 750
        for key, value in apk_info.items():
            c.drawString(50, y, f"{key}: {value}")
            y -= 15
        c.save()
    except:
        pass

    print(f"[+] Scan completed: {apk_info['Risk Level']} ({apk_info['Risk Score']}/100)")
    print(f"[+] Report saved in: {output_folder}\n")

def main(folder):
    for file in os.listdir(folder):
        file_path = os.path.join(folder, file)
        apk_info, error = scan_apk(file_path)
        if error:
            print(f"[!] {error}\n")
            continue
        save_reports(apk_info, os.path.join("reports", file.replace(" ", "_")))

if __name__ == "__main__":
    main("test_files")  

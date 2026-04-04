import os
from androguard.core.bytecodes.apk import APK

# قائمة permissions خطرة مع توصيات
DANGEROUS_PERMISSIONS = {
    "SEND_SMS": "Use runtime permission or remove if unnecessary",
    "READ_CONTACTS": "Request runtime permission only when needed",
    "ACCESS_COARSE_LOCATION": "Request permission only when needed",
    "READ_PHONE_STATE": "Use temporary runtime permission"
}

def scan_apk(file_path: str):
    """تحليل APK بصمت بدون أي طباعة أو إنشاء ملفات"""

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"APK file not found: {file_path}")

    try:
        apk = APK(file_path)
        permissions = apk.get_permissions() or []
    except Exception:
        permissions = []

    findings = []
    risk_score = 0

    # تحليل permissions مع تجاهل حالة الحروف
    for perm, advice in DANGEROUS_PERMISSIONS.items():
        for p in permissions:
            if perm.lower() in p.lower():
                findings.append({"permission": p, "ai_fix": advice})
                risk_score += 20

    if not findings:
        findings.append({"info": "No issues found"})

    verdict = "HIGH RISK" if risk_score >= 40 else "LOW RISK"

    # رجوع البيانات مباشرة للداشبورد
    return {
        "name": os.path.basename(file_path),
        "risk_score": risk_score,
        "permissions": permissions,
        "findings": findings,
        "verdict": verdict
    }
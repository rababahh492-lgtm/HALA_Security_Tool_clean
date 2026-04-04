from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.scanner import scan_apk  # الكود الأصلي لفحص APK
from datetime import datetime
import os

app = FastAPI()

# السماح بالـ CORS للـ Streamlit
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# تأكد من وجود مجلد test_files
os.makedirs("test_files", exist_ok=True)

@app.post("/scan/")
async def scan_apk_file(file: UploadFile = File(...)):
    # تحقق من حجم الملف
    file.file.seek(0, 2)  # نهاية الملف
    size = file.file.tell()
    file.file.seek(0)      # بداية الملف
    
    if size > 200 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File must be 200MB or smaller")
    
    # حفظ الملف مؤقتًا
    temp_path = f"test_files/{file.filename}"
    with open(temp_path, "wb") as f:
        f.write(await file.read())
    
    # نفذ فحص APK
    result = scan_apk(temp_path)
    
    # ادمج القيم الافتراضية مع الناتج لضمان كل المفاتيح موجودة
    now = datetime.now()
    default_keys = {
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
        "scan_date": now.strftime("%Y-%m-%d"),
        "scan_time": now.strftime("%H:%M:%S")
    }
    for key, val in default_keys.items():
        if key not in result or result[key] is None:
            result[key] = val

    # حساب Risk Level حسب Score
    risk_score = result.get("risk_score", 0)
    result["risk_score"] = risk_score
    if risk_score >= 15:
        result["risk_level"] = "HIGH"
    elif risk_score >= 5:
        result["risk_level"] = "MEDIUM"
    else:
        result["risk_level"] = "LOW"

    return result
import streamlit as st
import pandas as pd
from backend.scanner import scan_apk

st.set_page_config(page_title="HalaScan Dashboard", layout="wide")

st.title("📱 HalaScan Live Dashboard")
st.write("Upload APK file(s) and get instant security analysis.")

uploaded_files = st.file_uploader(
    "Upload APK file(s)",
    type=["apk"],
    accept_multiple_files=True
)

def verdict_color(score):
    if score >= 70:
        return "🔴 HIGH RISK"
    elif score >= 40:
        return "🟡 MEDIUM RISK"
    else:
        return "🟢 LOW RISK"

def progress_color(score):
    if score >= 70:
        return 100  # كامل الحمراء
    elif score >= 40:
        return 60   # أصفر
    else:
        return 30   # أخضر

if uploaded_files:
    results_list = []

    if st.button("Analyze All APKs"):
        for uploaded_file in uploaded_files:
            temp_path = f"temp_{uploaded_file.name}"
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())

            # تحليل بصمت
            result = scan_apk(temp_path)
            results_list.append(result)

            # مسح الملف المؤقت
            try:
                import os
                os.remove(temp_path)
            except:
                pass

        # جدول النتائج
        df = pd.DataFrame([
            {
                "APK Name": r["name"],
                "Risk Score": r["risk_score"],
                "Verdict": verdict_color(r["risk_score"]),
                "Findings": ", ".join([f.get("permission", f.get("info", "")) for f in r["findings"]])
            }
            for r in results_list
        ])

        st.subheader("📊 Summary Table")
        st.dataframe(df, use_container_width=True)

        st.subheader("🔹 Risk Score Chart")
        st.bar_chart(df.set_index("APK Name")["Risk Score"])

        st.subheader("APK Details")
        for res in results_list:
            st.markdown(f"### {res['name']}")
            st.progress(res["risk_score"])
            st.write(f"**Verdict:** {verdict_color(res['risk_score'])}")
            
            # Permissions
            st.write("**Permissions:**")
            for p in res["permissions"]:
                st.markdown(f"- {p}")

            # Findings – Cards
            st.write("**Findings:**")
            for f in res["findings"]:
                if "permission" in f:
                    st.markdown(f"**Permission:** {f['permission']}  \n**Recommendation:** {f['ai_fix']}")
                else:
                    st.markdown(f"{f.get('info','')}")
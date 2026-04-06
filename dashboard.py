import streamlit as st
import os
import pandas as pd
from halasec_scan import scan_apk, save_reports
import plotly.express as px
import time

# ----------- إعدادات الصفحة -----------
st.set_page_config(
    page_title="HALA-SCAN Dashboard",
    page_icon="logo.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ----------- ستايل CSS ----------
st.markdown("""
<style>
.stApp {
    background: linear-gradient(135deg, #1c1c1c, #b48ddb); /* أسود إلى بنفسجي مموج */
    color: #b48ddb; /* كل النصوص بنفسجي */
}
.stButton>button {
    background-color: #a085d6;  /* بنفسجي جذاب */
    color: white;
    font-weight: bold;
}
.stButton>button:hover {
    background-color: #c1a3f0;
    color: white;
}
.stTextInput>div>input, .stSelectbox>div>div>div>div {
    background-color: #f0f0f0;
    color: black;
    border: 1px solid #a085d6;
}
.stExpanderHeader {
    font-weight: bold;
    color: #b48ddb;
}
</style>
""", unsafe_allow_html=True)

# ----------- Header ----------
st.image("logo.png", width=150)
st.title("HALA-SCAN Security Dashboard")
st.subheader("Secure your mobile apps like a pro!")

# ----------- رفع ملفات APK ----------
uploaded_files = st.file_uploader(
    "Upload APK files",
    type=["apk"],
    accept_multiple_files=True
)

# ----------- مكان حفظ التقارير ----------
REPORTS_DIR = "reports"

# ----------- DataFrame لتخزين النتائج ----------
results_df = pd.DataFrame(columns=["APK Name", "Risk Score", "Risk Level", "Report Folder"])
permissions_list = []

# ----------- فحص وعرض النتائج ----------
if uploaded_files:
    with st.spinner("🔄 Scanning APKs… Secure your apps like a pro!"):
        time.sleep(1)  # لتوضيح الـ spinner حتى لو سريع
        for uploaded_file in uploaded_files:
            temp_path = os.path.join("temp", uploaded_file.name)
            os.makedirs("temp", exist_ok=True)
            with open(temp_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            apk_result, error = scan_apk(temp_path)
            if error:
                st.error(f"Error scanning {uploaded_file.name}: {error}")
            else:
                report_folder = save_reports(apk_result, temp_path)
                st.success(f"Scan completed: {apk_result['Risk Level']} ({apk_result['Risk Score']}/100)")
                st.info(f"Reports saved in folder: {report_folder}")

                # حفظ النتائج في DataFrame
                results_df = pd.concat([results_df, pd.DataFrame([{
                    "APK Name": apk_result["APK Name"],
                    "Risk Score": apk_result["Risk Score"],
                    "Risk Level": apk_result["Risk Level"],
                    "Report Folder": report_folder
                }])], ignore_index=True)

                # جمع Permissions
                if "Permissions" in apk_result:
                    permissions_list.extend(apk_result["Permissions"])

                # عرض التفاصيل
                with st.expander(f"View full scan details for {apk_result['APK Name']}"):
                    for k, v in apk_result.items():
                        st.markdown(f"**{k}:** {v}")

                # ----------- Dynamic Recommendations ---------
                risk_level = apk_result["Risk Level"]
                tips = []
                if risk_level == "HIGH":
                    tips = [
                        "⚠️ High Risk: Avoid using sensitive permissions!",
                        "🔒 Secure storage and transmission of user data is critical.",
                        "🛡️ Conduct penetration testing before release."
                    ]
                elif risk_level == "MEDIUM":
                    tips = [
                        "⚠️ Medium Risk: Review app permissions carefully.",
                        "🔧 Update libraries to latest versions.",
                        "🔎 Monitor for unusual app behavior."
                    ]
                else:  # LOW
                    tips = [
                        "✅ Low Risk: Keep following best practices.",
                        "📝 Document app changes regularly.",
                        "🔒 Maintain secure coding standards."
                    ]

                st.markdown("---")
                st.subheader(f"💡 Recommendations based on {apk_result['APK Name']} scan:")
                for tip in tips:
                    st.markdown(f"- {tip}")

# ----------- Charts ----------
if not results_df.empty:
    st.markdown("---")
    st.subheader("📊 APK Risk Scores")
    st.bar_chart(results_df.set_index("APK Name")["Risk Score"])

# ----------- Pie Chart للـ Permissions ----------
if permissions_list:
    st.markdown("---")
    st.subheader("📌 Permissions Distribution")
    perm_df = pd.DataFrame(permissions_list, columns=["Permission"])
    perm_count = perm_df["Permission"].value_counts().reset_index()
    perm_count.columns = ["Permission", "Count"]
    fig = px.pie(perm_count, names="Permission", values="Count", color_discrete_sequence=px.colors.qualitative.Pastel)
    st.plotly_chart(fig)

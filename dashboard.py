import streamlit as st
import os
import pandas as pd
import time
import plotly.express as px
from fpdf import FPDF
import base64

# -------- DUMMY SCAN FUNCTIONS --------
def scan_apk(path):
    return {
        "APK Name": os.path.basename(path),
        "Risk Score": 78,
        "Risk Level": "HIGH",
        "Permissions": ["INTERNET","CAMERA","LOCATION","READ_CONTACTS"],
        "Vulnerabilities":[
            {"Name":"Insecure Data Storage","OWASP":"M2: Insecure Data Storage",
             "Description":"Sensitive data stored unencrypted, can be stolen if device is compromised.",
             "Solution":"Encrypt data using AES and secure key storage."},
            {"Name":"Improper Platform Usage","OWASP":"M4: Insecure Communication",
             "Description":"App uses HTTP instead of HTTPS.",
             "Solution":"Use HTTPS with certificate pinning for all network requests."},
            {"Name":"Weak Authentication","OWASP":"M1: Improper Platform Usage",
             "Description":"App allows weak PINs and no timeout.",
             "Solution":"Enforce strong authentication with timeouts."}
        ]
    }, None

def save_reports(res, path):
    pass

# -------- PDF GENERATOR --------
def generate_pdf(app):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"HALA-SCAN Report - {app['APK Name']}", ln=True, align="C")
    pdf.ln(10)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, f"Risk Level: {app['Risk Level']}", ln=True)
    pdf.cell(0, 10, f"Risk Score: {app['Risk Score']}/100", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Permissions:", ln=True)
    pdf.set_font("Arial", "", 12)
    for perm in app.get("Permissions", []):
        pdf.cell(0, 8, f"- {perm}", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 10, "Vulnerabilities:", ln=True)
    pdf.set_font("Arial", "", 12)
    for vul in app.get("Vulnerabilities", []):
        pdf.multi_cell(0, 8, f"- {vul['Name']} ({vul['OWASP']})\n  Description: {vul['Description']}\n  Solution: {vul['Solution']}\n")
        pdf.ln(2)

    pdf_output = f"reports/{app['APK Name']}_HALAScan.pdf"
    os.makedirs("reports", exist_ok=True)
    pdf.output(pdf_output)
    return pdf_output

# -------- PAGE STATE --------
if "page" not in st.session_state: st.session_state.page = "landing"

# -------- GLOBAL STYLE ----------
st.set_page_config(page_title="HALA-SCAN", page_icon=None, layout="wide")
st.markdown("""
<style>
.stApp {background: linear-gradient(140deg,#0a0a0a,#1a1a1a,#2b1f3d,#5a3ea1); color:#d8cfff; font-family:'Segoe UI', sans-serif;}
h1,h2,h3{color:#cbb6ff !important;}
.card{background:rgba(20,20,20,0.85);padding:20px;border-radius:18px;margin-bottom:20px;border:1px solid rgba(122,95,199,0.2);box-shadow:0 0 15px rgba(122,95,199,0.2);transition:0.3s;}
.card:hover{transform:translateY(-5px);box-shadow:0 0 30px rgba(122,95,199,0.6);}
.progress{height:6px;border-radius:10px;background:#222;}
.fill{height:100%;border-radius:10px;}
.tip{background: rgba(122,95,199,0.08); border-left:3px solid #7a5fc7; padding:10px;margin:6px 0;border-radius:8px;}
.loader{border:6px solid #f3f3f3;border-top:6px solid #7a5fc7;border-radius:50%;width:60px;height:60px;animation:spin 1s linear infinite;margin:auto;margin-top:50px;}
@keyframes spin{0%{transform:rotate(0deg);}100%{transform:rotate(360deg);}}
.fadein{animation: fadeIn 1.5s ease-in;}
@keyframes fadeIn{from{opacity:0; transform: translateY(20px);}to{opacity:1; transform: translateY(0);}}
.typing{border-right:2px solid #cbb6ff; white-space: nowrap; overflow: hidden; display:inline-block; animation: typing 2s steps(40,end) forwards, blink 0.7s infinite;}
@keyframes typing{from{width:0} to{width:380px}}
@keyframes blink{50%{border-color:transparent}}
</style>
""", unsafe_allow_html=True)

# =========================================================
# LIGHT LANDING PAGE (ENGLISH)
# =========================================================
if st.session_state.page=="landing":
    st.markdown("""
    <div style='text-align:center; margin-top:150px;' class='fadein'>
        <h1 style='font-size:50px; color:#cbb6ff;'>Welcome to HALA-SCAN!</h1>
        <p class='typing' style='font-size:18px; color:#d8cfff; max-width:500px; margin:auto;'>
         Let's make your apps safer! 🚀 </p>
    </div>
    """, unsafe_allow_html=True)

    if st.button(" Start Scanning"):
        st.session_state.page = "dashboard"

# =========================================================
# DASHBOARD
# =========================================================
if st.session_state.page=="dashboard":
    st.image("logo.png", width=120)
    st.title("HALA-SCAN Dashboard")

    uploaded_files = st.file_uploader("Upload APKs", type=["apk"], accept_multiple_files=True)
    results=[]
    permissions_list=[]

    if uploaded_files:
        loader_placeholder = st.empty()
        loader_placeholder.markdown("<div class='loader'></div>", unsafe_allow_html=True)
        time.sleep(1)

        with st.spinner(" Analyzing APKs..."):
            for file in uploaded_files:
                path=os.path.join("temp",file.name)
                os.makedirs("temp",exist_ok=True)
                with open(path,"wb") as f: f.write(file.getbuffer())
                res, err=scan_apk(path)
                if err: st.error(err); continue
                save_reports(res,path)
                results.append(res)
                permissions_list.extend(res.get("Permissions",[]))

        loader_placeholder.empty()

    # ---------- RESULTS CARDS ----------
    for app in results:
        risk=app["Risk Level"]
        score=app["Risk Score"]
        color="#ff4d6d" if risk=="HIGH" else "#facc15" if risk=="MEDIUM" else "#4ade80"

        st.markdown(f"""
        <div class='card fadein'>
            <h3>📱 {app['APK Name']}</h3>
            <p style='color:{color}; font-weight:bold;'>{risk} — {score}/100</p>
            <div class='progress'><div class='fill' style='width:{score}%; background:{color}'></div></div>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("###  AI Vulnerability Analysis")
        for vul in app.get("Vulnerabilities",[]):
            st.markdown(f"""
            <div class='tip fadein'>
                <b>{vul['Name']} ({vul['OWASP']})</b><br>
                <b>Description:</b> {vul['Description']}<br>
                <b>Solution:</b> {vul['Solution']}
            </div>
            """, unsafe_allow_html=True)

        # ---------- PDF DOWNLOAD BUTTON ----------
        pdf_file = generate_pdf(app)
        with open(pdf_file, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
            href = f'<a href="data:application/octet-stream;base64,{b64}" download="{os.path.basename(pdf_file)}"><button style="background-color:#7a5fc7;color:white;padding:8px 16px;border:none;border-radius:8px;cursor:pointer;margin-top:5px;">📄 Download PDF</button></a>'
            st.markdown(href, unsafe_allow_html=True)

    # ---------- BAR CHART ----------
    if results:
        df=pd.DataFrame(results).sort_values(by="Risk Score", ascending=False)
        st.markdown("---")
        st.subheader(" Risk Scores Overview")
        st.bar_chart(df.set_index("APK Name")["Risk Score"])

    # ---------- PIE CHART ----------
    if permissions_list:
        st.markdown("---")
        st.subheader(" Permissions Distribution")
        p=pd.DataFrame(permissions_list,columns=["Permission"])
        p=p["Permission"].value_counts().reset_index()
        p.columns=["Permission","Count"]
        fig=px.pie(p,names="Permission",values="Count",color_discrete_sequence=px.colors.sequential.Purples)
        st.plotly_chart(fig)

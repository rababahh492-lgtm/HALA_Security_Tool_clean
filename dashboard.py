import streamlit as st
import os
import pandas as pd
import time
import plotly.express as px
import subprocess
import shutil

# -------- REAL SCAN FUNCTION --------
def scan_apk(path):
    try:
        from halasec_scan import analyze_apk
        res = analyze_apk(path)
        if not res:
            return None, "Failed to analyze APK"
        return {
            "APK Name": res.get("APK Name", os.path.basename(path)),
            "Risk Score": res.get("Risk Score", 0),
            "Risk Level": res.get("Risk Level", "UNKNOWN"),
            "Permissions": res.get("Permissions", []),
            "Vulnerabilities": res.get("Vulnerabilities", [])
        }, None
    except Exception as e:
        return None, str(e)

# -------- DYNAMIC-LIKE ANALYSIS (Enhanced) --------
def dynamic_analysis(apk_path, timeout_sec=60):
    decoded_dir = f"temp/decoded_{os.path.basename(apk_path)}"
    if os.path.exists(decoded_dir):
        shutil.rmtree(decoded_dir)

    try:
        cmd = ["java", "-jar", "apktool.jar", "d", apk_path, "-o", decoded_dir, "-f"]
        subprocess.run(cmd, timeout=timeout_sec, capture_output=True)
    except subprocess.TimeoutExpired:
        return [{"file": "Error", "line": f"Command timed out after {timeout_sec} seconds", "severity": "LOW"}]
    except Exception as e:
        return [{"file": "Error", "line": str(e), "severity": "LOW"}]

    findings = []
    keywords = {
        "HIGH": ["password", "secret", "api_key", "token", "private", "access_token", "android:exported=\"true\"", "android:debuggable=\"true\"", "allowBackup=\"true\""],
        "MEDIUM": ["http://", "https://", "ftp://", "ws://"],
        "LOW": ["debug", "log", "print"]
    }

    for root, dirs, files in os.walk(decoded_dir):
        for file in files:
            if file.endswith((".xml", ".smali", ".txt")):
                fpath = os.path.join(root, file)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line_lower = line.lower()
                            for severity, keys in keywords.items():
                                for k in keys:
                                    if k in line_lower:
                                        findings.append({
                                            "file": file,
                                            "line": line.strip()[:120],
                                            "severity": severity
                                        })
                                        break
                except:
                    continue
    return findings

# -------- PAGE STATE --------
if "page" not in st.session_state:
    st.session_state.page = "landing"

# -------- STYLE (Original Design) --------
st.set_page_config(page_title="HALA-SCAN", layout="wide")
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
@keyframes fadeIn{from{opacity:0;}to{opacity:1;}}
.typing{border-right:2px solid #cbb6ff; white-space: nowrap; overflow: hidden; display:inline-block; animation: typing 2s steps(40,end) forwards, blink 0.7s infinite;}
@keyframes typing{from{width:0} to{width:380px}}
@keyframes blink{50%{border-color:transparent}}
</style>
""", unsafe_allow_html=True)

# -------- LANDING --------
if st.session_state.page == "landing":
    st.markdown("""
    <div style='text-align:center; margin-top:150px;' class='fadein'>
        <h1 style='font-size:50px; color:#cbb6ff;'>Welcome to HALA-SCAN!</h1>
        <p class='typing' style='font-size:18px; margin:auto;'>Let's make your apps safer! 🚀</p>
    </div>
    """, unsafe_allow_html=True)

    if st.button(" Start Scanning"):
        st.session_state.page = "dashboard"

# -------- DASHBOARD --------
if st.session_state.page == "dashboard":
    st.image("logo.png", width=120)
    st.title("HALA-SCAN Dashboard")

    uploaded_files = st.file_uploader("Upload APKs", type=["apk"], accept_multiple_files=True)

    results = []
    permissions_list = []

    if uploaded_files:
        loader = st.empty()
        loader.markdown("<div class='loader'></div>", unsafe_allow_html=True)
        time.sleep(1)

        for file in uploaded_files:
            path = os.path.join("temp", file.name)
            os.makedirs("temp", exist_ok=True)

            with open(path, "wb") as f:
                f.write(file.getbuffer())

            res, err = scan_apk(path)
            if err:
                st.error(err)
                continue

            findings = dynamic_analysis(path)

            res["findings"] = findings
            results.append(res)
            permissions_list.extend(res.get("Permissions", []))

        loader.empty()

    # -------- CARDS --------
    for app in results:
        risk = app["Risk Level"]
        score = app["Risk Score"]
        findings = app["findings"]

        color = "#ff4d6d" if risk == "HIGH" else "#facc15" if risk == "MEDIUM" else "#4ade80"

        high = [f for f in findings if f["severity"] == "HIGH"]
        medium = [f for f in findings if f["severity"] == "MEDIUM"]
        low = [f for f in findings if f["severity"] == "LOW"]

        def format_items(items):
            return "<br>".join([f"📄 {i['file']} ➜ {i['line']}" for i in items]) or "None found"

        st.markdown(f"""
        <div class='card fadein'>
            <h3>📱 {app['APK Name']}</h3>
            <p style='color:{color}; font-weight:bold;'>{risk} — {score}/100</p>
            <div class='progress'><div class='fill' style='width:{score}%; background:{color}'></div></div>

            <div class='tip'><b>🔴 High Risk:</b><br>{format_items(high)}</div>
            <div class='tip'><b>🟡 Medium Risk:</b><br>{format_items(medium)}</div>
            <div class='tip'><b>🟢 Low Risk:</b><br>{format_items(low)}</div>
        </div>
        """, unsafe_allow_html=True)

    # -------- CHARTS --------
    if results:
        df = pd.DataFrame(results).sort_values(by="Risk Score", ascending=False)
        st.markdown("---")
        st.subheader("Risk Scores Overview")
        st.bar_chart(df.set_index("APK Name")["Risk Score"])

    if permissions_list:
        st.markdown("---")
        st.subheader("Permissions Distribution")

        p = pd.DataFrame(permissions_list, columns=["Permission"])
        p = p["Permission"].value_counts().reset_index()
        p.columns = ["Permission", "Count"]

        fig = px.pie(p, names="Permission", values="Count",
                     color_discrete_sequence=px.colors.sequential.Purples)

        st.plotly_chart(fig)

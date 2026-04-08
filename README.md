# HALA-SCAN 🚀

**Your friendly mobile security scanner**

Hey there! HALA-SCAN is a tool I built to help you quickly check Android apps for security issues. It scans APK files, calculates a risk score, shows potential vulnerabilities, and even gives you tips to fix them. Perfect for devs, security enthusiasts, or anyone curious about app safety.

---

##  What It Does

- **Scan APKs** – Upload one or multiple APK files, and HALA-SCAN checks them for issues.  
- **Risk Score** – See if an app is **HIGH, MEDIUM, or LOW risk**.  
- **Vulnerability Analysis** – Get a breakdown of issues with:  
  - Name  
  - OWASP classification  
  - Description  
  - Suggested Solution  
- **Interactive Dashboard** – Clean and dynamic interface with:  
  - Loading animation while scanning  
  - Typing effect welcome message  
  - Fade-in + shimmer effect on results  
- **Visual Charts** – Risk scores bar chart and permissions pie chart.  
- **PDF Reports** – Download each app’s scan as a PDF.

---

##  How to Run

1. **Clone the repo:**
```bash
git clone https://github.com/rababahh492-lgtm/HALA_Security_Tool.git
cd HALA_Security_Tool

2. Create a virtual environment and install dependencies:
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt

3.Run the dashboard:
streamlit run dashboard.py
Upload APK files, wait for the analysis, check results, and download reports.

4.Run the scanner script (optional for CLI analysis):
python halasec_scan.py test_files

***** Disclaimer: HALA-SCAN is intended for educational and ethical security purposes only. Do not use it to hack apps without the owner’s permission.

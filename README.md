HALA-SCAN 🚀

Your friendly mobile security scanner

Hey there! HALA-SCAN is a tool I built to help you quickly check Android apps for security issues. It scans APK files, calculates a risk score, shows potential vulnerabilities, and even gives you tips to fix them. Perfect for devs, security enthusiasts, or anyone curious about app safety.

🌟 What It Does
Scan APKs – Upload one or multiple APK files, and HALA-SCAN checks them for issues.
Risk Score – See if an app is HIGH, MEDIUM, or LOW risk.
Vulnerability Analysis – Get a breakdown of issues with:
Name
OWASP classification
Description
Suggested Solution
Interactive Dashboard – Clean and dynamic interface with:
Loading animation while scanning
Typing effect welcome message
Fade-in + shimmer effect on results
Visual Charts – Risk scores bar chart and permissions pie chart.
PDF Reports – Download each app’s scan as a PDF.
🛠 How to Run
Clone the repo:
git clone https://github.com/rababahh492-lgtm/HALA_Security_Tool.git
cd HALA_Security_Tool
Create a virtual environment and install dependencies:
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt

Run the dashboard:
streamlit run dashboard.py
Upload APK files, wait for the analysis, check results, and download reports.

Run the script halasec_scan <apk files name>:
python halasec_scan.py test_files 

 Sample Output:
App Name: MyApp.apk
Risk Score: 78/100 (HIGH)
Vulnerabilities:
Insecure Data Storage (M2) – Sensitive data is stored unencrypted. Solution: Encrypt it!
Improper Platform Usage (M4) – Using HTTP instead of HTTPS. Solution: Use HTTPS + pinning.
Permissions: INTERNET, CAMERA, LOCATION, READ_CONTACTS

(All results appear with animated effects in the dashboard.)

Future Improvements:
Adding iOS support is on the roadmap to make the scanner cross-platform.
Eventually, we want to make it multi-user, with secure logins and a full dashboard for team management.

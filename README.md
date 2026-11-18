# 🛡️TONIX-HTTPS 

AI-Powered Website Security Scanner & Vulnerability Analysis Tool

<p align="center">
  <b>Advanced Web Security • AI-Powered Analysis • Comprehensive Reporting</b>
</p><p align="center">
  <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python">
  <img src="https://img.shields.io/badge/Platform-Termux%20%7C%20Kali%20Linux-green">
  <img src="https://img.shields.io/badge/AI-Google%20Gemini-orange">
</p>---

## 📌 1. Introduction

TONIX-HTTPS is an advanced AI-powered web security assessment tool designed to scan authorized websites for potential security vulnerabilities and generate comprehensive security reports.

Powered by Python and Google Gemini AI, TONIX-HTTPS helps security researchers, developers, and website administrators understand security findings, prioritize risks, and identify practical remediation strategies.

## ✨ Key Features

- 🔍 Automated website security scanning.
- 🤖 Google Gemini AI-powered vulnerability analysis.
- 📊 Comprehensive vulnerability summaries.
- ⚠️ Top security risks identification.
- ⚡ Quick Wins and remediation recommendations.
- 💬 Interactive AI chat.
- 📄 Web Owner Reports (MD, HTML, JSON).
- 🐛 Bug-Bounty Submission Reports.
- 📦 Generate All Reports.
- 🔄 Re-run AI analysis.
- 🌐 Scan multiple authorized targets.

## 📥 3. Installation Guide

📱 A. Termux Installation (Android)

🔘Step 1:  Update packages
```
pkg update && pkg upgrade -y
```
🔘Step 2: Install dependencies
```
pkg install python git -y
```
🔘Step 3: Clone TONIX-HTTPS
```
git clone https://github.com/tonixtoolkitofficial-afk/TONIX-HTTPS.git
```
🔘Step 4: Enter project directory
```
cd TONIX-HTTPS
```
🔘Step 5: Install Python requirements
```
pip install -r requirements.txt
```
🔘Step 6: Run the application
```
python main.py
```
---

## 🐉 B. Kali Linux Installation

🔘Step 1: Update system
```
sudo apt update && sudo apt upgrade -y
```
🔘Step 2: Install dependencies
```
sudo apt install python3 python3-pip python3-venv git -y
```
🔘Step 3: Clone repository
```
git clone https://github.com/tonixtoolkitofficial-afk/TONIX-HTTPS.git
```
🔘Step 4: Enter project directory
```
cd TONIX-HTTPS
```
🔘Step 5: Create virtual environment
```
python3 -m venv venv
source venv/bin/activate
```
🔘Step 6: Install requirements
```
pip install -r requirements.txt
```
🔘Step 7: Run TONIX-HTTPS
```
python3 main.py
```
«Note: The commands assume the project uses "main.py" as its entry point. Confirm the actual filename in the repository before running.»

---

### 🔑 4. Gemini API Configuration

TONIX-HTTPS uses Google Gemini AI for intelligent security analysis.

1. Visit https://aistudio.google.com/
2. Obtain a Gemini API key.
3. Launch TONIX-HTTPS.
4. Enter your API key when prompted.
5. Keep your API key private.

Never upload API credentials to GitHub.

---

### 🚀 5. Usage Guide

After installation, launch the application:
```
python main.py
```
Target Website Configuration

Enter the target website URL when prompted.

Example:

[http://www.example.com]
Enter your target URL example [https://www.nasa.com]

Only scan websites you own or have explicit permission to assess.

Automated Security Scanning

TONIX-HTTPS performs its implemented security checks against the supplied target and collects relevant findings.

AI-Powered Analysis

The scan results are provided to Google Gemini AI for analysis.

AI helps interpret findings, explain potential security implications, prioritize risks, and recommend remediation strategies.

---

### 📊 6. Scan Results

After scanning and AI analysis, the application presents an organized security assessment.

A. Vulnerability Summary

Provides an overview of identified findings, potentially including:

- Critical vulnerabilities.
- High-risk findings.
- Medium-risk findings.
- Low-risk findings.
- Informational observations.

B. Top Security Risks

Highlights important findings and their potential impact, with remediation recommendations.

C. Quick Wins ⚡

Provides practical website security improvements, such as:

- Improving HTTP security headers.
- Reviewing cookie security settings.
- Correcting HTTPS configuration issues.
- Removing unnecessary information disclosure.
- Updating outdated software components.

D. AI Recommendations

Gemini AI provides explanations and suggestions based on the available scan results.

AI-generated findings must be independently verified.

---

###  🎮 7. Interactive Menu

After the scan, TONIX-HTTPS provides an interactive menu.

1. 💬 Chat with AI

Interact with Gemini AI using scan results as context.

- Ask questions about vulnerabilities.
- Understand technical findings.
- Request remediation explanations.
- Get additional security recommendations.

2. 📄 Web Owner Report

Generate professional reports for website owners.

Supported formats:

Format| Description
MD| Markdown report
HTML| Browser-friendly report
JSON| Structured machine-readable report

Reports can include executive summaries, vulnerability details, severity classifications, and remediation recommendations.

3. 🐛 Bug-Bounty Submission Report

Generate structured vulnerability disclosure documentation.

Potential report sections include:

- Vulnerability title.
- Affected URL.
- Description.
- Severity.
- Potential impact.
- Supporting evidence.
- Recommended remediation.

Always validate findings and follow the relevant bug-bounty program's rules before submission.

4. 📦 Generate All Reports

Generate all available report formats in one operation.

- Web Owner MD Report.
- Web Owner HTML Report.
- Web Owner JSON Report.
- Bug-Bounty Submission Report.

5. 🔄 Re-run AI Analysis

Run Gemini AI analysis again using existing scan findings.

This allows users to obtain another interpretation without necessarily performing a new scan.

6. 🌐 Scan Other Target

Start a new assessment against another authorized website without restarting the application.

7. 🚪 Exit

Exit TONIX-HTTPS safely.

---

### 📁 8. Project Structure

Illustrative structure (actual filenames depend on the repository):
```
TONIX-HTTPS/
│
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
│
├── scanner/
├── ai/
├── reports/
└── output/
```
---

### 🛠️ 9. Technologies Used

Technology| Purpose
Python| Core application
Git| Repository management
Google Gemini AI| AI analysis
Termux| Android environment
Kali Linux| Linux security environment
Markdown| Documentation
HTML| Report generation
JSON| Structured reports

---

### 🔧 10. Troubleshooting

#### Python Not Found

🔴Termux:
```
pkg install python -y
```
🔴Kali Linux:
```
sudo apt install python3 -y
```
#### Git Not Found

🔴Termux:
```
pkg install git -y
```
🔴Kali Linux:
```
sudo apt install git -y
```
🟢Missing Dependencies
```
pip install -r requirements.txt
```
### Gemini API Error

- Verify your API key.
- Check internet connectivity.
- Check API access and usage limits.
- Confirm the API key is configured correctly.

---

## 🔐 11. Security & Responsible Usage

TONIX-HTTPS is intended for educational, defensive, and authorized security assessments.

Users must:

1. Scan only authorized targets.
2. Respect bug-bounty scope restrictions.
3. Avoid disrupting website operations.
4. Protect API keys and sensitive information.
5. Verify findings before reporting.
6. Follow responsible disclosure practices.

Unauthorized testing may violate applicable laws or website policies.

---

### 🤝 12. Contributions

Contributions and suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Implement your changes.
4. Test your modifications.
5. Submit a pull request.

---

### 📜 13. License

See the repository's LICENSE file for applicable licensing terms.

---

###  ⭐ 14. Support & Feedback

If you find TONIX-HTTPS useful:

- ⭐ Star the GitHub repository.
- 🐛 Report bugs.
- 💡 Suggest new features.
- 🤝 Contribute improvements.

GitHub Repository:

[https://github.com/tonixtoolkitofficial-afk/TONIX-HTTPS]

---

<p align="center">🛡️ TONIX-HTTPS

Scan Smart. Analyze Deeply. Secure Better.

Powered by Python & Google Gemini AI

</p>---

### Disclaimer⚠️:*TONIX-HTTPS is provided for educational, defensive, and authorized security assessment purposes. It does not guarantee complete website security. Users are responsible for ensuring their testing activities are authorized.*
--------------
🎉 Done!

*Your project is now ready to install, configure, and run from Termux.
Happy Coding!* 🚀
--
##### develaper:@tonix

 DeepDomain v2.0 — Advanced Subdomain Enumeration Tool

╔══════════════════════════════════════════════════════════════╗
║ DeepDomain v2.0 ║
║ Advanced Subdomain Enumeration Tool ║
║ ║
║ 🔍 DNS Brute Force 📜 Certificate Transparency ║
║ 🌐 API Integration 🔍 HTTP Fingerprinting ║
║ ║
║ Created by: Soheil Manna ║
║ Open Source - Contributions Welcome ║
╚══════════════════════════════════════════════════════════════╝



DeepDomain is a powerful subdomain enumeration tool designed for red teams, researchers, and professional bug bounty hunters. It combines multiple techniques to discover and fingerprint subdomains efficiently and effectively.

---

##  Features

- 🔍 **DNS brute-force** with smart wordlists  
- 📜 **Certificate Transparency** parsing  
- 🌐 **API integration** with 3rd-party services  
- 🧠 **HTTP fingerprinting** for discovered subdomains  
- ⚡ **Fast mode** (lightweight DNS only)  
- 🧬 **Deep mode** (brute-force + APIs + CT logs)  
- 📂 Organized output and threading control  
- 🖥️ Clean terminal interface

---

## 📦 Installation

```bash
git clone https://github.com/roger054/DeepDomain.git
cd DeepDomain
pip install -r requirements.txt
✅ Python 3.x required
✅ Compatible with Linux, Windows (py instead of python), and macOS

⚡ Quick Usage
bash

py deepdomain.py example.com              # Basic scan
py deepdomain.py example.com --fast       # Fast scan
py deepdomain.py example.com --deep       # Deep scan
py deepdomain.py example.com --no-save    # Don't save results
🔧 Options
Flag / Option	Description
domain	Target domain (e.g., example.com)
--fast	Fast scan (DNS only, 22 prefixes)
--deep	Deep scan (all techniques, 252+ prefixes)
-t, --threads	Number of threads (default: 50)
--no-save	Don’t save results to output directory
-o, --output	Output directory (default: output)
--version	Show tool version
-h, --help	Show help and exit

📂 Output
Results will be saved in an output/ folder by default, including:

Discovered subdomains

Status codes, titles, technologies

CVE and risk assessments

DNS and fingerprinting data

 Author
Soheil Manna
GitHub: @roger054
Open Source — Contributions Welcome 
License: MIT

🛡️ Disclaimer
This tool is intended for authorized security testing and research purposes only.
Using DeepDomain on networks or domains without permission is illegal and unethical.




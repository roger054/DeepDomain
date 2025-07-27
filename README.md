DeepDomain
Advanced Subdomain Enumeration Tool

DeepDomain is a powerful and flexible open-source tool designed to perform comprehensive subdomain enumeration. It integrates multiple techniques including DNS brute forcing, certificate transparency logs, API data sources, and HTTP fingerprinting to discover and verify subdomains efficiently.

Features
🔍 DNS Brute Force: Perform high-speed subdomain enumeration using custom wordlists.

📜 Certificate Transparency Logs: Leverage public CT logs to find issued certificates linked to your target domains.

🌐 API Integration: Use external APIs for enriched domain discovery and verification.

🔍 HTTP Fingerprinting: Identify live hosts and technologies used by discovered subdomains.

⚡ Fast and Customizable: Easily configure wordlists, APIs, and scanning options to fit your recon needs.

Installation
bash
git clone https://github.com/roger054/DeepDomain.git
cd DeepDomain
pip install -r requirements.txt
py install.py
Usage
Basic usage example:

bash

py deepdomain.py -d example.com -w subdomains.txt
Options include specifying wordlists, output formats, and scan types. See the Wiki for detailed documentation.

Requirements
Python 3.8+

Dependencies listed in requirements.txt

Contributing
Contributions and improvements are welcome! Feel free to fork the repo, submit pull requests, or open issues with feature requests or bug reports.

License
This project is licensed under the MIT License — see the LICENSE file for details.

Contact
Created by Soheil Manna - @roger054 — reach out for support or collaboration.

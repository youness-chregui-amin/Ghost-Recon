# GhostRecon

## Tool Overview

**GhostRecon** is a stealthy, intelligent Python CLI tool for passive reconnaissance (OSINT) and ethical hacking. Designed for security professionals and researchers, GhostRecon enables you to map, analyze, and assess target infrastructure without direct contact, using a modular, AI-powered approach. It features both passive OSINT and stealthy attack modes, with encrypted result storage and a polished, user-friendly interface.

---

## Key Features

### OSINT Mode (Passive Reconnaissance)
- **Subdomain Enumeration**: Integrates crt.sh, Sublist3r, Subfinder, Amass (passive), VirusTotal, DNSDumpster, ViewDNS, and DNS brute-forcing (custom wordlist support).
- **Archived Data**: Wayback Machine for historical URLs and JavaScript analysis.
- **DNS & IP Intelligence**: DNSDumpster, ViewDNS (Whois, Reverse IP), and more.
- **Email Discovery**: Hunter.io scraping for public emails.
- **Malware Indicators**: ThreatFox integration.
- **AI Analysis**: Predicts additional subdomains and extracts secrets from discovered endpoints.
- **GitHub Recon**: Scans public code for secrets, endpoints, and subdomains.
- **Encrypted Storage**: All results are saved in encrypted JSON files.
- **Customizable DNS Brute-force**: Use your own wordlist for targeted subdomain brute-forcing.

### Attack Mode (Stealth Offensive)
- **Endpoint Probing**: Stealthily scan common sensitive endpoints.
- **Proxy Rotation**: Rotate proxies per request for anonymity.
- **Header & Cookie Injection**: Custom headers and cookies for advanced testing.
- **Session Memory & Replay**: Save and replay full attack sessions.
- **Error & Secret Detection**: AI-powered response analysis for secrets and vulnerabilities.
- **JavaScript Analysis**: Extract endpoints and secrets from JS files.
- **Threading & Randomization**: Random delays, user-agents, and threading for stealth.
- **Encrypted Results**: All attack findings are securely stored.

---

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)
- [Sublist3r](https://github.com/aboul3la/Sublist3r), [subfinder](https://github.com/projectdiscovery/subfinder), [amass](https://github.com/owasp-amass/amass) (install and add to PATH)
- (Optional) theHarvester, dnspython, and other tools for extended features

### Install Python Dependencies
```bash
pip install -r requirements.txt
```

### Install External Tools
- **Sublist3r**: `git clone https://github.com/aboul3la/Sublist3r.git && cd Sublist3r && pip install -r requirements.txt`
- **subfinder**: [Download binary](https://github.com/projectdiscovery/subfinder/releases) and add to PATH
- **amass**: [Download binary](https://github.com/owasp-amass/amass/releases) and add to PATH

---

## Usage Guide

### Interactive Mode
Run GhostRecon and follow the prompts:
```bash
python3 -m ghostrecon.cli
```

### Example: OSINT Mode
```bash
python3 -m ghostrecon.cli
# Select OSINT Mode
# Enter target domain, output file, and password
# Choose features (e.g., Sublist3r, Subfinder, DNS Brute-force, etc.)
# For DNS Brute-force, you can provide a custom wordlist file
```

### Example: Attack Mode
```bash
python3 -m ghostrecon.cli
# Select Attack Mode
# Enter target domain, output file, and password
# Configure proxies, headers, cookies, and session export as needed
```

### Viewing Results
To decrypt and view results:
```bash
python3 -m ghostrecon.view_results <encrypted_results.json>
```

---

## Customization / Developer Guide

- **Modular Design**: Add new data sources by creating a module in `ghostrecon/data_sources/` and integrating it in `cli.py`.
- **Analyzer Modules**: Add new analyzers in `ghostrecon/analyzers/` for custom data processing.
- **Feature Menu**: Update `osint_feature_menu` and `attack_feature_menu` in `cli.py` to expose new features.
- **Custom Wordlists**: Place your wordlist file anywhere and provide its path when prompted in OSINT mode.
- **API Keys**: For sources requiring API keys (e.g., VirusTotal, Shodan, ViewDNS), set them in the respective data source modules or pass as arguments.

---

## Author

**Youness Chregui Amin** - [GitHub](https://github.com/youness-chregui-amin)

---

## License

*Add your license information here (e.g., MIT, GPL, etc.)* # Ghost-Recon
# Ghost-Recon

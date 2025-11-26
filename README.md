# Bug Bounty Hunting Toolkit 🎯
[![CI](https://github.com/z0uz/bugbounty/actions/workflows/ci.yml/badge.svg)](https://github.com/z0uz/bugbounty/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/tag/z0uz/bugbounty?label=release)](https://github.com/z0uz/bugbounty/tags)

A comprehensive AI-enhanced toolkit for ethical bug bounty hunting on platforms like Bugcrowd and HackerOne.

## 🤖 NEW: AI-Powered Features

This toolkit now includes **Ollama Cloud AI integration** for:
- 🧠 Intelligent vulnerability analysis
- 🎯 False positive detection
- 📊 AI-generated reports
- 🔍 JavaScript code analysis
- 💡 Context-aware payload suggestions

**[📖 See AI Features Documentation](AI_FEATURES.md)** | **[🚀 Quick Setup Guide](OLLAMA_SETUP.md)**

## ⚠️ IMPORTANT LEGAL NOTICE

**ONLY use these tools on:**
- Programs you have explicit permission to test
- Targets listed in bug bounty programs you've joined
- Your own systems for practice

**Unauthorized testing is ILLEGAL and can result in criminal charges.**

## 🎯 Project Structure

```
bug_bounty_toolkit/
├── recon/              # Reconnaissance tools
├── scanners/           # Vulnerability scanners
├── exploits/           # Proof of concept scripts
├── reports/            # Report templates
├── wordlists/          # Custom wordlists
├── results/            # Scan results (gitignored)
└── tools/              # Utility scripts
```

## 🚀 Quick Start

### Traditional Mode (No AI)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run vulnerability scan:**
   ```bash
   python tools/vulnerability_scanner.py -t target.com
   # Include a quick port scan during reconnaissance (optional)
   python tools/vulnerability_scanner.py -t target.com --port-scan-mode quick --port-scan-threads 200
   ```

### AI-Enhanced Mode (Recommended)

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure Ollama Cloud:**
   ```bash
   cp .env.example .env
   # Edit .env and add your OLLAMA_API_KEY
   ```
   
   **[Get your API key and setup instructions →](OLLAMA_SETUP.md)**

3. **Run AI-enhanced scan:**
   ```bash
   python tools/ai_vulnerability_scanner.py -t target.com
   ```

4. **Generate AI report:**
   ```bash
   python reports/ai_report_generator.py -i results/target.com_ai_comprehensive_report.json
   ```

## 🔍 Methodology

### Phase 1: Reconnaissance
- Subdomain enumeration
- Port scanning
- Technology fingerprinting
- Directory/file discovery
- Parameter discovery
- JavaScript analysis

### Phase 2: Vulnerability Scanning
- XSS (Cross-Site Scripting)
- SQL Injection
- CSRF (Cross-Site Request Forgery)
- SSRF (Server-Side Request Forgery)
- Open Redirects
- Authentication bypasses
- API vulnerabilities
- File upload vulnerabilities

### Phase 3: Exploitation & Reporting
- Proof of concept development
- Impact assessment
- Professional report writing

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)
- [Bugcrowd University](https://www.bugcrowd.com/hackers/bugcrowd-university/)

## 🛠️ Tools Included

### Core Scanners
- **Reconnaissance**: Subdomain finder, port scanner, tech detector
- **Scanners**: XSS, SQLi, SSRF, open redirect detectors
- **Utilities**: Request interceptor, payload generator, report builder

### AI-Enhanced Tools ✨
- **AI Vulnerability Scanner**: Comprehensive scanner with AI analysis
- **AI XSS Scanner**: JavaScript analysis with DOM XSS detection
- **AI Report Generator**: Beautiful reports with AI insights
- **AI Analyzer**: Standalone AI analysis tool
- **False Positive Detector**: Automatic FP detection with confidence scoring

## 📝 Reporting

### Traditional Reports
Use the templates in `reports/` to create professional vulnerability reports.

### AI-Enhanced Reports ✨
Generate comprehensive reports with:
- Executive summaries in natural language
- AI-powered vulnerability analysis
- Exploitability scoring
- False positive warnings
- Beautiful HTML reports
- Prioritized recommendations

```bash
python reports/ai_report_generator.py -i results/scan_results.json
```

## 🔐 Ethics & Responsibility

- Always follow the bug bounty program's scope
- Never access or modify data you don't own
- Report vulnerabilities responsibly
- Don't perform DoS attacks
- Respect rate limits and system resources

## 📄 License

For educational and authorized security testing only.

#!/usr/bin/env python3
"""
Vulnerability Report Generator
Creates professional bug bounty reports
"""

import argparse
from datetime import datetime
from colorama import Fore, Style, init
import os

init(autoreset=True)

class ReportGenerator:
    def __init__(self, output_dir: str = "./reports"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def generate_report(self, vuln_data: dict) -> str:
        """Generate a professional vulnerability report"""
        
        report = f"""# Vulnerability Report: {vuln_data['title']}

## Executive Summary

**Vulnerability Type:** {vuln_data['type']}  
**Severity:** {vuln_data['severity']}  
**Reported By:** {vuln_data.get('reporter', 'Security Researcher')}  
**Date Discovered:** {vuln_data.get('date', datetime.now().strftime('%Y-%m-%d'))}  
**Status:** {vuln_data.get('status', 'New')}

---

## Vulnerability Details

### Description

{vuln_data['description']}

### Affected Components

- **URL:** `{vuln_data['url']}`
- **Parameter:** `{vuln_data.get('parameter', 'N/A')}`
- **Method:** {vuln_data.get('method', 'GET')}

---

## Steps to Reproduce

{vuln_data.get('steps', '1. Navigate to the vulnerable endpoint\\n2. Submit the payload\\n3. Observe the result')}

### Proof of Concept

```
{vuln_data.get('payload', 'N/A')}
```

### Request/Response

**Request:**
```http
{vuln_data.get('request', 'N/A')}
```

**Response:**
```http
{vuln_data.get('response', 'N/A')}
```

---

## Impact Assessment

### Security Impact

{vuln_data.get('impact', 'This vulnerability could allow an attacker to compromise the security of the application.')}

### CVSS Metrics

- **Attack Vector:** {vuln_data.get('attack_vector', 'Network')}
- **Attack Complexity:** {vuln_data.get('attack_complexity', 'Low')}
- **Privileges Required:** {vuln_data.get('privileges_required', 'None')}
- **User Interaction:** {vuln_data.get('user_interaction', 'None')}
- **Scope:** {vuln_data.get('scope', 'Unchanged')}
- **Confidentiality Impact:** {vuln_data.get('confidentiality', 'High')}
- **Integrity Impact:** {vuln_data.get('integrity', 'High')}
- **Availability Impact:** {vuln_data.get('availability', 'None')}

---

## Remediation

### Recommended Fix

{vuln_data.get('remediation', 'Implement proper input validation and output encoding.')}

### Code Example

```python
{vuln_data.get('fix_example', '# Implement security controls here')}
```

---

## References

{vuln_data.get('references', '- OWASP Top 10\\n- CWE Database\\n- Security Best Practices')}

---

## Timeline

- **{datetime.now().strftime('%Y-%m-%d')}:** Vulnerability discovered and reported

---

**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return report
    
    def save_report(self, report: str, filename: str):
        """Save report to file"""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[+] Report saved to: {filepath}{Style.RESET_ALL}")
        return filepath
    
    def create_quick_report(self):
        """Interactive report creation"""
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Quick Vulnerability Report Generator{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
        
        vuln_data = {}
        
        # Collect information
        vuln_data['title'] = input(f"{Fore.YELLOW}Vulnerability Title: {Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Vulnerability Type:{Style.RESET_ALL}")
        print("1. XSS (Cross-Site Scripting)")
        print("2. SQL Injection")
        print("3. CSRF")
        print("4. SSRF")
        print("5. Authentication Bypass")
        print("6. Other")
        
        type_choice = input(f"{Fore.YELLOW}Select type (1-6): {Style.RESET_ALL}")
        types = {
            '1': 'XSS (Cross-Site Scripting)',
            '2': 'SQL Injection',
            '3': 'CSRF (Cross-Site Request Forgery)',
            '4': 'SSRF (Server-Side Request Forgery)',
            '5': 'Authentication Bypass',
            '6': input(f"{Fore.YELLOW}Specify type: {Style.RESET_ALL}")
        }
        vuln_data['type'] = types.get(type_choice, 'Unknown')
        
        print(f"\n{Fore.CYAN}Severity:{Style.RESET_ALL}")
        print("1. Critical")
        print("2. High")
        print("3. Medium")
        print("4. Low")
        
        severity_choice = input(f"{Fore.YELLOW}Select severity (1-4): {Style.RESET_ALL}")
        severities = {'1': 'Critical', '2': 'High', '3': 'Medium', '4': 'Low'}
        vuln_data['severity'] = severities.get(severity_choice, 'Medium')
        
        vuln_data['url'] = input(f"\n{Fore.YELLOW}Vulnerable URL: {Style.RESET_ALL}")
        vuln_data['parameter'] = input(f"{Fore.YELLOW}Vulnerable Parameter: {Style.RESET_ALL}")
        vuln_data['description'] = input(f"{Fore.YELLOW}Description: {Style.RESET_ALL}")
        vuln_data['payload'] = input(f"{Fore.YELLOW}Payload/PoC: {Style.RESET_ALL}")
        vuln_data['impact'] = input(f"{Fore.YELLOW}Impact: {Style.RESET_ALL}")
        vuln_data['remediation'] = input(f"{Fore.YELLOW}Recommended Fix: {Style.RESET_ALL}")
        
        # Generate report
        report = self.generate_report(vuln_data)
        
        # Save report
        filename = f"{vuln_data['title'].replace(' ', '_').lower()}_{datetime.now().strftime('%Y%m%d')}.md"
        self.save_report(report, filename)
        
        print(f"\n{Fore.GREEN}[+] Report generated successfully!{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="Vulnerability Report Generator")
    parser.add_argument("-o", "--output", default="./reports", help="Output directory")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    
    args = parser.parse_args()
    
    generator = ReportGenerator(args.output)
    
    if args.interactive:
        generator.create_quick_report()
    else:
        print(f"{Fore.YELLOW}Use -i or --interactive for interactive report generation{Style.RESET_ALL}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AI-Enhanced Vulnerability Report Generator
Creates professional bug bounty reports with AI-generated summaries and insights
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import argparse
import json
from datetime import datetime
from colorama import Fore, Style, init
from typing import Dict, List, Any
from tools.ai_analyzer import OllamaAnalyzer

init(autoreset=True)


class AIReportGenerator:
    def __init__(self, output_dir: str = "./reports", use_ai: bool = True):
        self.output_dir = output_dir
        self.use_ai = use_ai
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize AI analyzer if enabled
        self.ai_analyzer = None
        if self.use_ai:
            try:
                self.ai_analyzer = OllamaAnalyzer()
                print(f"{Fore.GREEN}[+] AI report generation enabled{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] AI disabled: {str(e)}{Style.RESET_ALL}")
                self.use_ai = False
    
    def generate_executive_summary(self, scan_results: Dict[str, Any]) -> str:
        """Generate AI-powered executive summary"""
        if self.use_ai and self.ai_analyzer:
            print(f"{Fore.CYAN}[AI] Generating executive summary...{Style.RESET_ALL}")
            return self.ai_analyzer.generate_executive_summary(scan_results)
        else:
            # Fallback to template-based summary
            vuln_count = len(scan_results.get('vulnerabilities', []))
            critical = sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'Critical')
            high = sum(1 for v in scan_results.get('vulnerabilities', []) if v.get('severity') == 'High')
            
            return f"""This security assessment identified {vuln_count} potential vulnerabilities, 
including {critical} critical and {high} high severity issues. Immediate attention is recommended 
for critical findings to prevent potential security breaches."""
    
    def generate_vulnerability_report(self, vuln_data: Dict[str, Any]) -> str:
        """Generate a professional vulnerability report with AI insights"""
        
        # Get AI analysis if available
        ai_section = ""
        if vuln_data.get('ai_analysis'):
            ai_analysis = vuln_data['ai_analysis']
            ai_section = f"""
### AI Analysis

**Exploitability Score:** {ai_analysis.get('exploitability_score', 'N/A')}/10  
**Confidence:** {vuln_data.get('false_positive_check', {}).get('confidence', 'N/A')}%  
**False Positive Risk:** {'Yes' if vuln_data.get('false_positive_check', {}).get('is_false_positive') else 'No'}

**Impact Assessment:**
{ai_analysis.get('impact', 'Not available')}

**AI Recommendations:**
{ai_analysis.get('remediation', 'Not available')}
"""
        
        report = f"""# Vulnerability Report: {vuln_data.get('type', 'Unknown')}

## Executive Summary

**Vulnerability Type:** {vuln_data.get('type', 'Unknown')}  
**Severity:** {vuln_data.get('severity', 'Unknown')}  
**Reported By:** {vuln_data.get('reporter', 'Security Researcher')}  
**Date Discovered:** {vuln_data.get('date', datetime.now().strftime('%Y-%m-%d'))}  
**Status:** {vuln_data.get('status', 'New')}

---

## Vulnerability Details

### Description

{vuln_data.get('description', 'A security vulnerability was identified in the application.')}

### Affected Components

- **URL:** `{vuln_data.get('url', 'N/A')}`
- **Parameter:** `{vuln_data.get('parameter', 'N/A')}`
- **Method:** {vuln_data.get('method', 'GET')}

{ai_section}

---

## Steps to Reproduce

{vuln_data.get('steps', '1. Navigate to the vulnerable endpoint\\n2. Submit the payload\\n3. Observe the result')}

### Proof of Concept

```
{vuln_data.get('payload', 'N/A')}
```

### Evidence

```
{vuln_data.get('evidence', 'N/A')[:500]}
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
**AI-Enhanced:** {'Yes' if self.use_ai else 'No'}
"""
        
        return report
    
    def generate_comprehensive_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate comprehensive scan report with AI insights"""
        
        target = scan_results.get('target', 'Unknown')
        scan_date = scan_results.get('scan_date', datetime.now().isoformat())
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Generate executive summary with AI
        exec_summary = self.generate_executive_summary(scan_results)
        
        # Count vulnerabilities by severity
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'Low')
        
        # Count AI-specific metrics
        ai_detected = sum(1 for v in vulnerabilities if v.get('ai_detected'))
        false_positives = sum(1 for v in vulnerabilities 
                             if v.get('false_positive_check', {}).get('is_false_positive'))
        
        report = f"""# Comprehensive Security Assessment Report

## Target Information

**Target:** {target}  
**Scan Date:** {scan_date}  
**Report Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**AI Analysis:** {'Enabled' if self.use_ai else 'Disabled'}

---

## Executive Summary

{exec_summary}

---

## Vulnerability Summary

### Overall Statistics

- **Total Vulnerabilities:** {len(vulnerabilities)}
- **Critical:** {critical}
- **High:** {high}
- **Medium:** {medium}
- **Low:** {low}

### AI Analysis Statistics

- **AI-Detected Vulnerabilities:** {ai_detected}
- **Potential False Positives:** {false_positives}
- **Manually Verified:** {len(vulnerabilities) - ai_detected}

---

## Detailed Findings

"""
        
        # Add each vulnerability
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity_color = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🟢'
            }.get(vuln.get('severity', 'Unknown'), '⚪')
            
            report += f"""
### {idx}. {severity_color} {vuln.get('type', 'Unknown Vulnerability')}

**Severity:** {vuln.get('severity', 'Unknown')}  
**URL:** `{vuln.get('url', 'N/A')}`  
**Parameter:** `{vuln.get('parameter', 'N/A')}`  
**Method:** {vuln.get('method', 'GET')}

"""
            
            # Add AI analysis if available
            if vuln.get('ai_analysis'):
                ai_analysis = vuln['ai_analysis']
                report += f"""**AI Exploitability Score:** {ai_analysis.get('exploitability_score', 'N/A')}/10

**Impact:**
{ai_analysis.get('impact', 'Not available')}

"""
            
            # Add false positive warning
            if vuln.get('false_positive_check', {}).get('is_false_positive'):
                fp_check = vuln['false_positive_check']
                report += f"""
⚠️ **Potential False Positive** ({fp_check.get('confidence', 0)}% confidence)
*Reason:* {fp_check.get('reason', 'Unknown')}

"""
            
            report += f"""**Payload:**
```
{vuln.get('payload', 'N/A')}
```

**Evidence:**
```
{str(vuln.get('evidence', 'N/A'))[:300]}...
```

---

"""
        
        # Add reconnaissance results
        recon = scan_results.get('reconnaissance', {})
        if recon:
            report += f"""
## Reconnaissance Results

### Discovered Assets

- **Subdomains:** {len(recon.get('subdomains', []))}
- **Directories/Files:** {len(recon.get('directories', []))}
- **Technologies Detected:** {len(recon.get('technologies', []))}

"""
            
            if recon.get('technologies'):
                report += "### Technology Stack\n\n"
                for tech in recon.get('technologies', [])[:10]:
                    report += f"- {tech}\n"
                report += "\n"
        
        # Add JavaScript analysis results if available
        js_analysis = scan_results.get('javascript_analysis', [])
        if js_analysis:
            report += f"""
## JavaScript Security Analysis

**Total Scripts Analyzed:** {len(js_analysis)}

"""
            for idx, analysis in enumerate(js_analysis[:5], 1):
                if analysis.get('vulnerabilities'):
                    report += f"""
### Script {idx}: {analysis.get('url', 'Unknown')}

**Risk Level:** {analysis.get('risk_level', 'Unknown')}  
**Vulnerabilities Found:** {len(analysis.get('vulnerabilities', []))}

"""
                    for vuln in analysis.get('vulnerabilities', [])[:3]:
                        report += f"- {vuln.get('description', 'Unknown issue')}\n"
                    report += "\n"
        
        # Add recommendations
        report += """
---

## Recommendations

### Immediate Actions (Critical/High)

1. **Address Critical Vulnerabilities:** Prioritize fixing all critical severity issues immediately
2. **Implement Input Validation:** Ensure all user inputs are properly validated and sanitized
3. **Enable Security Headers:** Implement CSP, X-Frame-Options, and other security headers
4. **Review Authentication:** Strengthen authentication and session management

### Short-term Actions (Medium)

1. **Code Review:** Conduct thorough code review of affected components
2. **Security Testing:** Implement automated security testing in CI/CD pipeline
3. **Update Dependencies:** Ensure all third-party libraries are up to date
4. **Security Training:** Provide security awareness training to development team

### Long-term Actions (Low)

1. **Security Architecture:** Review and improve overall security architecture
2. **Monitoring:** Implement security monitoring and logging
3. **Incident Response:** Develop incident response procedures
4. **Regular Assessments:** Schedule regular security assessments

---

## Conclusion

This assessment identified multiple security vulnerabilities that require attention. The AI-enhanced analysis 
has helped prioritize findings and reduce false positives, allowing the security team to focus on the most 
critical issues first.

**Next Steps:**
1. Review and validate all findings
2. Prioritize remediation based on severity and exploitability
3. Implement fixes and conduct regression testing
4. Schedule follow-up assessment to verify fixes

---

**Report Generated By:** Bug Bounty Toolkit with Ollama Cloud AI  
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        return report
    
    def save_report(self, report: str, filename: str) -> str:
        """Save report to file"""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[+] Report saved to: {filepath}{Style.RESET_ALL}")
        return filepath
    
    def generate_from_scan_results(self, results_file: str):
        """Generate report from scan results JSON file"""
        print(f"{Fore.CYAN}[*] Loading scan results from {results_file}{Style.RESET_ALL}")
        
        try:
            with open(results_file, 'r') as f:
                scan_results = json.load(f)
            
            # Generate comprehensive report
            report = self.generate_comprehensive_report(scan_results)
            
            # Save report
            target = scan_results.get('target', 'unknown').replace('http://', '').replace('https://', '').replace('/', '_')
            filename = f"{target}_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            self.save_report(report, filename)
            
            # Also save HTML version
            html_report = self.generate_html_report(scan_results)
            html_filename = filename.replace('.md', '.html')
            self.save_report(html_report, html_filename)
            
            print(f"{Fore.GREEN}[+] Reports generated successfully!{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error generating report: {str(e)}{Style.RESET_ALL}")
    
    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML version of the report"""
        target = scan_results.get('target', 'Unknown')
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Count severities
        critical = sum(1 for v in vulnerabilities if v.get('severity') == 'Critical')
        high = sum(1 for v in vulnerabilities if v.get('severity') == 'High')
        medium = sum(1 for v in vulnerabilities if v.get('severity') == 'Medium')
        low = sum(1 for v in vulnerabilities if v.get('severity') == 'Low')
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Security Report - {target}</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            margin: 0; 
            padding: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }}
        h1 {{ 
            color: #2d3748; 
            border-bottom: 4px solid #667eea; 
            padding-bottom: 15px;
            margin-top: 0;
        }}
        h2 {{ 
            color: #4a5568; 
            margin-top: 40px;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .stat-card h3 {{ margin: 0; font-size: 36px; }}
        .stat-card p {{ margin: 10px 0 0 0; opacity: 0.9; }}
        .critical {{ background: linear-gradient(135deg, #dc3545 0%, #c82333 100%); }}
        .high {{ background: linear-gradient(135deg, #fd7e14 0%, #e8590c 100%); }}
        .medium {{ background: linear-gradient(135deg, #ffc107 0%, #e0a800 100%); color: #333; }}
        .low {{ background: linear-gradient(135deg, #28a745 0%, #218838 100%); }}
        .total {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }}
        .vuln-item {{ 
            margin: 20px 0; 
            padding: 25px; 
            border: 1px solid #e2e8f0; 
            border-radius: 8px;
            border-left: 4px solid #667eea;
            background: #f7fafc;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        .vuln-item:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }}
        .vuln-item.critical {{ border-left-color: #dc3545; }}
        .vuln-item.high {{ border-left-color: #fd7e14; }}
        .vuln-item.medium {{ border-left-color: #ffc107; }}
        .vuln-item.low {{ border-left-color: #28a745; }}
        .badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-right: 8px;
        }}
        .badge.critical {{ background: #dc3545; color: white; }}
        .badge.high {{ background: #fd7e14; color: white; }}
        .badge.medium {{ background: #ffc107; color: #333; }}
        .badge.low {{ background: #28a745; color: white; }}
        code {{ 
            background: #2d3748; 
            color: #68d391;
            padding: 2px 8px; 
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 14px;
        }}
        pre {{
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            font-family: 'Monaco', 'Courier New', monospace;
        }}
        .ai-badge {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            margin-left: 10px;
        }}
        .fp-warning {{
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 6px;
            padding: 12px;
            margin: 10px 0;
            color: #856404;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Assessment Report</h1>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan Date:</strong> {scan_results.get('scan_date', 'Unknown')}</p>
        <p><strong>Report Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>📊 Vulnerability Summary</h2>
        <div class="stats">
            <div class="stat-card total">
                <h3>{len(vulnerabilities)}</h3>
                <p>Total Vulnerabilities</p>
            </div>
            <div class="stat-card critical">
                <h3>{critical}</h3>
                <p>Critical</p>
            </div>
            <div class="stat-card high">
                <h3>{high}</h3>
                <p>High</p>
            </div>
            <div class="stat-card medium">
                <h3>{medium}</h3>
                <p>Medium</p>
            </div>
            <div class="stat-card low">
                <h3>{low}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <h2>🚨 Detailed Findings</h2>
"""
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            severity = vuln.get('severity', 'Unknown').lower()
            ai_badge = '<span class="ai-badge">AI DETECTED</span>' if vuln.get('ai_detected') else ''
            
            html += f"""
        <div class="vuln-item {severity}">
            <h3>{idx}. {vuln.get('type', 'Unknown')}{ai_badge}</h3>
            <span class="badge {severity}">{vuln.get('severity', 'Unknown')}</span>
            <p><strong>URL:</strong> <code>{vuln.get('url', 'N/A')}</code></p>
            <p><strong>Parameter:</strong> <code>{vuln.get('parameter', 'N/A')}</code></p>
            <p><strong>Method:</strong> {vuln.get('method', 'GET')}</p>
"""
            
            if vuln.get('ai_analysis'):
                ai_analysis = vuln['ai_analysis']
                html += f"""
            <p><strong>AI Exploitability Score:</strong> {ai_analysis.get('exploitability_score', 'N/A')}/10</p>
"""
            
            if vuln.get('false_positive_check', {}).get('is_false_positive'):
                fp_check = vuln['false_positive_check']
                html += f"""
            <div class="fp-warning">
                ⚠️ <strong>Potential False Positive</strong> ({fp_check.get('confidence', 0)}% confidence)<br>
                <em>{fp_check.get('reason', 'Unknown')}</em>
            </div>
"""
            
            html += f"""
            <p><strong>Payload:</strong></p>
            <pre>{vuln.get('payload', 'N/A')}</pre>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html


def main():
    parser = argparse.ArgumentParser(description="AI-Enhanced Vulnerability Report Generator")
    parser.add_argument("-i", "--input", help="Input scan results JSON file")
    parser.add_argument("-o", "--output", default="./reports", help="Output directory")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    
    args = parser.parse_args()
    
    generator = AIReportGenerator(args.output, use_ai=not args.no_ai)
    
    if args.input:
        generator.generate_from_scan_results(args.input)
    else:
        print(f"{Fore.YELLOW}Usage: python ai_report_generator.py -i <scan_results.json>{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Example: python ai_report_generator.py -i results/example.com_comprehensive_report.json{Style.RESET_ALL}")


if __name__ == "__main__":
    main()

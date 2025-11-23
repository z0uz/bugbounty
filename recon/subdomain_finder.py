#!/usr/bin/env python3
"""
Subdomain Enumeration Tool
Discovers subdomains using multiple techniques
"""

import dns.resolver
import requests
import asyncio
import aiohttp
from typing import List, Set
import argparse
from colorama import Fore, Style, init
import json
import os

init(autoreset=True)

class SubdomainFinder:
    def __init__(self, domain: str, output_dir: str = "./results"):
        self.domain = domain
        self.output_dir = output_dir
        self.subdomains: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2
        self.resolver.lifetime = 2
        
        os.makedirs(output_dir, exist_ok=True)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║     Subdomain Enumeration Tool        ║
║     Target: {self.domain:<24}║
╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def bruteforce_subdomains(self, wordlist_path: str = None) -> Set[str]:
        """Bruteforce subdomains using a wordlist"""
        print(f"{Fore.YELLOW}[*] Starting bruteforce enumeration...{Style.RESET_ALL}")
        
        # Default common subdomains
        common_subdomains = [
            "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
            "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
            "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn",
            "ns3", "mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx",
            "static", "docs", "beta", "shop", "sql", "secure", "demo", "cp", "calendar",
            "wiki", "web", "media", "email", "images", "img", "www1", "intranet", "portal",
            "video", "sip", "dns2", "api", "cdn", "stats", "dns1", "ns4", "www3", "dns",
            "search", "staging", "server", "mx1", "chat", "wap", "my", "svn", "mail1",
            "sites", "proxy", "ads", "host", "crm", "cms", "backup", "mx2", "lyncdiscover",
            "info", "apps", "download", "remote", "db", "forums", "store", "relay", "files",
            "newsletter", "app", "live", "owa", "en", "start", "sms", "office", "exchange",
            "ipv4", "git", "upload", "stage", "dashboard", "internal", "prod", "production"
        ]
        
        found = set()
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{self.domain}"
            try:
                answers = self.resolver.resolve(full_domain, 'A')
                if answers:
                    ip = answers[0].to_text()
                    found.add(full_domain)
                    print(f"{Fore.GREEN}[+] Found: {full_domain} -> {ip}{Style.RESET_ALL}")
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                pass
            except Exception as e:
                pass
        
        return found
    
    def certificate_transparency(self) -> Set[str]:
        """Query Certificate Transparency logs"""
        print(f"{Fore.YELLOW}[*] Checking Certificate Transparency logs...{Style.RESET_ALL}")
        
        found = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcard and newline-separated entries
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().replace('*', '')
                            if n.endswith(self.domain) and n != self.domain:
                                found.add(n)
                                print(f"{Fore.GREEN}[+] CT Log: {n}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[-] CT Log error: {str(e)}{Style.RESET_ALL}")
        
        return found
    
    def dns_dumpster(self) -> Set[str]:
        """Query DNSDumpster API"""
        print(f"{Fore.YELLOW}[*] Querying DNSDumpster...{Style.RESET_ALL}")
        
        found = set()
        # Note: DNSDumpster requires CSRF token handling
        # This is a simplified version
        print(f"{Fore.YELLOW}[!] DNSDumpster requires web scraping - use online tool{Style.RESET_ALL}")
        return found
    
    async def check_subdomain_async(self, session: aiohttp.ClientSession, subdomain: str) -> bool:
        """Async HTTP check for subdomain"""
        url = f"http://{subdomain}"
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as response:
                return response.status < 500
        except:
            return False
    
    async def verify_subdomains_http(self, subdomains: Set[str]) -> Set[str]:
        """Verify subdomains respond to HTTP requests"""
        print(f"{Fore.YELLOW}[*] Verifying subdomains via HTTP...{Style.RESET_ALL}")
        
        verified = set()
        async with aiohttp.ClientSession() as session:
            tasks = [self.check_subdomain_async(session, sub) for sub in subdomains]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for subdomain, is_valid in zip(subdomains, results):
                if is_valid:
                    verified.add(subdomain)
        
        return verified
    
    def save_results(self):
        """Save discovered subdomains to file"""
        output_file = os.path.join(self.output_dir, f"{self.domain}_subdomains.txt")
        json_file = os.path.join(self.output_dir, f"{self.domain}_subdomains.json")
        
        # Save as text
        with open(output_file, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        
        # Save as JSON with metadata
        data = {
            "domain": self.domain,
            "total_found": len(self.subdomains),
            "subdomains": sorted(list(self.subdomains))
        }
        
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n{Fore.CYAN}[*] Results saved to:{Style.RESET_ALL}")
        print(f"    - {output_file}")
        print(f"    - {json_file}")
    
    def run(self):
        """Execute all enumeration techniques"""
        self.print_banner()
        
        # Bruteforce
        bruteforce_results = self.bruteforce_subdomains()
        self.subdomains.update(bruteforce_results)
        
        # Certificate Transparency
        ct_results = self.certificate_transparency()
        self.subdomains.update(ct_results)
        
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Total subdomains found: {len(self.subdomains)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
        
        # Save results
        self.save_results()
        
        return self.subdomains


def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumeration Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    
    args = parser.parse_args()
    
    finder = SubdomainFinder(args.domain, args.output)
    finder.run()


if __name__ == "__main__":
    main()

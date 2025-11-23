#!/usr/bin/env python3
"""
Directory and File Scanner
Discovers hidden directories and files
"""

import argparse
from colorama import Fore, Style, init
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
from urllib.parse import urljoin
from utils.http_client import HttpClient
from utils.targets import normalize_url, ensure_trailing_slash

init(autoreset=True)

class DirectoryScanner:
    def __init__(self, target_url: str, output_dir: str = "./results"):
        self.target_url = ensure_trailing_slash(normalize_url(target_url))
        self.output_dir = output_dir
        self.found_paths: List[Dict] = []
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Common directories and files
        self.wordlist = [
            # Admin panels
            "admin", "administrator", "admin.php", "admin.html", "login", "login.php",
            "wp-admin", "wp-login.php", "phpmyadmin", "cpanel", "webmail",
            
            # Common directories
            "api", "backup", "backups", "config", "configs", "database", "db",
            "dev", "development", "docs", "downloads", "files", "images", "img",
            "includes", "js", "css", "assets", "static", "uploads", "upload",
            "test", "testing", "tmp", "temp", "logs", "log", "old", "new",
            
            # Common files
            ".git", ".env", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
            "web.config", "composer.json", "package.json", "README.md", "CHANGELOG.md",
            "config.php", "config.json", "settings.php", "database.sql", "dump.sql",
            "backup.zip", "backup.tar.gz", "phpinfo.php", "info.php", "test.php",
            
            # API endpoints
            "api/v1", "api/v2", "api/users", "api/admin", "api/config",
            "graphql", "swagger", "api-docs",
            
            # Sensitive files
            ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
            "wp-config.php", "wp-config.php.bak", "configuration.php",
            ".env.local", ".env.production", "credentials.json",
            
            # Backup files
            "index.php.bak", "index.html.bak", "config.php.bak",
            "database.sql.gz", "backup.sql", "db_backup.sql",
        ]
        self.http = HttpClient(timeout=6)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║     Directory/File Scanner            ║
║     Target: {self.target_url[:24]:<24}║
╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def check_path(self, path: str) -> Dict:
        """Check if a path exists"""
        url = urljoin(self.target_url, path)
        
        try:
            response = self.http.get(url, allow_redirects=False)
            if not response:
                return None
            
            # Consider 200, 301, 302, 403 as interesting
            if response.status_code in [200, 301, 302, 403]:
                result = {
                    'url': url,
                    'path': path,
                    'status_code': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'Unknown')
                }
                
                # Color code based on status
                if response.status_code == 200:
                    color = Fore.GREEN
                    status = "FOUND"
                elif response.status_code == 403:
                    color = Fore.YELLOW
                    status = "FORBIDDEN"
                else:
                    color = Fore.CYAN
                    status = "REDIRECT"
                
                print(f"{color}[{status}] {url} ({response.status_code}) - {len(response.content)} bytes{Style.RESET_ALL}")
                
                return result
        
        except Exception:
            return None
        
        return None
    
    def scan(self, threads: int = 20):
        """Scan for directories and files"""
        print(f"{Fore.YELLOW}[*] Starting directory scan with {len(self.wordlist)} paths...{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_path = {executor.submit(self.check_path, path): path for path in self.wordlist}
            
            for future in as_completed(future_to_path):
                result = future.result()
                if result:
                    self.found_paths.append(result)
    
    def analyze_findings(self):
        """Analyze and categorize findings"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Analysis of Findings{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
        
        # Categorize by sensitivity
        sensitive_patterns = [
            '.git', '.env', 'config', 'backup', 'database', 'db', 'admin',
            'phpmyadmin', 'credentials', 'password', 'wp-config'
        ]
        
        sensitive_findings = []
        for finding in self.found_paths:
            path_lower = finding['path'].lower()
            if any(pattern in path_lower for pattern in sensitive_patterns):
                sensitive_findings.append(finding)
        
        if sensitive_findings:
            print(f"{Fore.RED}[!] Potentially Sensitive Files/Directories:{Style.RESET_ALL}")
            for finding in sensitive_findings:
                print(f"  • {finding['url']} ({finding['status_code']})")
            print()
    
    def save_results(self):
        """Save scan results"""
        from urllib.parse import urlparse
        domain = urlparse(self.target_url).netloc
        output_file = os.path.join(self.output_dir, f"{domain}_directory_scan.json")
        
        data = {
            "target": self.target_url,
            "total_found": len(self.found_paths),
            "findings": self.found_paths
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"{Fore.CYAN}[*] Results saved to: {output_file}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan Complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total paths found: {len(self.found_paths)}{Style.RESET_ALL}")
        
        status_200 = sum(1 for f in self.found_paths if f['status_code'] == 200)
        status_403 = sum(1 for f in self.found_paths if f['status_code'] == 403)
        status_30x = sum(1 for f in self.found_paths if f['status_code'] in [301, 302])
        
        print(f"{Fore.GREEN}  - 200 OK: {status_200}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  - 403 Forbidden: {status_403}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  - 30x Redirects: {status_30x}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
    
    def run(self, threads: int = 20):
        """Execute directory scan"""
        self.print_banner()
        self.scan(threads)
        self.analyze_findings()
        self.print_summary()
        self.save_results()


def main():
    parser = argparse.ArgumentParser(description="Directory and File Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of threads")
    parser.add_argument("-w", "--wordlist", help="Custom wordlist file")
    
    args = parser.parse_args()
    
    scanner = DirectoryScanner(args.url, args.output)
    
    # Load custom wordlist if provided
    if args.wordlist and os.path.exists(args.wordlist):
        with open(args.wordlist, 'r') as f:
            scanner.wordlist = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}[*] Loaded {len(scanner.wordlist)} paths from custom wordlist{Style.RESET_ALL}")
    
    scanner.run(args.threads)


if __name__ == "__main__":
    main()

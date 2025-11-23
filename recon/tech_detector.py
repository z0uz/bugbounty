#!/usr/bin/env python3
"""
Technology Detection Tool
Identifies technologies used by target website
"""

import requests
import re
import json
import argparse
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import os
from typing import Dict, List, Set

init(autoreset=True)

class TechDetector:
    def __init__(self, url: str, output_dir: str = "./results"):
        self.url = url if url.startswith('http') else f"http://{url}"
        self.output_dir = output_dir
        self.technologies: Dict[str, List[str]] = {
            "web_servers": [],
            "frameworks": [],
            "cms": [],
            "javascript_libraries": [],
            "analytics": [],
            "cdn": [],
            "programming_languages": [],
            "databases": [],
            "other": []
        }
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Technology signatures
        self.signatures = {
            # Web Servers
            "Apache": {"headers": ["Server"], "pattern": r"Apache"},
            "Nginx": {"headers": ["Server"], "pattern": r"nginx"},
            "IIS": {"headers": ["Server"], "pattern": r"Microsoft-IIS"},
            "LiteSpeed": {"headers": ["Server"], "pattern": r"LiteSpeed"},
            
            # Frameworks
            "Laravel": {"headers": ["Set-Cookie"], "pattern": r"laravel_session"},
            "Django": {"headers": ["Server", "X-Frame-Options"], "pattern": r"Django"},
            "Ruby on Rails": {"headers": ["X-Powered-By"], "pattern": r"Phusion Passenger"},
            "Express": {"headers": ["X-Powered-By"], "pattern": r"Express"},
            "ASP.NET": {"headers": ["X-Powered-By", "X-AspNet-Version"], "pattern": r"ASP\.NET"},
            "Flask": {"headers": ["Server"], "pattern": r"Flask"},
            "Spring": {"headers": ["X-Application-Context"], "pattern": r"Spring"},
            
            # CMS
            "WordPress": {"html": r"wp-content|wp-includes"},
            "Joomla": {"html": r"/components/com_|Joomla"},
            "Drupal": {"html": r"Drupal|drupal\.js"},
            "Magento": {"html": r"Mage\.Cookies|Magento"},
            "Shopify": {"html": r"cdn\.shopify\.com"},
            
            # JavaScript Libraries
            "jQuery": {"html": r"jquery\.min\.js|jquery-[0-9]"},
            "React": {"html": r"react\.js|react\.min\.js|react-dom"},
            "Vue.js": {"html": r"vue\.js|vue\.min\.js"},
            "Angular": {"html": r"angular\.js|angular\.min\.js"},
            "Bootstrap": {"html": r"bootstrap\.min\.css|bootstrap\.min\.js"},
            
            # Analytics
            "Google Analytics": {"html": r"google-analytics\.com/analytics\.js|gtag/js"},
            "Facebook Pixel": {"html": r"connect\.facebook\.net/en_US/fbevents\.js"},
            "Hotjar": {"html": r"static\.hotjar\.com"},
            
            # CDN
            "Cloudflare": {"headers": ["Server", "CF-RAY"], "pattern": r"cloudflare"},
            "Akamai": {"headers": ["Server"], "pattern": r"AkamaiGHost"},
            "Fastly": {"headers": ["X-Served-By"], "pattern": r"fastly"},
        }
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║      Technology Detection Tool        ║
║     Target: {self.url[:24]:<24}║
╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def fetch_target(self) -> tuple:
        """Fetch target URL and return headers and HTML"""
        try:
            print(f"{Fore.YELLOW}[*] Fetching target...{Style.RESET_ALL}")
            response = requests.get(self.url, timeout=10, allow_redirects=True,
                                    headers={"User-Agent": "Mozilla/5.0"})
            return response.headers, response.text
        except Exception as e:
            print(f"{Fore.RED}[-] Error fetching target: {str(e)}{Style.RESET_ALL}")
            return {}, ""
    
    def detect_from_headers(self, headers: Dict):
        """Detect technologies from HTTP headers"""
        print(f"{Fore.YELLOW}[*] Analyzing HTTP headers...{Style.RESET_ALL}")
        
        for tech, sig in self.signatures.items():
            if "headers" in sig:
                for header in sig["headers"]:
                    if header in headers:
                        if re.search(sig["pattern"], headers[header], re.IGNORECASE):
                            self.add_technology(tech, f"Header: {header}")
        
        # Check specific headers
        if "X-Powered-By" in headers:
            print(f"{Fore.GREEN}[+] X-Powered-By: {headers['X-Powered-By']}{Style.RESET_ALL}")
            self.technologies["other"].append(f"X-Powered-By: {headers['X-Powered-By']}")
        
        if "Server" in headers:
            print(f"{Fore.GREEN}[+] Server: {headers['Server']}{Style.RESET_ALL}")
    
    def detect_from_html(self, html: str):
        """Detect technologies from HTML content"""
        print(f"{Fore.YELLOW}[*] Analyzing HTML content...{Style.RESET_ALL}")
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check meta tags
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            generator = meta_generator['content']
            print(f"{Fore.GREEN}[+] Generator: {generator}{Style.RESET_ALL}")
            self.technologies["cms"].append(f"Generator: {generator}")
        
        # Check for technology signatures in HTML
        for tech, sig in self.signatures.items():
            if "html" in sig:
                if re.search(sig["html"], html, re.IGNORECASE):
                    self.add_technology(tech, "HTML content")
        
        # Detect JavaScript libraries from script tags
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script.get('src', '')
            self.detect_js_library(src)
        
        # Detect CSS frameworks
        links = soup.find_all('link', rel='stylesheet')
        for link in links:
            href = link.get('href', '')
            self.detect_css_framework(href)
    
    def detect_js_library(self, src: str):
        """Detect JavaScript library from script source"""
        js_libs = {
            "jQuery": r"jquery",
            "React": r"react",
            "Vue.js": r"vue",
            "Angular": r"angular",
            "Lodash": r"lodash",
            "Moment.js": r"moment",
            "D3.js": r"d3\.js",
            "Chart.js": r"chart\.js",
        }
        
        for lib, pattern in js_libs.items():
            if re.search(pattern, src, re.IGNORECASE):
                if lib not in self.technologies["javascript_libraries"]:
                    self.technologies["javascript_libraries"].append(lib)
    
    def detect_css_framework(self, href: str):
        """Detect CSS framework from link href"""
        css_frameworks = {
            "Bootstrap": r"bootstrap",
            "Tailwind CSS": r"tailwind",
            "Foundation": r"foundation",
            "Bulma": r"bulma",
            "Materialize": r"materialize",
        }
        
        for framework, pattern in css_frameworks.items():
            if re.search(pattern, href, re.IGNORECASE):
                if framework not in self.technologies["frameworks"]:
                    self.technologies["frameworks"].append(framework)
    
    def add_technology(self, tech: str, source: str):
        """Add detected technology to appropriate category"""
        categories = {
            "Apache": "web_servers", "Nginx": "web_servers", "IIS": "web_servers",
            "LiteSpeed": "web_servers",
            "Laravel": "frameworks", "Django": "frameworks", "Ruby on Rails": "frameworks",
            "Express": "frameworks", "ASP.NET": "frameworks", "Flask": "frameworks",
            "Spring": "frameworks",
            "WordPress": "cms", "Joomla": "cms", "Drupal": "cms", "Magento": "cms",
            "Shopify": "cms",
            "jQuery": "javascript_libraries", "React": "javascript_libraries",
            "Vue.js": "javascript_libraries", "Angular": "javascript_libraries",
            "Bootstrap": "frameworks",
            "Google Analytics": "analytics", "Facebook Pixel": "analytics",
            "Hotjar": "analytics",
            "Cloudflare": "cdn", "Akamai": "cdn", "Fastly": "cdn",
        }
        
        category = categories.get(tech, "other")
        if tech not in self.technologies[category]:
            self.technologies[category].append(tech)
            print(f"{Fore.GREEN}[+] Detected: {tech} ({source}){Style.RESET_ALL}")
    
    def print_results(self):
        """Print detection results"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Technology Detection Results{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")
        
        for category, techs in self.technologies.items():
            if techs:
                print(f"{Fore.YELLOW}{category.replace('_', ' ').title()}:{Style.RESET_ALL}")
                for tech in techs:
                    print(f"  • {tech}")
                print()
    
    def save_results(self):
        """Save results to file"""
        domain = self.url.replace('http://', '').replace('https://', '').split('/')[0]
        output_file = os.path.join(self.output_dir, f"{domain}_technologies.json")
        
        with open(output_file, 'w') as f:
            json.dump({
                "url": self.url,
                "technologies": self.technologies
            }, f, indent=2)
        
        print(f"{Fore.CYAN}[*] Results saved to: {output_file}{Style.RESET_ALL}")
    
    def run(self):
        """Execute technology detection"""
        self.print_banner()
        headers, html = self.fetch_target()
        
        if headers or html:
            self.detect_from_headers(headers)
            self.detect_from_html(html)
            self.print_results()
            self.save_results()
        else:
            print(f"{Fore.RED}[-] Failed to fetch target{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="Technology Detection Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    
    args = parser.parse_args()
    
    detector = TechDetector(args.url, args.output)
    detector.run()


if __name__ == "__main__":
    main()

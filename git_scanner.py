#!/usr/bin/env python3
import requests
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime
import os

# Suppress only the single warning from urllib3 needed.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class GitScanner:
    def __init__(self, timeout=10, delay=1, threads=5, output=None, verbose=False):
        self.timeout = timeout
        self.delay = delay
        self.threads = threads
        self.output = output
        self.verbose = verbose
        self.git_paths = [
            'HEAD',
            'config',
            'index',
            'COMMIT_EDITMSG',
            'description',
            'info/refs',
            'objects/info/packs',
            'refs/heads/master',
            'refs/heads/main',
            'logs/HEAD',
            'refs/',
            'objects/',
            'packed-refs',
            'refs/remotes/origin/HEAD',
            'refs/stash',
            'logs/refs/heads/master',
            'logs/refs/heads/main',
            'hooks/',
            'info/exclude',
            'objects/info/',
            'info/'
        ]
        
        self.results = []

    def print_banner(self):
        banner = """
╔═══════════════════════════════════════╗
║     Git Repository Exposure Scanner    ║
║      Enhanced Security Assessment      ║
╚═══════════════════════════════════════╝
        """
        print(banner)

    def check_domain(self, domain):
        if not domain.startswith(('http://', 'https://')):
            domain = f'https://{domain}'
        domain = domain.rstrip('/')
        vulnerable_paths = []
        
        for path in self.git_paths:
            try:
                url = f"{domain}/.git/{path}"
                response = requests.head(url, verify=False, timeout=self.timeout, allow_redirects=True)
                
                if response.status_code in [200, 301, 302, 307, 308]:
                    size = int(response.headers.get('content-length', 0))
                    vulnerable_paths.append({
                        'path': path,
                        'status': response.status_code,
                        'size': size
                    })
                    
                    if self.verbose:
                        print(f"[+] Found: {url} (Status: {response.status_code}, Size: {size})")
                
                time.sleep(self.delay)
            
            except requests.exceptions.RequestException as e:
                if self.verbose:
                    print(f"[-] Error checking {url}: {str(e)}")
                continue
        
        return domain, vulnerable_paths

    def write_results(self, domain, paths):
        if not paths:
            return
            
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        output = f"\n[{timestamp}] Results for {domain}:\n"
        output += "=" * 50 + "\n"
        
        for item in paths:
            output += f"Path: /.git/{item['path']}\n"
            output += f"Status: {item['status']}\n"
            output += f"Size: {item['size']} bytes\n"
            output += "-" * 30 + "\n"
        
        if self.output:
            with open(self.output, 'a') as f:
                f.write(output)
        else:
            print(output)

    def scan_domains(self, domains):
        self.print_banner()
        print(f"[*] Starting scan of {len(domains)} domains...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {executor.submit(self.check_domain, domain): domain for domain in domains}
            
            for future in as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    domain, paths = future.result()
                    if paths:
                        print(f"\n[!] Vulnerable Git repository found: {domain}")
                        self.write_results(domain, paths)
                    elif self.verbose:
                        print(f"[-] No Git exposure found: {domain}")
                except Exception as e:
                    print(f"[-] Error scanning {domain}: {str(e)}")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Git Repository Exposure Scanner")
    parser.add_argument("-f", "--file", help="File containing list of domains to scan", required=True)
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    parser.add_argument("-d", "--delay", type=float, default=1, help="Delay between requests in seconds (default: 1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    try:
        with open(args.file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] Error: File {args.file} not found")
        sys.exit(1)

    scanner = GitScanner(
        timeout=10,
        delay=args.delay,
        threads=args.threads,
        output=args.output,
        verbose=args.verbose
    )
    
    scanner.scan_domains(domains)

if __name__ == "__main__":
    main()

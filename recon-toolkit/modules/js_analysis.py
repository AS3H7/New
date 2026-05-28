#!/usr/bin/env python3
"""
JavaScript Analysis Module
----------------------------
Discovers and analyzes JavaScript files for secrets, endpoints, and sensitive data.

What it does:
  1. Crawls target URLs to discover JS files
  2. Downloads and analyzes each JS file for:
     - API keys, tokens, secrets (with entropy scoring)
     - Hidden API endpoints and routes
     - Internal hostnames and IPs
     - Interesting comments (TODO, FIXME, HACK, passwords)
     - Cloud service references (AWS, Firebase, Azure)

False Positive Reduction:
  - Entropy scoring for potential secrets (filters low-entropy strings)
  - Pattern validation (e.g., AWS keys match specific format)
  - Deduplication of findings
  - Filters common false positives (example.com, localhost, etc.)

Usage:
  python3 modules/js_analysis.py --input output/ferrari.com/live_hosts.txt
  python3 modules/js_analysis.py --url https://www.ferrari.com
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = f"""
{Fore.MAGENTA}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}JS ANALYZER — Secrets & Endpoints Finder{Fore.MAGENTA}    ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# --- Secret Detection Patterns ---
# Format: (name, regex_pattern, min_entropy, description)
SECRET_PATTERNS = [
    ("AWS Access Key", r'AKIA[0-9A-Z]{16}', 3.0, "AWS access key ID"),
    ("AWS Secret Key", r'["\']?aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9/+=]{40})["\']', 4.0, "AWS secret access key"),
    ("Google API Key", r'AIza[0-9A-Za-z\-_]{35}', 3.5, "Google API key"),
    ("Google OAuth", r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 3.5, "Google OAuth client ID"),
    ("Firebase URL", r'https?://[a-zA-Z0-9-]+\.firebaseio\.com', 2.0, "Firebase database URL"),
    ("Firebase API Key", r'AIza[0-9A-Za-z\-_]{35}', 3.5, "Firebase API key"),
    ("Slack Token", r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}', 4.0, "Slack API token"),
    ("Slack Webhook", r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}', 3.0, "Slack webhook URL"),
    ("GitHub Token", r'ghp_[0-9a-zA-Z]{36}', 4.0, "GitHub personal access token"),
    ("GitLab Token", r'glpat-[0-9a-zA-Z\-_]{20}', 4.0, "GitLab personal access token"),
    ("Stripe Live Key", r'sk_live_[0-9a-zA-Z]{24,99}', 4.0, "Stripe live secret key"),
    ("Stripe Publishable", r'pk_live_[0-9a-zA-Z]{24,99}', 3.5, "Stripe live publishable key"),
    ("Heroku API Key", r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', 3.5, "Possible Heroku/UUID API key"),
    ("Mailgun API Key", r'key-[0-9a-zA-Z]{32}', 4.0, "Mailgun API key"),
    ("Twilio API Key", r'SK[0-9a-fA-F]{32}', 4.0, "Twilio API key"),
    ("SendGrid API Key", r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}', 4.5, "SendGrid API key"),
    ("JWT Token", r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+', 4.0, "JSON Web Token"),
    ("Private Key", r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----', 0, "Private key block"),
    ("Generic API Key", r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,60})["\']', 3.5, "Generic API key assignment"),
    ("Generic Secret", r'["\']?secret["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,60})["\']', 3.5, "Generic secret assignment"),
    ("Generic Token", r'["\']?token["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{20,60})["\']', 3.5, "Generic token assignment"),
    ("Password Assignment", r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']', 2.5, "Hardcoded password"),
    ("Authorization Header", r'["\']?authorization["\']?\s*[:=]\s*["\']Bearer\s+([A-Za-z0-9\-_\.]+)["\']', 3.5, "Hardcoded auth token"),
]

# --- Endpoint Detection Patterns ---
ENDPOINT_PATTERNS = [
    # API paths
    r'["\'](/api/[a-zA-Z0-9/_\-\.]+)["\']',
    r'["\'](/v[0-9]+/[a-zA-Z0-9/_\-\.]+)["\']',
    r'["\'](/graphql[a-zA-Z0-9/_\-\.]*)["\']',
    # Relative paths
    r'["\'](/[a-zA-Z0-9/_\-\.]+(?:\.php|\.asp|\.jsp|\.json|\.xml))["\']',
    # Full URLs (same domain)
    r'["\'](https?://[a-zA-Z0-9\.\-]+/[a-zA-Z0-9/_\-\.?=&]+)["\']',
    # Path patterns
    r'(?:url|path|endpoint|href|src|action)\s*[:=]\s*["\']([/a-zA-Z0-9_\-\.]+)["\']',
]

# False positive domains to filter
FALSE_POSITIVE_DOMAINS = [
    "example.com", "localhost", "127.0.0.1", "0.0.0.0",
    "placeholder.com", "test.com", "foo.com", "bar.com",
    "w3.org", "schema.org", "json-schema.org",
    "jquery.com", "jsdelivr.net", "cdnjs.cloudflare.com",
    "unpkg.com", "googleapis.com/ajax",
]


class JSAnalyzer:
    def __init__(self, input_file=None, url=None, output_dir=None, threads=10, timeout=15):
        self.input_file = input_file
        self.single_url = url
        self.threads = threads
        self.timeout = timeout
        self.js_files = set()
        self.findings = []
        self.endpoints = set()
        self.secrets = []
        self.analyzed_hashes = set()  # Dedup identical JS files
        
        if output_dir:
            self.output_dir = output_dir
        elif input_file:
            self.output_dir = os.path.dirname(input_file)
        else:
            self.output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "output"
            )
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg, level="info"):
        colors = {
            "info": Fore.CYAN, "success": Fore.GREEN,
            "warning": Fore.YELLOW, "error": Fore.RED,
            "secret": Fore.RED, "endpoint": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    def calculate_entropy(self, string):
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        counter = Counter(string)
        length = len(string)
        entropy = -sum((count/length) * math.log2(count/length) for count in counter.values())
        return entropy

    def is_false_positive_url(self, url):
        """Check if URL is a known false positive."""
        for fp in FALSE_POSITIVE_DOMAINS:
            if fp in url:
                return True
        return False

    def discover_js_files(self, url):
        """Discover JavaScript files from a URL."""
        found_js = set()
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Find <script src="..."> tags
            for script in soup.find_all("script", src=True):
                src = script["src"]
                full_url = urljoin(url, src)
                if full_url.endswith(".js") or ".js?" in full_url:
                    found_js.add(full_url)
            
            # Find JS references in the HTML/inline scripts
            js_pattern = r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']'
            for match in re.finditer(js_pattern, resp.text):
                js_ref = match.group(1)
                full_url = urljoin(url, js_ref)
                if not self.is_false_positive_url(full_url):
                    found_js.add(full_url)
                    
        except Exception as e:
            self.log(f"Error discovering JS from {url}: {str(e)}", "error")
        
        return found_js

    def analyze_js_content(self, url, content):
        """Analyze JS file content for secrets and endpoints."""
        findings = {
            "url": url,
            "secrets": [],
            "endpoints": [],
            "interesting_comments": [],
            "internal_hosts": [],
        }
        
        # Calculate content hash for dedup
        content_hash = hashlib.md5(content.encode()).hexdigest()
        if content_hash in self.analyzed_hashes:
            return None
        self.analyzed_hashes.add(content_hash)
        
        # --- Secret Detection ---
        for name, pattern, min_entropy, description in SECRET_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(1) if match.lastindex else match.group(0)
                
                # Entropy check to reduce false positives
                if min_entropy > 0:
                    entropy = self.calculate_entropy(secret_value)
                    if entropy < min_entropy:
                        continue
                
                # Skip if it's clearly a placeholder
                if any(ph in secret_value.lower() for ph in 
                       ["example", "placeholder", "your_", "xxx", "test", "dummy", "sample"]):
                    continue
                
                findings["secrets"].append({
                    "type": name,
                    "value": secret_value[:50] + "..." if len(secret_value) > 50 else secret_value,
                    "description": description,
                    "entropy": round(self.calculate_entropy(secret_value), 2),
                    "line_context": content[max(0, match.start()-30):match.end()+30].strip()
                })
        
        # --- Endpoint Discovery ---
        for pattern in ENDPOINT_PATTERNS:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(1)
                # Filter out common non-endpoints
                if (len(endpoint) > 5 and 
                    not endpoint.startswith("//") and
                    not self.is_false_positive_url(endpoint) and
                    not endpoint.endswith(('.png', '.jpg', '.gif', '.svg', '.css', '.woff', '.ttf'))):
                    findings["endpoints"].append(endpoint)
                    self.endpoints.add(endpoint)
        
        # --- Interesting Comments ---
        comment_patterns = [
            (r'//\s*(TODO|FIXME|HACK|BUG|XXX|TEMP)[:\s]+(.+)', "dev_comment"),
            (r'//\s*(password|secret|key|token|admin|debug)[:\s]+(.+)', "sensitive_comment"),
            (r'/\*[\s\S]*?(password|secret|key|credentials)[\s\S]*?\*/', "sensitive_block_comment"),
        ]
        for pattern, comment_type in comment_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                findings["interesting_comments"].append({
                    "type": comment_type,
                    "content": match.group(0)[:200]
                })
        
        # --- Internal Hosts/IPs ---
        # IP addresses
        ip_pattern = r'(?:https?://)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?'
        for match in re.finditer(ip_pattern, content):
            ip = match.group(1)
            if not ip.startswith(("0.", "127.", "255.")):
                findings["internal_hosts"].append(match.group(0))
        
        # Internal hostnames
        internal_patterns = r'(?:https?://)?([a-zA-Z0-9\-]+\.(?:internal|local|corp|intranet|private|dev|staging|test)\.[a-zA-Z]+)'
        for match in re.finditer(internal_patterns, content, re.IGNORECASE):
            findings["internal_hosts"].append(match.group(0))
        
        # Deduplicate
        findings["endpoints"] = list(set(findings["endpoints"]))
        findings["internal_hosts"] = list(set(findings["internal_hosts"]))
        
        return findings

    def analyze_js_url(self, url):
        """Download and analyze a single JS file."""
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False
            )
            
            if resp.status_code == 200 and len(resp.text) > 0:
                return self.analyze_js_content(url, resp.text)
                
        except Exception:
            pass
        return None

    def run(self):
        """Run the full JS analysis pipeline."""
        print(BANNER)
        
        # Step 1: Gather target URLs
        target_urls = []
        if self.single_url:
            target_urls = [self.single_url]
        elif self.input_file:
            with open(self.input_file, "r") as f:
                target_urls = [line.strip() for line in f if line.strip()]
        
        self.log(f"Target URLs: {len(target_urls)}", "info")
        
        # Step 2: Discover JS files
        self.log("Discovering JavaScript files...", "info")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.discover_js_files, url): url for url in target_urls}
            for future in as_completed(futures):
                try:
                    js_files = future.result()
                    self.js_files.update(js_files)
                except Exception:
                    pass
        
        self.log(f"Discovered {len(self.js_files)} unique JS files", "success")
        print()
        
        # Step 3: Analyze each JS file
        self.log("Analyzing JavaScript files for secrets & endpoints...", "info")
        completed = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.analyze_js_url, js_url): js_url for js_url in self.js_files}
            
            for future in as_completed(futures):
                completed += 1
                if completed % 10 == 0:
                    print(f"\r  [PROGRESS] {completed}/{len(self.js_files)} analyzed...", end="", flush=True)
                
                try:
                    result = future.result()
                    if result:
                        self.findings.append(result)
                        
                        # Live output for secrets found
                        if result["secrets"]:
                            for secret in result["secrets"]:
                                print(f"\r  {Fore.RED}[SECRET]{Style.RESET_ALL} {secret['type']} in {result['url']}")
                                self.secrets.append({**secret, "source_url": result["url"]})
                        
                        if result["internal_hosts"]:
                            for host in result["internal_hosts"]:
                                print(f"\r  {Fore.YELLOW}[INTERNAL]{Style.RESET_ALL} {host} in {result['url']}")
                except Exception:
                    pass
        
        print(f"\r  [PROGRESS] {completed}/{len(self.js_files)} — DONE!              ")
        print()
        
        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save analysis results."""
        # Secrets file (HIGH PRIORITY)
        secrets_file = os.path.join(self.output_dir, "js_secrets.txt")
        with open(secrets_file, "w") as f:
            for s in self.secrets:
                f.write(f"[{s['type']}] {s['value']} | Entropy: {s['entropy']} | Source: {s.get('source_url', 'N/A')}\n")
        
        # Endpoints file
        endpoints_file = os.path.join(self.output_dir, "js_endpoints.txt")
        with open(endpoints_file, "w") as f:
            for ep in sorted(self.endpoints):
                f.write(f"{ep}\n")
        
        # JS files list
        js_list_file = os.path.join(self.output_dir, "js_files.txt")
        with open(js_list_file, "w") as f:
            for js in sorted(self.js_files):
                f.write(f"{js}\n")
        
        # Full detailed JSON
        detailed_file = os.path.join(self.output_dir, "js_analysis_detailed.json")
        output = {
            "timestamp": datetime.now().isoformat(),
            "total_js_files": len(self.js_files),
            "total_secrets": len(self.secrets),
            "total_endpoints": len(self.endpoints),
            "secrets": self.secrets,
            "endpoints": sorted(list(self.endpoints)),
            "findings": self.findings
        }
        with open(detailed_file, "w") as f:
            json.dump(output, f, indent=2)
        
        self.log(f"Saved secrets: {secrets_file}", "info")
        self.log(f"Saved endpoints: {endpoints_file}", "info")
        self.log(f"Saved detailed: {detailed_file}", "info")

    def print_summary(self):
        """Print analysis summary."""
        print(f"\n{Fore.MAGENTA}{'='*50}")
        print(f"  JS ANALYSIS COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  JS Files Analyzed:   {len(self.js_files)}")
        print(f"  Secrets Found:       {Fore.RED}{len(self.secrets)}{Style.RESET_ALL}")
        print(f"  Endpoints Found:     {len(self.endpoints)}")
        
        if self.secrets:
            print(f"\n  {Fore.RED}SECRETS BREAKDOWN:{Style.RESET_ALL}")
            secret_types = Counter(s["type"] for s in self.secrets)
            for stype, count in secret_types.most_common():
                print(f"    {stype}: {count}")
        
        # Internal hosts found
        all_internal = set()
        for f in self.findings:
            if f:
                all_internal.update(f.get("internal_hosts", []))
        if all_internal:
            print(f"\n  {Fore.YELLOW}INTERNAL HOSTS:{Style.RESET_ALL}")
            for host in sorted(all_internal)[:20]:
                print(f"    {host}")
        
        print(f"\n  Output: {self.output_dir}/")
        print(f"{Fore.MAGENTA}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="JavaScript file analysis for secrets and endpoints")
    parser.add_argument("--input", "-i", help="Input file with live host URLs")
    parser.add_argument("--url", "-u", help="Single URL to analyze")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--threads", "-t", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Timeout (default: 15)")
    
    args = parser.parse_args()
    
    if not args.input and not args.url:
        print(f"{Fore.RED}[ERROR] Provide --input file or --url{Style.RESET_ALL}")
        sys.exit(1)
    
    analyzer = JSAnalyzer(
        input_file=args.input,
        url=args.url,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    analyzer.run()


if __name__ == "__main__":
    main()

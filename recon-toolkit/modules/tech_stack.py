#!/usr/bin/env python3
"""
Tech Stack Fingerprinting Module
----------------------------------
Identifies technologies, frameworks, and versions from HTTP responses.

What it detects:
  - Web servers (Apache, Nginx, IIS, etc.)
  - Frameworks (React, Angular, Vue, Django, Laravel, Spring, etc.)
  - CMS (WordPress, Drupal, Joomla)
  - Programming languages (PHP, Python, Java, .NET, Node.js)
  - JavaScript libraries & versions
  - Security headers analysis
  - Cookie-based framework detection

Why this matters for hunting:
  - Each tech stack has known vulnerability patterns
  - Framework detection guides exploit selection
  - Missing security headers = quick wins

Usage:
  python3 modules/tech_stack.py --input output/ferrari.com/live_hosts.txt
"""

import argparse
import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = f"""
{Fore.YELLOW}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}TECH STACK FINGERPRINTER — Deep Detection{Fore.YELLOW}   ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# --- Detection Patterns ---

# Cookie name patterns → Framework
COOKIE_PATTERNS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java",
    "ASP.NET_SessionId": "ASP.NET",
    "csrftoken": "Django",
    "laravel_session": "Laravel",
    "_rails": "Ruby on Rails",
    "rack.session": "Ruby Rack",
    "connect.sid": "Node.js Express",
    "ci_session": "CodeIgniter",
    "CAKEPHP": "CakePHP",
    "symfony": "Symfony",
    "wp-settings": "WordPress",
    "__cfduid": "Cloudflare",
}

# HTML/Body patterns → Technology
BODY_PATTERNS = {
    # Frontend Frameworks
    r'ng-app|ng-controller|angular\.module': "Angular",
    r'react\.development\.js|react\.production|_react|__NEXT_DATA__': "React",
    r'vue\.js|v-bind|v-model|v-if': "Vue.js",
    r'svelte': "Svelte",
    r'ember': "Ember.js",
    
    # CMS
    r'wp-content|wp-includes|wordpress': "WordPress",
    r'drupal\.settings|sites/default/files': "Drupal",
    r'joomla': "Joomla",
    r'magento|Mage\.Cookies': "Magento",
    r'shopify': "Shopify",
    
    # JS Libraries
    r'jquery[\.\-](\d+\.\d+\.\d+)': "jQuery",
    r'bootstrap[\.\-](\d+\.\d+)': "Bootstrap",
    r'lodash|underscore': "Lodash/Underscore",
    
    # Backend indicators in HTML
    r'__VIEWSTATE|__EVENTVALIDATION': "ASP.NET WebForms",
    r'csrf_token.*name="authenticity_token"': "Ruby on Rails",
    r'laravel|Laravel': "Laravel",
    r'django|csrfmiddlewaretoken': "Django",
    
    # Cloud/Infra
    r'amazonaws\.com': "AWS S3/CloudFront",
    r'azurewebsites\.net|azure': "Azure",
    r'googleapis\.com|firebase': "Google Cloud/Firebase",
    r'herokuapp\.com': "Heroku",
}

# Header patterns → Technology
HEADER_PATTERNS = {
    "X-Powered-By": {
        r"PHP/(.+)": "PHP",
        r"ASP\.NET": "ASP.NET",
        r"Express": "Node.js Express",
        r"Servlet": "Java Servlet",
        r"Next\.js": "Next.js",
    },
    "Server": {
        r"nginx/(.+)": "Nginx",
        r"Apache/(.+)": "Apache",
        r"Microsoft-IIS/(.+)": "IIS",
        r"gunicorn": "Python Gunicorn",
        r"Werkzeug": "Python Flask",
        r"openresty": "OpenResty",
        r"LiteSpeed": "LiteSpeed",
        r"Kestrel": ".NET Kestrel",
    },
    "X-AspNet-Version": {
        r"(.+)": "ASP.NET",
    },
    "X-Generator": {
        r"(.+)": None,  # Use the value directly
    },
}

# Security headers to check
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]


class TechStackFingerprinter:
    def __init__(self, input_file, output_dir=None, threads=20, timeout=10):
        self.input_file = input_file
        self.threads = threads
        self.timeout = timeout
        self.results = []
        
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.dirname(input_file)
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg, level="info"):
        colors = {
            "info": Fore.CYAN, "success": Fore.GREEN,
            "warning": Fore.YELLOW, "error": Fore.RED,
            "tech": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    def load_hosts(self):
        """Load live hosts from file."""
        with open(self.input_file, "r") as f:
            return [line.strip() for line in f if line.strip()]

    def detect_from_headers(self, headers):
        """Detect technologies from HTTP headers."""
        tech_found = {}
        
        for header_name, patterns in HEADER_PATTERNS.items():
            header_value = headers.get(header_name, "")
            if not header_value:
                continue
            for pattern, tech_name in patterns.items():
                match = re.search(pattern, header_value, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else ""
                    name = tech_name if tech_name else header_value
                    tech_found[name] = version
        
        return tech_found

    def detect_from_cookies(self, cookies):
        """Detect technologies from cookie names."""
        tech_found = {}
        cookie_names = [c.name for c in cookies] if hasattr(cookies, '__iter__') else []
        
        for cookie_name in cookie_names:
            for pattern, tech_name in COOKIE_PATTERNS.items():
                if pattern.lower() in cookie_name.lower():
                    tech_found[tech_name] = "detected via cookie"
        
        return tech_found

    def detect_from_body(self, body):
        """Detect technologies from HTML body content."""
        tech_found = {}
        
        for pattern, tech_name in BODY_PATTERNS.items():
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else ""
                tech_found[tech_name] = version
        
        return tech_found

    def check_security_headers(self, headers):
        """Check which security headers are present/missing."""
        present = []
        missing = []
        
        for header in SECURITY_HEADERS:
            if header.lower() in {k.lower() for k in headers.keys()}:
                present.append(header)
            else:
                missing.append(header)
        
        return {"present": present, "missing": missing}

    def fingerprint_host(self, url):
        """Fingerprint a single host."""
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            headers = dict(resp.headers)
            body = resp.text[:100000]
            
            # Detect technologies from all sources
            tech_from_headers = self.detect_from_headers(headers)
            tech_from_cookies = self.detect_from_cookies(resp.cookies)
            tech_from_body = self.detect_from_body(body)
            
            # Merge all detections
            all_tech = {}
            all_tech.update(tech_from_headers)
            all_tech.update(tech_from_cookies)
            all_tech.update(tech_from_body)
            
            # Security headers analysis
            security = self.check_security_headers(headers)
            
            result = {
                "url": url,
                "final_url": resp.url,
                "technologies": all_tech,
                "server": headers.get("Server", "Unknown"),
                "security_headers": security,
                "missing_security_headers_count": len(security["missing"]),
                "interesting_headers": {k: v for k, v in headers.items() 
                                       if k.lower().startswith("x-") or k.lower() in ["server", "via"]},
            }
            
            return result
            
        except Exception as e:
            return {"url": url, "error": str(e), "technologies": {}}

    def fingerprint_all(self):
        """Fingerprint all hosts."""
        print(BANNER)
        hosts = self.load_hosts()
        self.log(f"Loaded {len(hosts)} hosts from {self.input_file}", "info")
        print()
        
        completed = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.fingerprint_host, host): host for host in hosts}
            
            for future in as_completed(futures):
                completed += 1
                if completed % 5 == 0:
                    print(f"\r  [PROGRESS] {completed}/{len(hosts)} fingerprinted...", end="", flush=True)
                
                try:
                    result = future.result()
                    if result and result.get("technologies"):
                        self.results.append(result)
                        # Live output
                        techs = ", ".join(result["technologies"].keys())
                        print(f"\r  {Fore.MAGENTA}[TECH]{Style.RESET_ALL} {result['url']} → {techs}")
                    elif result:
                        self.results.append(result)
                except Exception:
                    pass
        
        print(f"\r  [PROGRESS] {completed}/{len(hosts)} — DONE!              ")
        print()
        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save fingerprinting results."""
        # Summary file
        summary_file = os.path.join(self.output_dir, "tech_stack.txt")
        with open(summary_file, "w") as f:
            for r in self.results:
                if r.get("technologies"):
                    techs = ", ".join(f"{k} {v}".strip() for k, v in r["technologies"].items())
                    f.write(f"{r['url']} | {techs}\n")
        
        # Hosts with missing security headers (quick wins)
        insecure_file = os.path.join(self.output_dir, "missing_security_headers.txt")
        with open(insecure_file, "w") as f:
            for r in self.results:
                missing = r.get("security_headers", {}).get("missing", [])
                if len(missing) >= 3:
                    f.write(f"{r['url']} | Missing: {', '.join(missing)}\n")
        
        # Full JSON
        detailed_file = os.path.join(self.output_dir, "tech_stack_detailed.json")
        output = {
            "timestamp": datetime.now().isoformat(),
            "total_fingerprinted": len(self.results),
            "results": self.results
        }
        with open(detailed_file, "w") as f:
            json.dump(output, f, indent=2)
        
        self.log(f"Saved tech stack: {summary_file}", "info")
        self.log(f"Saved insecure hosts: {insecure_file}", "info")
        self.log(f"Saved detailed: {detailed_file}", "info")

    def print_summary(self):
        """Print tech stack summary."""
        print(f"\n{Fore.YELLOW}{'='*50}")
        print(f"  TECH STACK FINGERPRINTING COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        
        # Aggregate tech counts
        tech_counts = {}
        for r in self.results:
            for tech in r.get("technologies", {}):
                tech_counts[tech] = tech_counts.get(tech, 0) + 1
        
        if tech_counts:
            print(f"\n  Technologies Detected:")
            for tech, count in sorted(tech_counts.items(), key=lambda x: -x[1])[:20]:
                print(f"    {Fore.MAGENTA}{tech}{Style.RESET_ALL}: {count} hosts")
        
        # Security header stats
        total_missing = sum(r.get("missing_security_headers_count", 0) for r in self.results)
        hosts_with_issues = sum(1 for r in self.results if r.get("missing_security_headers_count", 0) >= 3)
        
        print(f"\n  Security Header Issues:")
        print(f"    Hosts missing 3+ headers: {Fore.RED}{hosts_with_issues}{Style.RESET_ALL}")
        
        print(f"\n  Output: {self.output_dir}/")
        print(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Technology stack fingerprinting")
    parser.add_argument("--input", "-i", required=True, help="Input file with live host URLs")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--threads", "-t", type=int, default=20, help="Threads (default: 20)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"{Fore.RED}[ERROR] Input file not found: {args.input}{Style.RESET_ALL}")
        sys.exit(1)
    
    fingerprinter = TechStackFingerprinter(
        input_file=args.input,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    fingerprinter.fingerprint_all()


if __name__ == "__main__":
    main()

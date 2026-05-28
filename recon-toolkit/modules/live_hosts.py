#!/usr/bin/env python3
"""
Live Host Probing & HTTP Fingerprinting Module
-----------------------------------------------
Probes subdomains for HTTP/HTTPS, captures response metadata.

What it does:
  - Probes both HTTP and HTTPS for each subdomain
  - Captures: status code, page title, content length, redirect location
  - Captures response headers for tech fingerprinting
  - Identifies interesting status codes (401, 403, 500, etc.)
  - Categorizes hosts by type (login pages, APIs, default pages, etc.)

False Positive Reduction:
  - Validates actual HTTP response (not just DNS)
  - Detects parked domains and default pages
  - Identifies CDN/WAF (Cloudflare, Akamai, etc.)

Usage:
  python3 modules/live_hosts.py --input output/ferrari.com/subdomains.txt
  python3 modules/live_hosts.py --input output/ferrari.com/subdomains.txt --threads 50
"""

import argparse
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = f"""
{Fore.BLUE}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}LIVE HOST PROBER — HTTP Fingerprinting{Fore.BLUE}      ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# Known parked/default page indicators
PARKED_INDICATORS = [
    "domain is for sale", "buy this domain", "parked domain",
    "this domain has expired", "coming soon", "under construction",
    "godaddy", "namecheap parking", "sedoparking",
    "hugedomains", "dan.com"
]

# CDN/WAF Detection patterns
CDN_WAF_HEADERS = {
    "cloudflare": ["cf-ray", "cf-cache-status"],
    "akamai": ["x-akamai-transformed", "akamai-origin-hop"],
    "aws_cloudfront": ["x-amz-cf-id", "x-amz-cf-pop"],
    "fastly": ["x-served-by", "x-cache", "x-fastly-request-id"],
    "incapsula": ["x-iinfo", "x-cdn"],
    "sucuri": ["x-sucuri-id"],
    "stackpath": ["x-sp-"],
}


class LiveHostProber:
    def __init__(self, input_file, output_dir=None, threads=30, timeout=10):
        self.input_file = input_file
        self.threads = threads
        self.timeout = timeout
        self.results = []
        self.interesting = []
        
        # Determine output dir
        if output_dir:
            self.output_dir = output_dir
        else:
            # Try to infer from input path
            parent = os.path.dirname(input_file)
            if os.path.basename(parent) != "output":
                self.output_dir = parent
            else:
                self.output_dir = os.path.join(parent, "probe_results")
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg, level="info"):
        colors = {
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "interesting": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    def load_subdomains(self):
        """Load subdomains from input file."""
        with open(self.input_file, "r") as f:
            subs = [line.strip() for line in f if line.strip()]
        return list(set(subs))

    def detect_cdn_waf(self, headers):
        """Detect CDN/WAF from response headers."""
        detected = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for cdn_name, header_patterns in CDN_WAF_HEADERS.items():
            for pattern in header_patterns:
                if pattern.lower() in headers_lower:
                    detected.append(cdn_name)
                    break
        
        # Check Server header
        server = headers_lower.get("server", "").lower()
        if "cloudflare" in server:
            detected.append("cloudflare")
        elif "akamaighost" in server:
            detected.append("akamai")
        elif "nginx" in server:
            detected.append("nginx")
        elif "apache" in server:
            detected.append("apache")
        elif "microsoft-iis" in server:
            detected.append("iis")
        
        return list(set(detected))

    def is_parked(self, body):
        """Check if the page is a parked/default domain page."""
        body_lower = body.lower() if body else ""
        for indicator in PARKED_INDICATORS:
            if indicator in body_lower:
                return True
        return False

    def extract_title(self, body):
        """Extract page title from HTML."""
        try:
            soup = BeautifulSoup(body, "html.parser")
            title_tag = soup.find("title")
            if title_tag:
                return title_tag.get_text().strip()[:100]
        except Exception:
            pass
        return ""

    def categorize_host(self, status_code, title, url, headers):
        """Categorize the host based on response characteristics."""
        categories = []
        title_lower = title.lower() if title else ""
        url_lower = url.lower()
        
        # Auth/Login pages
        if any(kw in title_lower for kw in ["login", "sign in", "authenticate", "sso"]):
            categories.append("login_page")
        if any(kw in url_lower for kw in ["/login", "/auth", "/sso", "/admin"]):
            categories.append("auth_endpoint")
        
        # API endpoints
        if any(kw in url_lower for kw in ["/api", "/v1/", "/v2/", "/graphql"]):
            categories.append("api")
        
        # Admin panels
        if any(kw in title_lower for kw in ["admin", "dashboard", "panel", "management"]):
            categories.append("admin_panel")
        
        # Interesting status codes
        if status_code == 401:
            categories.append("requires_auth")
        elif status_code == 403:
            categories.append("forbidden")
        elif status_code >= 500:
            categories.append("server_error")
        
        return categories if categories else ["standard"]

    def probe_host(self, subdomain):
        """Probe a single subdomain for HTTP and HTTPS."""
        results = []
        
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                resp = requests.get(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                body = resp.text[:50000]  # Limit body size
                title = self.extract_title(body)
                cdn_waf = self.detect_cdn_waf(dict(resp.headers))
                is_parked = self.is_parked(body)
                categories = self.categorize_host(resp.status_code, title, resp.url, dict(resp.headers))
                
                result = {
                    "subdomain": subdomain,
                    "url": url,
                    "final_url": resp.url,
                    "status_code": resp.status_code,
                    "title": title,
                    "content_length": len(resp.content),
                    "content_type": resp.headers.get("Content-Type", ""),
                    "server": resp.headers.get("Server", ""),
                    "cdn_waf": cdn_waf,
                    "is_parked": is_parked,
                    "categories": categories,
                    "redirect_chain": [r.url for r in resp.history] if resp.history else [],
                    "interesting_headers": {
                        "x-powered-by": resp.headers.get("X-Powered-By", ""),
                        "x-aspnet-version": resp.headers.get("X-AspNet-Version", ""),
                        "x-generator": resp.headers.get("X-Generator", ""),
                        "access-control-allow-origin": resp.headers.get("Access-Control-Allow-Origin", ""),
                    }
                }
                results.append(result)
                
                # If HTTPS works, skip HTTP (prefer HTTPS)
                if scheme == "https" and resp.status_code < 500:
                    break
                    
            except requests.exceptions.SSLError:
                # If HTTPS fails with SSL error, we'll try HTTP next
                if scheme == "https":
                    continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue
        
        return results

    def probe_all(self):
        """Probe all subdomains."""
        print(BANNER)
        subdomains = self.load_subdomains()
        self.log(f"Loaded {len(subdomains)} subdomains from {self.input_file}", "info")
        self.log(f"Threads: {self.threads} | Timeout: {self.timeout}s", "info")
        print()
        
        completed = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.probe_host, sub): sub for sub in subdomains}
            
            for future in as_completed(futures):
                completed += 1
                if completed % 10 == 0:
                    print(f"\r  [PROGRESS] {completed}/{len(subdomains)} probed...", end="", flush=True)
                
                try:
                    host_results = future.result()
                    for result in host_results:
                        self.results.append(result)
                        
                        # Flag interesting findings
                        if (result["categories"] != ["standard"] or 
                            result["status_code"] in [401, 403, 500, 502, 503]):
                            self.interesting.append(result)
                            
                        # Live output for interesting finds
                        status = result["status_code"]
                        color = Fore.GREEN if status == 200 else Fore.YELLOW if status < 400 else Fore.RED
                        if result["categories"] != ["standard"]:
                            print(f"\r  {Fore.MAGENTA}[INTERESTING]{Style.RESET_ALL} {color}[{status}]{Style.RESET_ALL} {result['url']} — {result['title'][:50]} {result['categories']}")
                except Exception:
                    pass
        
        print(f"\r  [PROGRESS] {completed}/{len(subdomains)} probed — DONE!       ")
        print()
        
        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save results to files."""
        # Simple live hosts list (for piping to other tools)
        live_file = os.path.join(self.output_dir, "live_hosts.txt")
        with open(live_file, "w") as f:
            for r in sorted(self.results, key=lambda x: x["subdomain"]):
                if not r["is_parked"]:
                    f.write(f"{r['url']}\n")
        
        # Interesting hosts
        interesting_file = os.path.join(self.output_dir, "interesting_hosts.txt")
        with open(interesting_file, "w") as f:
            for r in self.interesting:
                f.write(f"[{r['status_code']}] {r['url']} | {r['title']} | {r['categories']}\n")
        
        # Full detailed JSON
        detailed_file = os.path.join(self.output_dir, "live_hosts_detailed.json")
        output = {
            "timestamp": datetime.now().isoformat(),
            "total_probed": len(self.results),
            "interesting_count": len(self.interesting),
            "results": self.results
        }
        with open(detailed_file, "w") as f:
            json.dump(output, f, indent=2)
        
        self.log(f"Saved live hosts: {live_file}", "info")
        self.log(f"Saved interesting: {interesting_file}", "info")
        self.log(f"Saved detailed: {detailed_file}", "info")

    def print_summary(self):
        """Print summary of findings."""
        print(f"\n{Fore.BLUE}{'='*50}")
        print(f"  PROBING COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  Total Live Hosts:    {len(self.results)}")
        print(f"  Interesting Hosts:   {len(self.interesting)}")
        print(f"  Parked/Default:      {sum(1 for r in self.results if r['is_parked'])}")
        
        # Status code breakdown
        status_counts = {}
        for r in self.results:
            sc = r["status_code"]
            status_counts[sc] = status_counts.get(sc, 0) + 1
        
        print(f"\n  Status Code Breakdown:")
        for code in sorted(status_counts.keys()):
            count = status_counts[code]
            color = Fore.GREEN if code == 200 else Fore.YELLOW if code < 400 else Fore.RED
            print(f"    {color}{code}{Style.RESET_ALL}: {count}")
        
        # CDN/WAF breakdown
        cdn_counts = {}
        for r in self.results:
            for cdn in r.get("cdn_waf", []):
                cdn_counts[cdn] = cdn_counts.get(cdn, 0) + 1
        
        if cdn_counts:
            print(f"\n  CDN/WAF Detected:")
            for cdn, count in sorted(cdn_counts.items(), key=lambda x: -x[1]):
                print(f"    {cdn}: {count}")
        
        # Categories
        cat_counts = {}
        for r in self.results:
            for cat in r.get("categories", []):
                if cat != "standard":
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
        
        if cat_counts:
            print(f"\n  {Fore.MAGENTA}Interesting Categories:{Style.RESET_ALL}")
            for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
                print(f"    {cat}: {count}")
        
        print(f"\n  Output: {self.output_dir}/")
        print(f"{Fore.BLUE}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="HTTP probe and fingerprint live hosts")
    parser.add_argument("--input", "-i", required=True, help="Input file with subdomains (one per line)")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--threads", "-t", type=int, default=30, help="Number of threads (default: 30)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"{Fore.RED}[ERROR] Input file not found: {args.input}{Style.RESET_ALL}")
        sys.exit(1)
    
    prober = LiveHostProber(
        input_file=args.input,
        output_dir=args.output,
        threads=args.threads,
        timeout=args.timeout
    )
    prober.probe_all()


if __name__ == "__main__":
    main()

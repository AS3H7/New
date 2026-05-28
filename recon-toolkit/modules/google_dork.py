#!/usr/bin/env python3
"""
Google Dorking Module
---------------------
Generates targeted Google dork queries for bug bounty recon.

What it does:
  - Generates categorized dork queries for the target domain
  - Optionally saves them for manual execution (Google blocks automated queries)
  - Categories: exposed files, login panels, APIs, errors, cloud storage, etc.

Why manual execution:
  - Google blocks automated queries (CAPTCHA)
  - Better to use these in browser or with a Google Custom Search API key

Usage:
  python3 modules/google_dork.py --domain ferrari.com
  python3 modules/google_dork.py --domain ferrari.com --category all
"""

import argparse
import json
import os
import sys
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.GREEN}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}GOOGLE DORK GENERATOR — Targeted Queries{Fore.GREEN}    ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""


class GoogleDorkGenerator:
    def __init__(self, domain, output_dir=None):
        self.domain = domain
        
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "output", self.domain
            )
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_dorks(self):
        """Generate all dork categories."""
        dorks = {}
        
        # --- Exposed Files & Sensitive Data ---
        dorks["sensitive_files"] = {
            "description": "Find exposed sensitive files (configs, backups, credentials)",
            "impact": "Credential theft, source code access, configuration data",
            "queries": [
                f'site:{self.domain} ext:env',
                f'site:{self.domain} ext:conf',
                f'site:{self.domain} ext:cfg',
                f'site:{self.domain} ext:ini',
                f'site:{self.domain} ext:log',
                f'site:{self.domain} ext:bak',
                f'site:{self.domain} ext:backup',
                f'site:{self.domain} ext:old',
                f'site:{self.domain} ext:sql',
                f'site:{self.domain} ext:db',
                f'site:{self.domain} ext:sqlite',
                f'site:{self.domain} ext:yml OR ext:yaml',
                f'site:{self.domain} ext:json "password" OR "secret" OR "key"',
                f'site:{self.domain} ext:xml "password" OR "secret"',
                f'site:{self.domain} filetype:pdf "confidential" OR "internal"',
                f'site:{self.domain} filetype:xlsx OR filetype:csv "email" OR "password"',
                f'site:{self.domain} "index of /" +.env',
                f'site:{self.domain} intitle:"index of" "backup"',
                f'site:{self.domain} intitle:"index of" "database"',
            ]
        }
        
        # --- Login & Admin Panels ---
        dorks["login_panels"] = {
            "description": "Find login pages, admin panels, and authentication endpoints",
            "impact": "Brute force targets, auth bypass attempts, admin access",
            "queries": [
                f'site:{self.domain} inurl:login',
                f'site:{self.domain} inurl:admin',
                f'site:{self.domain} inurl:portal',
                f'site:{self.domain} inurl:signin',
                f'site:{self.domain} inurl:dashboard',
                f'site:{self.domain} inurl:panel',
                f'site:{self.domain} inurl:console',
                f'site:{self.domain} inurl:manage',
                f'site:{self.domain} intitle:"login" OR intitle:"sign in"',
                f'site:{self.domain} intitle:"admin" OR intitle:"administrator"',
                f'site:{self.domain} intitle:"dashboard"',
                f'site:{self.domain} inurl:wp-admin OR inurl:wp-login',
                f'site:{self.domain} inurl:phpmyadmin',
                f'site:{self.domain} inurl:cpanel',
                f'site:{self.domain} inurl:webmail',
            ]
        }
        
        # --- API Endpoints ---
        dorks["api_endpoints"] = {
            "description": "Find exposed API endpoints and documentation",
            "impact": "IDOR, broken auth, data exposure, undocumented endpoints",
            "queries": [
                f'site:{self.domain} inurl:api',
                f'site:{self.domain} inurl:/v1/ OR inurl:/v2/ OR inurl:/v3/',
                f'site:{self.domain} inurl:graphql',
                f'site:{self.domain} inurl:swagger OR inurl:api-docs',
                f'site:{self.domain} intitle:"swagger" OR intitle:"API documentation"',
                f'site:{self.domain} inurl:rest OR inurl:endpoint',
                f'site:{self.domain} ext:json inurl:api',
                f'site:{self.domain} inurl:oauth OR inurl:token',
                f'site:{self.domain} inurl:callback OR inurl:redirect',
                f'site:{self.domain} "api_key" OR "apikey" OR "api-key"',
                f'site:{self.domain} inurl:graphiql',
                f'site:{self.domain} inurl:__graphql',
            ]
        }
        
        # --- Error Pages & Debug Info ---
        dorks["errors_debug"] = {
            "description": "Find error pages leaking stack traces, debug info, or versions",
            "impact": "Technology disclosure, internal path disclosure, error-based injection",
            "queries": [
                f'site:{self.domain} "stack trace" OR "traceback"',
                f'site:{self.domain} "error" "exception" -"page not found"',
                f'site:{self.domain} "debug" "true"',
                f'site:{self.domain} "PHP Fatal error"',
                f'site:{self.domain} "Warning: mysql" OR "Warning: pg_"',
                f'site:{self.domain} "ORA-" -site:oracle.com',
                f'site:{self.domain} "Microsoft OLE DB Provider"',
                f'site:{self.domain} "500 Internal Server Error"',
                f'site:{self.domain} "Django Debug" OR "Werkzeug Debugger"',
                f'site:{self.domain} "Laravel" "exception"',
                f'site:{self.domain} intitle:"phpinfo()"',
                f'site:{self.domain} "environment" "DB_PASSWORD" OR "APP_KEY"',
            ]
        }
        
        # --- Cloud Storage ---
        dorks["cloud_storage"] = {
            "description": "Find exposed cloud storage buckets and resources",
            "impact": "Data exposure, sensitive file access, potential write access",
            "queries": [
                f'site:s3.amazonaws.com "{self.domain.split(".")[0]}"',
                f'site:amazonaws.com "{self.domain.split(".")[0]}"',
                f'site:blob.core.windows.net "{self.domain.split(".")[0]}"',
                f'site:storage.googleapis.com "{self.domain.split(".")[0]}"',
                f'site:drive.google.com "{self.domain.split(".")[0]}"',
                f'site:docs.google.com "{self.domain.split(".")[0]}"',
                f'site:{self.domain} "s3.amazonaws.com"',
                f'site:{self.domain} "storage.googleapis.com"',
                f'site:{self.domain} "blob.core.windows.net"',
                f'"{self.domain.split(".")[0]}" site:pastebin.com',
                f'"{self.domain.split(".")[0]}" site:trello.com',
                f'"{self.domain.split(".")[0]}" site:notion.so',
            ]
        }
        
        # --- Source Code & Dev ---
        dorks["source_code"] = {
            "description": "Find exposed source code, git repos, and development artifacts",
            "impact": "Source code analysis, credential extraction, vulnerability identification",
            "queries": [
                f'site:{self.domain} inurl:.git',
                f'site:{self.domain} intitle:"index of" ".git"',
                f'site:{self.domain} inurl:.svn',
                f'site:{self.domain} ext:php OR ext:asp OR ext:jsp intitle:"index of"',
                f'site:github.com "{self.domain}"',
                f'site:gitlab.com "{self.domain}"',
                f'site:bitbucket.org "{self.domain}"',
                f'site:github.com "{self.domain.split(".")[0]}" "password" OR "secret" OR "token"',
                f'site:github.com "{self.domain.split(".")[0]}" extension:env',
                f'site:{self.domain} inurl:package.json OR inurl:composer.json',
                f'site:{self.domain} inurl:Dockerfile OR inurl:docker-compose',
                f'site:{self.domain} inurl:.DS_Store',
            ]
        }
        
        # --- Subdomains & Infrastructure ---
        dorks["infrastructure"] = {
            "description": "Find subdomains, staging/dev environments, and infrastructure",
            "impact": "Expanded attack surface, less protected environments",
            "queries": [
                f'site:*.{self.domain}',
                f'site:{self.domain} inurl:staging OR inurl:stage',
                f'site:{self.domain} inurl:dev OR inurl:development',
                f'site:{self.domain} inurl:test OR inurl:testing',
                f'site:{self.domain} inurl:uat OR inurl:preprod',
                f'site:{self.domain} inurl:internal',
                f'site:{self.domain} inurl:jenkins OR inurl:ci OR inurl:build',
                f'site:{self.domain} inurl:jira OR inurl:confluence',
                f'site:{self.domain} inurl:grafana OR inurl:kibana',
                f'site:{self.domain} inurl:gitlab',
                f'site:{self.domain} intitle:"Grafana" OR intitle:"Kibana"',
                f'site:{self.domain} intitle:"Jenkins"',
            ]
        }
        
        # --- Juicy Parameters ---
        dorks["parameters"] = {
            "description": "Find URLs with potentially vulnerable parameters",
            "impact": "XSS, SQLi, SSRF, LFI, open redirect vectors",
            "queries": [
                f'site:{self.domain} inurl:redirect= OR inurl:url= OR inurl:return=',
                f'site:{self.domain} inurl:next= OR inurl:dest= OR inurl:go=',
                f'site:{self.domain} inurl:file= OR inurl:path= OR inurl:folder=',
                f'site:{self.domain} inurl:page= OR inurl:doc= OR inurl:document=',
                f'site:{self.domain} inurl:id= OR inurl:user= OR inurl:account=',
                f'site:{self.domain} inurl:search= OR inurl:query= OR inurl:q=',
                f'site:{self.domain} inurl:upload OR inurl:download',
                f'site:{self.domain} inurl:callback= OR inurl:next= OR inurl:continue=',
                f'site:{self.domain} inurl:action= OR inurl:cmd= OR inurl:exec=',
                f'site:{self.domain} inurl:include= OR inurl:require= OR inurl:load=',
            ]
        }
        
        # --- Third Party Leaks ---
        dorks["third_party_leaks"] = {
            "description": "Find credentials and sensitive data leaked on third-party sites",
            "impact": "Credential access, API key exposure, internal documentation",
            "queries": [
                f'"{self.domain}" "password" site:pastebin.com',
                f'"{self.domain}" site:ghostbin.co OR site:hastebin.com',
                f'"{self.domain.split(".")[0]}" "api" OR "key" OR "secret" site:github.com',
                f'"{self.domain}" site:stackoverflow.com "error" OR "exception"',
                f'"{self.domain}" inurl:sharepoint.com',
                f'"{self.domain}" site:shodan.io',
                f'"{self.domain}" "internal" OR "confidential" filetype:pdf',
                f'"{self.domain}" site:medium.com OR site:notion.so',
                f'"{self.domain.split(".")[0]}" "BEGIN RSA PRIVATE KEY"',
                f'"{self.domain.split(".")[0]}" "AWS_ACCESS_KEY_ID" OR "AWS_SECRET"',
            ]
        }
        
        return dorks

    def save_dorks(self, dorks):
        """Save dorks to files."""
        # All dorks in one file
        all_file = os.path.join(self.output_dir, "google_dorks.txt")
        with open(all_file, "w") as f:
            for category, data in dorks.items():
                f.write(f"\n{'='*60}\n")
                f.write(f"CATEGORY: {category.upper()}\n")
                f.write(f"Description: {data['description']}\n")
                f.write(f"Impact: {data['impact']}\n")
                f.write(f"{'='*60}\n\n")
                for query in data["queries"]:
                    f.write(f"{query}\n")
                f.write("\n")
        
        # JSON with metadata
        json_file = os.path.join(self.output_dir, "google_dorks.json")
        output = {
            "target": self.domain,
            "timestamp": datetime.now().isoformat(),
            "total_dorks": sum(len(d["queries"]) for d in dorks.values()),
            "categories": dorks
        }
        with open(json_file, "w") as f:
            json.dump(output, f, indent=2)
        
        # Per-category files for easy use
        dorks_dir = os.path.join(self.output_dir, "dorks")
        os.makedirs(dorks_dir, exist_ok=True)
        for category, data in dorks.items():
            cat_file = os.path.join(dorks_dir, f"{category}.txt")
            with open(cat_file, "w") as f:
                for query in data["queries"]:
                    f.write(f"{query}\n")
        
        return all_file, json_file

    def run(self, categories=None):
        """Generate and display dorks."""
        print(BANNER)
        print(f"  {Fore.CYAN}[INFO]{Style.RESET_ALL} Target: {self.domain}")
        print()
        
        dorks = self.generate_dorks()
        
        # Filter categories if specified
        if categories and categories != ["all"]:
            dorks = {k: v for k, v in dorks.items() if k in categories}
        
        # Display
        total_queries = 0
        for category, data in dorks.items():
            print(f"  {Fore.GREEN}[{category.upper()}]{Style.RESET_ALL} — {data['description']}")
            print(f"  {Fore.YELLOW}Impact: {data['impact']}{Style.RESET_ALL}")
            for query in data["queries"]:
                print(f"    {query}")
                total_queries += 1
            print()
        
        # Save
        all_file, json_file = self.save_dorks(dorks)
        
        print(f"\n{Fore.GREEN}{'='*50}")
        print(f"  DORK GENERATION COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  Total Dorks Generated: {total_queries}")
        print(f"  Categories: {len(dorks)}")
        print(f"\n  Saved to: {all_file}")
        print(f"  JSON: {json_file}")
        print(f"\n  {Fore.YELLOW}TIP: Execute these in Google manually or via Google CSE API")
        print(f"  to avoid getting blocked by CAPTCHAs.{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Google dork query generator for bug bounty recon")
    parser.add_argument("--domain", "-d", required=True, help="Target domain")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--category", "-c", nargs="+", default=["all"],
                       help="Categories: sensitive_files, login_panels, api_endpoints, errors_debug, cloud_storage, source_code, infrastructure, parameters, third_party_leaks")
    
    args = parser.parse_args()
    
    generator = GoogleDorkGenerator(
        domain=args.domain,
        output_dir=args.output
    )
    generator.run(categories=args.category)


if __name__ == "__main__":
    main()

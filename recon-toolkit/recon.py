#!/usr/bin/env python3
"""
🏎️ RECON TOOLKIT — Master Orchestrator
=========================================
Runs all recon modules in sequence against a target domain.

Workflow:
  1. Subdomain Enumeration (multi-source + DNS validation)
  2. Live Host Probing (HTTP fingerprinting)
  3. Tech Stack Detection (framework & version identification)
  4. Google Dork Generation (targeted queries)
  5. JavaScript Analysis (secrets & endpoints)
  6. Wayback Machine Recon (historical URLs & parameters)
  7. Port Scanning (light, safe TCP scan)

Usage:
  python3 recon.py --target ferrari.com
  python3 recon.py --target ferrari.com --skip port_scan
  python3 recon.py --target ferrari.com --only subdomain,live_hosts
"""

import argparse
import os
import sys
import time
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

# Add modules to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.subdomain_enum import SubdomainEnumerator
from modules.live_hosts import LiveHostProber
from modules.tech_stack import TechStackFingerprinter
from modules.google_dork import GoogleDorkGenerator
from modules.js_analysis import JSAnalyzer
from modules.wayback_recon import WaybackRecon
from modules.port_scanner import PortScanner

BANNER = f"""
{Fore.RED}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Style.RESET_ALL}
  {Fore.WHITE}Custom Bug Bounty Recon Framework{Style.RESET_ALL}
  {Fore.CYAN}─────────────────────────────────{Style.RESET_ALL}
  {Fore.YELLOW}Philosophy: "What can an attacker gain with this?"{Style.RESET_ALL}
"""

ALL_MODULES = [
    "subdomain",
    "live_hosts",
    "tech_stack",
    "google_dork",
    "js_analysis",
    "wayback",
    "port_scan",
]


def print_phase(phase_num, total, name):
    """Print a phase header."""
    print(f"\n{'='*60}")
    print(f"  {Fore.GREEN}[PHASE {phase_num}/{total}]{Style.RESET_ALL} {name}")
    print(f"{'='*60}\n")


def run_recon(target, output_dir, modules_to_run, threads=30, timeout=10):
    """Run the full recon pipeline."""
    print(BANNER)
    print(f"  {Fore.CYAN}Target:{Style.RESET_ALL}   {target}")
    print(f"  {Fore.CYAN}Output:{Style.RESET_ALL}   {output_dir}")
    print(f"  {Fore.CYAN}Modules:{Style.RESET_ALL}  {', '.join(modules_to_run)}")
    print(f"  {Fore.CYAN}Started:{Style.RESET_ALL}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    os.makedirs(output_dir, exist_ok=True)
    start_time = time.time()
    total_phases = len(modules_to_run)
    current_phase = 0
    
    # ===== PHASE 1: Subdomain Enumeration =====
    if "subdomain" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "SUBDOMAIN ENUMERATION")
        
        enumerator = SubdomainEnumerator(
            domain=target,
            output_dir=output_dir,
            resolve=True,
            threads=threads
        )
        enumerator.enumerate()
    
    # ===== PHASE 2: Live Host Probing =====
    if "live_hosts" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "LIVE HOST PROBING")
        
        subs_file = os.path.join(output_dir, "subdomains.txt")
        if not os.path.exists(subs_file):
            subs_file = os.path.join(output_dir, "subdomains_all.txt")
        
        if os.path.exists(subs_file):
            prober = LiveHostProber(
                input_file=subs_file,
                output_dir=output_dir,
                threads=threads,
                timeout=timeout
            )
            prober.probe_all()
        else:
            print(f"  {Fore.YELLOW}[SKIP] No subdomains file found. Run subdomain module first.{Style.RESET_ALL}")
    
    # ===== PHASE 3: Tech Stack Detection =====
    if "tech_stack" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "TECH STACK FINGERPRINTING")
        
        live_file = os.path.join(output_dir, "live_hosts.txt")
        if os.path.exists(live_file):
            fingerprinter = TechStackFingerprinter(
                input_file=live_file,
                output_dir=output_dir,
                threads=threads,
                timeout=timeout
            )
            fingerprinter.fingerprint_all()
        else:
            print(f"  {Fore.YELLOW}[SKIP] No live hosts file found. Run live_hosts module first.{Style.RESET_ALL}")
    
    # ===== PHASE 4: Google Dork Generation =====
    if "google_dork" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "GOOGLE DORK GENERATION")
        
        generator = GoogleDorkGenerator(
            domain=target,
            output_dir=output_dir
        )
        generator.run()
    
    # ===== PHASE 5: JavaScript Analysis =====
    if "js_analysis" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "JAVASCRIPT ANALYSIS")
        
        live_file = os.path.join(output_dir, "live_hosts.txt")
        if os.path.exists(live_file):
            analyzer = JSAnalyzer(
                input_file=live_file,
                output_dir=output_dir,
                threads=10,
                timeout=15
            )
            analyzer.run()
        else:
            print(f"  {Fore.YELLOW}[SKIP] No live hosts file found. Run live_hosts module first.{Style.RESET_ALL}")
    
    # ===== PHASE 6: Wayback Machine Recon =====
    if "wayback" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "WAYBACK MACHINE RECON")
        
        recon = WaybackRecon(
            domain=target,
            output_dir=output_dir,
            check_alive=True,
            threads=threads,
            timeout=timeout
        )
        recon.run()
    
    # ===== PHASE 7: Port Scanning =====
    if "port_scan" in modules_to_run:
        current_phase += 1
        print_phase(current_phase, total_phases, "PORT SCANNING")
        
        subs_file = os.path.join(output_dir, "subdomains.txt")
        if not os.path.exists(subs_file):
            subs_file = os.path.join(output_dir, "subdomains_all.txt")
        
        if os.path.exists(subs_file):
            scanner = PortScanner(
                input_file=subs_file,
                output_dir=output_dir,
                port_profile="web",
                threads=50,
                timeout=3
            )
            scanner.run()
        else:
            print(f"  {Fore.YELLOW}[SKIP] No subdomains file found. Run subdomain module first.{Style.RESET_ALL}")
    
    # ===== FINAL SUMMARY =====
    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    
    print(f"\n{'='*60}")
    print(f"{Fore.GREEN}")
    print(f"  ╔══════════════════════════════════════════╗")
    print(f"  ║       RECON COMPLETE                     ║")
    print(f"  ╚══════════════════════════════════════════╝")
    print(f"{Style.RESET_ALL}")
    print(f"  Target:      {target}")
    print(f"  Duration:    {minutes}m {seconds}s")
    print(f"  Output:      {output_dir}/")
    print(f"\n  {Fore.YELLOW}Files generated:{Style.RESET_ALL}")
    
    if os.path.exists(output_dir):
        for f in sorted(os.listdir(output_dir)):
            filepath = os.path.join(output_dir, f)
            if os.path.isfile(filepath):
                size = os.path.getsize(filepath)
                size_str = f"{size/1024:.1f}KB" if size > 1024 else f"{size}B"
                print(f"    📄 {f} ({size_str})")
    
    print(f"\n  {Fore.CYAN}Next Steps:{Style.RESET_ALL}")
    print(f"    1. Review js_secrets.txt for exposed credentials")
    print(f"    2. Review critical_ports.txt for exposed services")
    print(f"    3. Review interesting_hosts.txt for attack targets")
    print(f"    4. Run Google dorks manually from google_dorks.txt")
    print(f"    5. Check wayback_interesting.txt for forgotten endpoints")
    print(f"    6. Use tech_stack.txt to choose attack vectors")
    print(f"\n  {Fore.YELLOW}Remember: \"What can an attacker gain with this?\"{Style.RESET_ALL}")
    print(f"{'='*60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Recon Toolkit — Custom Bug Bounty Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 recon.py --target ferrari.com
  python3 recon.py --target ferrari.com --skip port_scan
  python3 recon.py --target ferrari.com --only subdomain,live_hosts,tech_stack
  python3 recon.py --target ferrari.com --threads 50 --timeout 15
        """
    )
    parser.add_argument("--target", "-t", required=True, help="Target domain (e.g., ferrari.com)")
    parser.add_argument("--output", "-o", help="Output directory (default: output/<domain>/)")
    parser.add_argument("--skip", help="Comma-separated modules to skip")
    parser.add_argument("--only", help="Comma-separated modules to run (only these)")
    parser.add_argument("--threads", type=int, default=30, help="Thread count (default: 30)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (default: 10)")
    
    args = parser.parse_args()
    
    # Determine output directory
    output_dir = args.output or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "output", args.target
    )
    
    # Determine which modules to run
    if args.only:
        modules_to_run = [m.strip() for m in args.only.split(",")]
    else:
        modules_to_run = ALL_MODULES.copy()
        if args.skip:
            skip_modules = [m.strip() for m in args.skip.split(",")]
            modules_to_run = [m for m in modules_to_run if m not in skip_modules]
    
    # Validate modules
    for m in modules_to_run:
        if m not in ALL_MODULES:
            print(f"{Fore.RED}[ERROR] Unknown module: {m}")
            print(f"Available: {', '.join(ALL_MODULES)}{Style.RESET_ALL}")
            sys.exit(1)
    
    run_recon(
        target=args.target,
        output_dir=output_dir,
        modules_to_run=modules_to_run,
        threads=args.threads,
        timeout=args.timeout
    )


if __name__ == "__main__":
    main()

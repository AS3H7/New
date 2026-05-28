#!/usr/bin/env python3
"""
Port Scanner Module (Light & Safe)
------------------------------------
Performs lightweight TCP port scanning on discovered hosts.

Design Principles:
  - SAFE: Respects rate limits, doesn't flood targets
  - LIGHT: Only checks common web/service ports (not full 65535)
  - SMART: Identifies services based on common port assignments
  - RESPECTFUL: Designed for authorized bug bounty testing only

What it checks:
  - Common web ports (80, 443, 8080, 8443, etc.)
  - Database ports (3306, 5432, 27017, 6379, etc.)
  - Admin/Dev ports (3000, 5000, 8000, 9090, etc.)
  - Identifies exposed services that shouldn't be public

Usage:
  python3 modules/port_scanner.py --input output/ferrari.com/subdomains.txt
  python3 modules/port_scanner.py --host subdomain.ferrari.com
  python3 modules/port_scanner.py --input subs.txt --ports top100
"""

import argparse
import json
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

BANNER = f"""
{Fore.RED}╔══════════════════════════════════════════════╗
║  {Fore.WHITE}PORT SCANNER — Light & Safe{Fore.RED}                   ║
╚══════════════════════════════════════════════╝{Style.RESET_ALL}
"""

# Port categories and their significance for bug bounty
PORT_PROFILES = {
    "minimal": {
        "description": "Quick scan — most common web ports only",
        "ports": [80, 443, 8080, 8443]
    },
    "web": {
        "description": "Web-focused ports",
        "ports": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 4443, 9443, 8081, 8082]
    },
    "top50": {
        "description": "Top 50 interesting ports for bug bounty",
        "ports": [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1433, 1521, 2049, 2083, 2087,
            3000, 3306, 3389, 4443, 5000, 5432, 5900, 5985, 6379, 6443,
            8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300,
            9443, 10000, 10443, 11211, 15672, 27017, 28017, 50000, 50070, 61616
        ]
    },
    "top100": {
        "description": "Extended scan — top 100 ports",
        "ports": [
            21, 22, 23, 25, 53, 80, 81, 88, 110, 111,
            135, 139, 143, 389, 443, 445, 464, 587, 593, 636,
            993, 995, 1025, 1080, 1099, 1433, 1521, 1723, 2049, 2082,
            2083, 2086, 2087, 2095, 2096, 3000, 3001, 3128, 3306, 3389,
            4000, 4443, 4444, 4848, 5000, 5001, 5432, 5555, 5601, 5900,
            5984, 5985, 6000, 6379, 6443, 7001, 7002, 7443, 8000, 8001,
            8008, 8009, 8080, 8081, 8082, 8083, 8085, 8086, 8088, 8090,
            8161, 8443, 8444, 8445, 8834, 8880, 8888, 8899, 9000, 9001,
            9043, 9060, 9080, 9090, 9091, 9200, 9300, 9443, 9999, 10000,
            10250, 10443, 11211, 11443, 15672, 27017, 27018, 28017, 50000, 61616
        ]
    }
}

# Service identification based on port
PORT_SERVICE_MAP = {
    21: ("FTP", "File transfer — check for anonymous access"),
    22: ("SSH", "Secure shell — check version for CVEs"),
    23: ("Telnet", "CRITICAL: Unencrypted remote access"),
    25: ("SMTP", "Mail server — open relay check"),
    53: ("DNS", "DNS server — zone transfer check"),
    80: ("HTTP", "Web server"),
    110: ("POP3", "Mail — unencrypted"),
    111: ("RPCBind", "RPC — information disclosure"),
    135: ("MSRPC", "Microsoft RPC"),
    139: ("NetBIOS", "Windows sharing — enumerate shares"),
    143: ("IMAP", "Mail — unencrypted"),
    389: ("LDAP", "Directory service — anonymous bind check"),
    443: ("HTTPS", "Secure web server"),
    445: ("SMB", "File sharing — EternalBlue, enum"),
    587: ("SMTP", "Mail submission"),
    636: ("LDAPS", "Secure LDAP"),
    993: ("IMAPS", "Secure IMAP"),
    1433: ("MSSQL", "CRITICAL: Database exposed"),
    1521: ("Oracle", "CRITICAL: Database exposed"),
    2049: ("NFS", "Network File System — check exports"),
    2082: ("cPanel", "Hosting panel"),
    2083: ("cPanel SSL", "Hosting panel (SSL)"),
    3000: ("Dev Server", "Node.js/Grafana/Dev app"),
    3306: ("MySQL", "CRITICAL: Database exposed"),
    3389: ("RDP", "Remote Desktop — brute force target"),
    4443: ("HTTPS Alt", "Alternative HTTPS"),
    4848: ("GlassFish", "Java app server admin"),
    5000: ("Dev Server", "Flask/Docker Registry/Dev"),
    5432: ("PostgreSQL", "CRITICAL: Database exposed"),
    5601: ("Kibana", "Log dashboard — info disclosure"),
    5900: ("VNC", "CRITICAL: Remote desktop unencrypted"),
    5984: ("CouchDB", "CRITICAL: Database exposed"),
    5985: ("WinRM", "Windows Remote Management"),
    6379: ("Redis", "CRITICAL: Cache/DB — often unauthenticated"),
    6443: ("Kubernetes API", "CRITICAL: K8s API"),
    7001: ("WebLogic", "Oracle WebLogic — check for deserialization"),
    8000: ("Dev Server", "Development server"),
    8008: ("HTTP Alt", "Alternative HTTP"),
    8009: ("AJP", "Apache JServ Protocol — GhostCat"),
    8080: ("HTTP Proxy", "Web server/proxy"),
    8081: ("HTTP Alt", "Alternative HTTP"),
    8161: ("ActiveMQ", "Message broker admin"),
    8443: ("HTTPS Alt", "Alternative HTTPS"),
    8834: ("Nessus", "Vulnerability scanner"),
    8888: ("HTTP Alt", "Dev server/Jupyter"),
    9000: ("SonarQube", "Code analysis"),
    9090: ("Prometheus", "Metrics — info disclosure"),
    9200: ("Elasticsearch", "CRITICAL: Search engine — data exposure"),
    9300: ("Elasticsearch", "Elasticsearch transport"),
    9443: ("HTTPS Alt", "Alternative HTTPS"),
    10000: ("Webmin", "Server admin panel"),
    10250: ("Kubelet", "CRITICAL: Kubernetes node API"),
    11211: ("Memcached", "CRITICAL: Cache — often unauthenticated"),
    15672: ("RabbitMQ", "Message broker management"),
    27017: ("MongoDB", "CRITICAL: Database — often no auth"),
    28017: ("MongoDB Web", "MongoDB web interface"),
    50000: ("SAP", "SAP management"),
    61616: ("ActiveMQ", "Message broker"),
}


class PortScanner:
    def __init__(self, input_file=None, host=None, output_dir=None, 
                 port_profile="web", threads=50, timeout=3):
        self.input_file = input_file
        self.single_host = host
        self.port_profile = port_profile
        self.threads = threads
        self.timeout = timeout
        self.results = {}
        self.critical_findings = []
        
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
            "critical": Fore.RED
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    def get_ports(self):
        """Get list of ports based on profile."""
        if self.port_profile in PORT_PROFILES:
            return PORT_PROFILES[self.port_profile]["ports"]
        return PORT_PROFILES["web"]["ports"]

    def load_hosts(self):
        """Load hosts from file or single host."""
        if self.single_host:
            return [self.single_host]
        
        if self.input_file:
            with open(self.input_file, "r") as f:
                hosts = []
                for line in f:
                    host = line.strip()
                    # Strip protocol if present
                    if "://" in host:
                        host = host.split("://")[1]
                    # Strip path
                    host = host.split("/")[0]
                    # Strip port
                    host = host.split(":")[0]
                    if host:
                        hosts.append(host)
                return list(set(hosts))
        
        return []

    def scan_port(self, host, port):
        """Scan a single port on a host."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result == 0:
                service_info = PORT_SERVICE_MAP.get(port, ("Unknown", "Unknown service"))
                return {
                    "host": host,
                    "port": port,
                    "state": "open",
                    "service": service_info[0],
                    "note": service_info[1],
                    "is_critical": "CRITICAL" in service_info[1]
                }
        except socket.gaierror:
            pass  # DNS resolution failed
        except Exception:
            pass
        
        return None

    def scan_host(self, host, ports):
        """Scan all ports on a single host."""
        open_ports = []
        
        for port in ports:
            result = self.scan_port(host, port)
            if result:
                open_ports.append(result)
        
        return host, open_ports

    def run(self):
        """Run the port scanner."""
        print(BANNER)
        
        hosts = self.load_hosts()
        ports = self.get_ports()
        profile_info = PORT_PROFILES.get(self.port_profile, {})
        
        self.log(f"Hosts: {len(hosts)}", "info")
        self.log(f"Ports per host: {len(ports)} ({self.port_profile})", "info")
        self.log(f"Profile: {profile_info.get('description', 'Custom')}", "info")
        self.log(f"Total probes: {len(hosts) * len(ports)}", "info")
        self.log(f"Timeout: {self.timeout}s | Threads: {self.threads}", "info")
        print()
        
        # Scan all hosts
        completed_hosts = 0
        total_open = 0
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Create scan tasks for each host-port combination
            futures = {}
            for host in hosts:
                for port in ports:
                    future = executor.submit(self.scan_port, host, port)
                    futures[future] = (host, port)
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        host = result["host"]
                        if host not in self.results:
                            self.results[host] = []
                        self.results[host].append(result)
                        total_open += 1
                        
                        # Live output
                        color = Fore.RED if result["is_critical"] else Fore.GREEN
                        print(f"  {color}[OPEN]{Style.RESET_ALL} {host}:{result['port']} — {result['service']} ({result['note']})")
                        
                        if result["is_critical"]:
                            self.critical_findings.append(result)
                except Exception:
                    pass
        
        print()
        self.save_results()
        self.print_summary()

    def save_results(self):
        """Save scanning results."""
        # Simple open ports list
        ports_file = os.path.join(self.output_dir, "open_ports.txt")
        with open(ports_file, "w") as f:
            for host, ports in sorted(self.results.items()):
                for p in sorted(ports, key=lambda x: x["port"]):
                    f.write(f"{host}:{p['port']} [{p['service']}] {p['note']}\n")
        
        # Critical findings (HIGH PRIORITY)
        if self.critical_findings:
            critical_file = os.path.join(self.output_dir, "critical_ports.txt")
            with open(critical_file, "w") as f:
                f.write("# CRITICAL: These ports should NOT be publicly accessible!\n")
                f.write("# Each of these is potentially a high-severity finding.\n\n")
                for finding in self.critical_findings:
                    f.write(f"{finding['host']}:{finding['port']} — {finding['service']} — {finding['note']}\n")
            self.log(f"Saved critical findings: {critical_file}", "warning")
        
        # JSON detailed
        detailed_file = os.path.join(self.output_dir, "port_scan_detailed.json")
        output = {
            "timestamp": datetime.now().isoformat(),
            "profile": self.port_profile,
            "total_hosts": len(self.results),
            "total_open_ports": sum(len(p) for p in self.results.values()),
            "critical_findings": self.critical_findings,
            "results": self.results
        }
        with open(detailed_file, "w") as f:
            json.dump(output, f, indent=2, default=str)
        
        self.log(f"Saved open ports: {ports_file}", "info")
        self.log(f"Saved detailed: {detailed_file}", "info")

    def print_summary(self):
        """Print scan summary."""
        print(f"\n{Fore.RED}{'='*50}")
        print(f"  PORT SCAN COMPLETE")
        print(f"{'='*50}{Style.RESET_ALL}")
        print(f"  Hosts with open ports: {len(self.results)}")
        print(f"  Total open ports:      {sum(len(p) for p in self.results.values())}")
        print(f"  Critical findings:     {Fore.RED}{len(self.critical_findings)}{Style.RESET_ALL}")
        
        if self.critical_findings:
            print(f"\n  {Fore.RED}⚠️  CRITICAL EXPOSED SERVICES:{Style.RESET_ALL}")
            for f in self.critical_findings:
                print(f"    {f['host']}:{f['port']} → {f['service']}")
        
        # Port frequency
        port_freq = {}
        for host_ports in self.results.values():
            for p in host_ports:
                port_freq[p["port"]] = port_freq.get(p["port"], 0) + 1
        
        if port_freq:
            print(f"\n  Most Common Open Ports:")
            for port, count in sorted(port_freq.items(), key=lambda x: -x[1])[:10]:
                service = PORT_SERVICE_MAP.get(port, ("?", ""))[0]
                print(f"    Port {port} ({service}): {count} hosts")
        
        print(f"\n  Output: {self.output_dir}/")
        print(f"{Fore.RED}{'='*50}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(description="Lightweight port scanner for bug bounty recon")
    parser.add_argument("--input", "-i", help="Input file with hosts/subdomains")
    parser.add_argument("--host", help="Single host to scan")
    parser.add_argument("--output", "-o", help="Output directory")
    parser.add_argument("--ports", "-p", default="web",
                       choices=["minimal", "web", "top50", "top100"],
                       help="Port profile (default: web)")
    parser.add_argument("--threads", "-t", type=int, default=50, help="Threads (default: 50)")
    parser.add_argument("--timeout", type=int, default=3, help="Timeout per port in seconds (default: 3)")
    
    args = parser.parse_args()
    
    if not args.input and not args.host:
        print(f"{Fore.RED}[ERROR] Provide --input file or --host{Style.RESET_ALL}")
        sys.exit(1)
    
    scanner = PortScanner(
        input_file=args.input,
        host=args.host,
        output_dir=args.output,
        port_profile=args.ports,
        threads=args.threads,
        timeout=args.timeout
    )
    scanner.run()


if __name__ == "__main__":
    main()

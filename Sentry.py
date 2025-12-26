#!/usr/bin/env python3
"""
Sentry - Pure Passive Recon Tool by z3r0-1 @z3r0-1sec
A lightweight, 100% passive subdomain and basic info enumerator.
Uses only public sources (crt.sh, DNSDumpster) — no APIs, no proxies, no scanning.

Key features:
- Extremely fast (~10-40 seconds per target)
- Clean, organized output in ./output/{domain}/
- Tracks source attribution (crt.sh vs DNSDumpster vs both)
- Full DNS record lookup (A/AAAA/MX/TXT/NS)
- Robust crt.sh cleaning (no noise, duplicates, artifacts)
- Permissive domain validation for modern TLDs (punycode, .co.uk, .technology, etc.)
- User-Agent rotation & natural delays for stealth

Limitations:
    - DNSDumpster can be rate-limited or change layout (rare but possible)
    - crt.sh shows historical data — some subs may be defunct
    - No active probing (intentional — keeps it fully passive)

License: MIT
Author: z3r0-1 @z3r0-1sec
"""

import argparse
import requests
import random
import time
from bs4 import BeautifulSoup
import dns.resolver
import dns.rdatatype
import re
import sys
import json
from pathlib import Path
from collections import defaultdict
import whoisit

# Bootstrap whoisit once at startup
try:
    whoisit.bootstrap()
except Exception as e:
    print(f"[!] whoisit bootstrap failed: {e}. WHOIS lookups may fail.")

# List of realistic User-Agents to rotate for stealth
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
]

def get_random_headers():
    """Rotate User-Agent to mimic organic traffic and reduce detection risk."""
    return {'User-Agent': random.choice(USER_AGENTS)}

def is_valid_domain(domain):
    """
    Permissive validation for modern domains.
    Allows multi-level TLDs, punycode, digits, long gTLDs.
    """
    domain = domain.lower().strip()
    pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
    return bool(re.match(pattern, domain))

def is_valid_subdomain(sub, domain):
    """
    Validate subdomains with permissive rules.
    Handles wildcards, trailing dots, artifacts.
    """
    sub = sub.lower().strip()
    if not sub or sub == domain:
        return False
    if not sub.endswith('.' + domain):
        return False
    prefix = sub[:-len('.' + domain)].strip()
    if not prefix:
        return False
    if prefix.startswith('xn--'):
        return True
    labels = prefix.split('.')
    for label in labels:
        if not label or not re.match(r'^[a-z0-9][a-z0-9-]*[a-z0-9]?$', label):
            return False
    return True

def get_crt_subdomains(domain):
    """Fetch and clean subdomains from crt.sh."""
    print("[+] Querying crt.sh...")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    for attempt in range(3):
        try:
            time.sleep(random.uniform(0.5, 1.5))
            response = requests.get(url, headers=get_random_headers(), timeout=20)
            if response.status_code != 200:
                print(f"[-] crt.sh {response.status_code} (attempt {attempt+1})")
                time.sleep(2)
                continue
            data = response.json()
            for entry in data:
                name = entry.get('name_value', '')
                for part in name.splitlines():
                    cleaned = part.strip().lstrip('*.').rstrip('.').lower()
                    if is_valid_subdomain(cleaned, domain):
                        subs.add(cleaned)
            print(f"[+] {len(subs)} from crt.sh")
            return subs
        except Exception as e:
            print(f"[-] crt.sh attempt {attempt+1}: {e}")
            time.sleep(3)
    print("[-] crt.sh failed after retries")
    return set()

def get_dnsdumpster_subdomains(domain):
    """Scrape DNSDumpster for host records."""
    print("[+] Querying DNSDumpster...")
    url = "https://dnsdumpster.com/"
    session = requests.Session()
    headers = get_random_headers()
    try:
        resp = session.get(url, headers=headers, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        csrf_tag = soup.find('input', {'name': 'csrfmiddlewaretoken'})
        if not csrf_tag:
            print("[-] No CSRF token found")
            return set()
        csrf = csrf_tag['value']

        data = {'csrfmiddlewaretoken': csrf, 'targetip': domain, 'user': 'free'}
        search_resp = session.post(url, data=data, headers={**headers, 'Referer': url}, timeout=15)

        soup = BeautifulSoup(search_resp.text, 'html.parser')
        subs = set()
        host_table = None
        for table in soup.find_all('table'):
            if table.find('th') and 'Host Records' in table.find('th').text:
                host_table = table
                break

        if not host_table:
            print("[-] Host Records table not found (UI may have changed)")
            return set()

        rows = host_table.find_all('tr')
        for row in rows[1:]:
            cols = row.find_all('td')
            if cols:
                host = cols[0].text.strip().split()[0].rstrip('.').lower()
                if is_valid_subdomain(host, domain):
                    subs.add(host)

        if not subs:
            print("[-] No hosts parsed from DNSDumpster")
        else:
            print(f"[+] {len(subs)} from DNSDumpster")
        return subs
    except Exception as e:
        print(f"[-] DNSDumpster failed: {e}")
        return set()

def full_dns_lookup(domain):
    """Comprehensive DNS lookups for A/AAAA/MX/TXT/NS."""
    print("[+] Full DNS lookups...")
    info = defaultdict(list)
    resolver = dns.resolver.Resolver()
    for rtype in ['A', 'AAAA', 'MX', 'TXT', 'NS']:
        try:
            answers = resolver.resolve(domain, rtype)
            for ans in answers:
                val = str(ans).rstrip('.').lower()
                if rtype == 'TXT':
                    val = val.strip('"')
                info[rtype].append(val)
        except:
            pass
    return dict(info)

def whois_lookup(domain):
    """RDAP/WHOIS lookup using whoisit."""
    print("[+] RDAP/WHOIS...")
    try:
        w = whoisit.domain(domain)
        return {
            'registrar': w.get('registrar'),
            'creation': w.get('created'),
            'emails': w.get('emails', [])
        }
    except Exception as e:
        return {"error": str(e)}

def create_output_dir(domain):
    """Create organized output directory."""
    base = Path("output")
    base.mkdir(exist_ok=True)
    target = base / re.sub(r'[^a-z0-9.-]', '_', domain.lower().strip())
    target.mkdir(exist_ok=True)
    print(f"[+] Output directory: {target}")
    return target

def save_results(target_dir, subdomains_with_sources, dns_info, whois_info):
    """Save results to multiple clean files."""
    flat_subs = sorted(subdomains_with_sources.keys())
    with open(target_dir / "subdomains.txt", 'w') as f:
        for sub in flat_subs:
            f.write(sub + '\n')

    with open(target_dir / "subdomains_with_sources.json", 'w') as f:
        json.dump({k: list(v) for k, v in subdomains_with_sources.items()}, f, indent=4)

    with open(target_dir / "dns_info.json", 'w') as f:
        json.dump(dns_info, f, indent=4)

    with open(target_dir / "whois.txt", 'w') as f:
        json.dump(whois_info, f, indent=4)

    # Human-readable WHOIS summary
    with open(target_dir / "whois_summary.txt", 'w') as f:
        if "error" in whois_info:
            f.write(f"Error: {whois_info['error']}\n")
        else:
            f.write(f"Registrar: {whois_info.get('registrar', 'N/A')}\n")
            f.write(f"Creation Date: {whois_info.get('creation', 'N/A')}\n")
            f.write(f"Emails: {', '.join(whois_info.get('emails', [])) or 'N/A'}\n")

    print(f"[+] Saved:")
    print(f" - subdomains.txt ({len(flat_subs)} subs)")
    print(f" - subdomains_with_sources.json (with origin)")
    print(f" - dns_info.json")
    print(f" - whois.txt")
    print(f" - whois_summary.txt (readable)")

def main():
    parser = argparse.ArgumentParser(description="Sentry - Passive Recon by z3r0-1")
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., example.com)')
    args = parser.parse_args()

    domain = args.domain.lower().strip()
    if not is_valid_domain(domain):
        print("[-] Invalid domain format")
        sys.exit(1)

    output_dir = create_output_dir(domain)

    # Collect subdomains
    crt_subs = get_crt_subdomains(domain)
    dd_subs = get_dnsdumpster_subdomains(domain)

    subdomains_with_sources = defaultdict(set)
    for sub in crt_subs:
        subdomains_with_sources[sub].add("crt.sh")
    for sub in dd_subs:
        subdomains_with_sources[sub].add("dnsdumpster")
    subdomains_with_sources[domain].add("input")

    unique_subs = sorted(subdomains_with_sources.keys())

    print("\n[+] Unique Subdomains Found:")
    for sub in unique_subs:
        sources = ', '.join(subdomains_with_sources[sub])
        print(f" {sub} ({sources})")

    # DNS & WHOIS with error handling
    try:
        dns_info = full_dns_lookup(domain)
    except Exception as e:
        print(f"[!] DNS lookup failed: {e}")
        dns_info = {}

    try:
        whois_info = whois_lookup(domain)
    except Exception as e:
        print(f"[!] WHOIS failed: {e}")
        whois_info = {"error": str(e)}

    print("\n[+] DNS Info:")
    for rtype, values in dns_info.items():
        print(f" {rtype}: {', '.join(values) if values else 'None'}")

    print("\n[+] WHOIS Summary:")
    print(json.dumps(whois_info, indent=4))

    save_results(output_dir, subdomains_with_sources, dns_info, whois_info)

    print(f"\n[+] Done! All results saved in {output_dir}")
    print(" Run again with different domains — everything stays organized!")

if __name__ == "__main__":
    print("""
    Sentry-Recon by z3r0-1sec
    Pure Passive Recon Tool - Fast, Clean, and Stealthy
    """)
    main()


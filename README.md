# Sentry-Recon ⚡

Pure passive reconnaissance tool by z3r0-1sec.  
Fast (~10-40 seconds per target), stealthy, no active probes or APIs.  
Sources: crt.sh (Certificate Transparency) + DNSDumpster.  
Includes: subdomain attribution, full DNS records (A/AAAA/MX/TXT/NS), WHOIS/RDAP lookup.

## Features
- User-Agent rotation and natural delays for evasion
- Cleaned output (no wildcards, duplicates, noise, artifacts)
- Organized per-target folder: `./output/domain_name/`
- JSON + human-readable reports
- Permissive validation for modern TLDs (punycode, .co.uk, .technology, etc.)

## Installation
```bash
git clone https://github.com/z3r0-1sec/Sentry-Recon.git
cd Sentry-Recon
pip install -r requirements.txt
```
## Usage
```bash
python Sentry.py -d example.com
# or (make executable first)
chmod +x Sentry.py
./Sentry.py -d example.com
```

## Example Run
[+] Querying crt.sh...
[+] 12 from crt.sh
[+] Querying DNSDumpster...
[+] 3 from DNSDumpster

[+] Unique Subdomains Found:
 api.example.com (crt.sh)
 mail.example.com (crt.sh, dnsdumpster)
 ...

[+] Done! All results saved in output/example_com

## Output Files
> subdomains.txt — Flat list of unique subdomains
> subdomains_with_sources.json — Subdomains with source attribution
> dns_info.json — DNS records (A/AAAA/MX/TXT/NS)
> whois.txt — Raw WHOIS JSON
> whois_summary.txt — Readable WHOIS summary

## Ethical Use Only
For authorized reconnaissance and bug bounty scope discovery.
Always obtain permission before testing any target.
MIT License | z3r0-1sec | z3r0-1sec@proton.me
Built on Kali Linux

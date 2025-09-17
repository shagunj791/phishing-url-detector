#!/usr/bin/env python3
"""
Simple Phishing URL Detector
- Checks if a URL might be phishing based on patterns
"""

import re
from urllib.parse import urlparse

def is_phishy(url):
    """
    Returns True if URL seems suspicious
    """
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    # Simple rules
    rules = [
        lambda u: '-' in u,                               # hyphens in domain
        lambda u: u.count('.') > 3,                       # too many subdomains
        lambda u: any(c.isdigit() for c in u),            # ANY digit in domain
        lambda u: len(u) > 50,                            # too large domain names
        lambda u: not u.endswith((".com", ".org", ".net", ".gov", ".edu")) # unusual TLDs
    ]

    score = sum(rule(hostname) for rule in rules)

    if score >= 2:
        label = "Dangerous "
    elif score == 1:
        label = "Suspicious "
    else:
        label = "Safe "
    return label

def cli():
    url = input("Enter a URL to check: ").strip()
    result = is_phishy(url)
    print(f"URL: {url}")
    print(f"Safety Status: {result}")

if __name__ == "__main__":
    cli()

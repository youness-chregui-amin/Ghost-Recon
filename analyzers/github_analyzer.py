"""
github_analyzer.py
Analyze GitHub data for subdomains, secrets, and internal IPs.
"""

import re

def analyze_github_data(raw_data, domain=None):
    """
    Extract subdomains, secrets, and internal IPs from GitHub search results.
    Returns a dict with keys: subdomains, secrets, ips.
    """
    subdomain_regex = rf'([a-zA-Z0-9_-]+\.{re.escape(domain)})' if domain else r'([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z]{2,})'
    secret_regex = r'(?:api[_-]?key|secret|token)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{8,})["\']'
    ip_regex = r'\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}\b'
    subdomains = set(re.findall(subdomain_regex, raw_data, re.I))
    secrets = set(re.findall(secret_regex, raw_data, re.I))
    ips = set(re.findall(ip_regex, raw_data))
    return {
        'subdomains': list(subdomains),
        'secrets': list(secrets),
        'ips': list(ips)
    } 
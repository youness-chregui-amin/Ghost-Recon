import subprocess
import re

def get_subdomains(domain):
    """
    Run Sublist3r as a subprocess and parse subdomains from its output.
    Returns a set of subdomains.
    """
    try:
        result = subprocess.run(['sublist3r', '-d', domain, '-o', '-'], capture_output=True, text=True, timeout=60)
        output = result.stdout
        subdomains = set(re.findall(rf'([a-zA-Z0-9_-]+\\.{re.escape(domain)})', output))
        return subdomains
    except Exception:
        return set() 
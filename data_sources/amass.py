import subprocess
import re

def get_subdomains(domain):
    """
    Run amass in passive mode as a subprocess and parse subdomains from its output.
    Returns a set of subdomains.
    """
    try:
        result = subprocess.run(['amass', 'enum', '-passive', '-d', domain], capture_output=True, text=True, timeout=90)
        output = result.stdout
        subdomains = set(re.findall(rf'([a-zA-Z0-9_-]+\\.{re.escape(domain)})', output))
        return subdomains
    except Exception:
        return set() 
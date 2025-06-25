import subprocess
import re

def get_emails_and_hosts(domain):
    """
    Run TheHarvester as a subprocess and parse emails and hosts from its output.
    Returns a dict with 'emails' and 'hosts'.
    """
    try:
        result = subprocess.run(['theHarvester', '-d', domain, '-b', 'all'], capture_output=True, text=True, timeout=90)
        output = result.stdout
        emails = set(re.findall(r'[\w\.-]+@[\w\.-]+', output))
        hosts = set(re.findall(rf'([a-zA-Z0-9_-]+\\.{re.escape(domain)})', output))
        return {'emails': list(emails), 'hosts': list(hosts)}
    except Exception:
        return {'emails': [], 'hosts': []} 
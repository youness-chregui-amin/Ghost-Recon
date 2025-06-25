import requests
import time

def get_ssl_labs_report(domain):
    """
    Query SSL Labs for SSL test results. Returns a dict of findings.
    """
    url = f'https://api.ssllabs.com/api/v3/analyze?host={domain}'
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            # Wait for analysis if in progress
            while data.get('status') == 'IN_PROGRESS':
                time.sleep(10)
                resp = requests.get(url, timeout=15)
                data = resp.json()
            return data
    except Exception:
        pass
    return {} 
"""
virustotal.py
Query VirusTotal API for passive subdomain enumeration.
"""

def get_subdomains(domain, api_key=None):
    """Query VirusTotal for subdomains of the given domain (passive, no direct target contact)."""
    import requests
    VT_API_KEY = "9b59e34e1df3f6854b55f961c0a30eb42bd5f6a8d906fd53eb3f1bbc49d94b4c"
    key = api_key or VT_API_KEY
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": key}
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for item in data.get("data", []):
                subdomain = item.get("id")
                if subdomain:
                    subdomains.add(subdomain)
            return subdomains
        else:
            print(f"[!] VirusTotal error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] VirusTotal exception: {e}")
    return set() 
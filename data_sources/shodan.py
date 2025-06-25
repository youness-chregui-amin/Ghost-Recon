"""
shodan.py
Query Shodan for passive intelligence on the target domain.
"""

def get_shodan_data(domain, api_key=None):
    """Query Shodan for intelligence related to the domain (no direct target contact)."""
    import requests
    SHODAN_API_KEY = "C0UzsRV0rqLoX7qBC6z7GJCOjei80cw4"
    key = api_key or SHODAN_API_KEY
    url = f"https://api.shodan.io/dns/domain/{domain}?key={key}"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            return resp.json()
        else:
            print(f"[!] Shodan error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] Shodan exception: {e}")
    return {} 
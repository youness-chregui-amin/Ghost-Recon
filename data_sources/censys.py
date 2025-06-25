"""
censys.py
Query Censys for passive intelligence on the target domain.
"""
import requests
from requests.auth import HTTPBasicAuth

def get_censys_data(domain, api_id, api_secret):
    """
    Query Censys for intelligence related to the domain (no direct target contact).
    Returns a list of results or an empty list on error.
    """
    url = "https://search.censys.io/api/v2/hosts/search"
    query = {"q": domain, "per_page": 100}
    results = []
    try:
        resp = requests.get(url, params=query, auth=HTTPBasicAuth(api_id, api_secret), timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            results = data.get('result', {}).get('hits', [])
        else:
            print(f"[!] Censys error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] Censys exception: {e}")
    return results 
"""
dnsdb.py
Query DNSDB for passive DNS data on the target domain.
Requires API key. To enable, remove comments and provide your API key.
"""
import requests

def get_dnsdb_data(domain, api_key):
    """
    Query DNSDB for passive DNS data related to the domain.
    Returns a list of DNS records or an empty list on error.
    """
    url = f'https://api.dnsdb.info/lookup/rrset/name/{domain}/?limit=1000'
    headers = {'X-API-Key': api_key, 'Accept': 'application/json'}
    results = []
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            results = data if isinstance(data, list) else [data]
        else:
            print(f"[!] DNSDB error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] DNSDB exception: {e}")
    return results 
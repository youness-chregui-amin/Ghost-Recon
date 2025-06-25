import requests

def get_urlscan_results(domain):
    """
    Scrape URLScan.io for recent scans of the domain. Returns a list of scan URLs.
    """
    url = f'https://urlscan.io/api/v1/search/?q=domain:{domain}'
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            results = [item['result'] for item in data.get('results', []) if 'result' in item]
            return results
    except Exception:
        pass
    return [] 
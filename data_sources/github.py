"""
github.py
Search GitHub for company/domain-related data (subdomains, secrets, endpoints).
"""
import requests

def search_github_code(domain, github_token=None):
    """
    Search GitHub code for references to the domain, subdomains, secrets, etc.
    Returns a list of code search results (raw text snippets).
    """
    url = f"https://api.github.com/search/code?q={domain}&per_page=100"
    headers = {'Accept': 'application/vnd.github.v3+json'}
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    results = []
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get('items', []):
                file_url = item.get('html_url')
                results.append(file_url)
        else:
            print(f"[!] GitHub error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] GitHub exception: {e}")
    return results 
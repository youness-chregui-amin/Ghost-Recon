import requests
from bs4 import BeautifulSoup
from bs4.element import Tag

def get_whois(domain):
    """
    Scrape ViewDNS.info for Whois data (no API key required).
    Returns a dict of Whois info.
    """
    url = f'https://viewdns.info/whois/?domain={domain}'
    try:
        resp = requests.get(url, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        pre = soup.find('pre')
        return {'whois': pre.get_text()} if pre else {}
    except Exception as e:
        print(f"[!] ViewDNS Whois exception: {e}")
    return {}

def get_reverse_ip(domain):
    """
    Scrape ViewDNS.info for Reverse IP data (no API key required).
    Returns a list of domains sharing the same IP.
    """
    url = f'https://viewdns.info/reverseip/?host={domain}&t=1'
    try:
        resp = requests.get(url, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        table = soup.find('table', {'border': '1'})
        domains = []
        if table and isinstance(table, Tag):
            rows = table.find_all('tr', recursive=False)[1:]  # skip header
            for row in rows:
                cols = row.find_all('td', recursive=False)
                if cols:
                    domains.append(cols[0].get_text().strip())
        return domains
    except Exception as e:
        print(f"[!] ViewDNS ReverseIP exception: {e}")
    return []

def get_subdomains(domain, api_key=None):
    """
    Query ViewDNS.info API for subdomains (requires API key). Returns a set of subdomains.
    """
    VIEWDNS_API_KEY = "741fe4f955f515338321259eab87966ca15ba4bd"
    key = api_key or VIEWDNS_API_KEY
    url = f"https://api.viewdns.info/subdomains/?domain={domain}&apikey={key}&output=json"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data.get('response', {}).get('subdomains', []):
                sub = entry.get('name')
                if sub:
                    subdomains.add(sub)
            return subdomains
        else:
            print(f"[!] ViewDNS API error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] ViewDNS API exception: {e}")
    return set() 
import requests
from bs4 import BeautifulSoup

def get_robtex_data(domain):
    """
    Scrape Robtex for domain info. Returns a dict of findings.
    """
    url = f'https://www.robtex.com/dns-lookup/{domain}'
    try:
        resp = requests.get(url, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        findings = {}
        for table in soup.find_all('table'):
            rows = table.find_all('tr')
            for row in rows:
                cols = row.find_all('td')
                if len(cols) == 2:
                    key = cols[0].get_text(strip=True)
                    val = cols[1].get_text(strip=True)
                    findings[key] = val
        return findings
    except Exception:
        return {} 
import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import quote

def get_google_dorks(domain):
    """
    Perform basic Google Dorking for the domain. Returns a list of found URLs.
    """
    dorks = [
        f'site:{domain} ext:php',
        f'site:{domain} ext:sql',
        f'site:{domain} inurl:admin',
        f'site:{domain} intitle:index.of',
        f'site:{domain} password',
        f'site:{domain} confidential',
    ]
    results = set()
    headers = {'User-Agent': 'Mozilla/5.0'}
    for dork in dorks:
        url = f'https://www.google.com/search?q={quote(dork)}'
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            for a in soup.find_all('a'):
                href = a.get('href')
                if href and '/url?q=' in href:
                    link = href.split('/url?q=')[1].split('&')[0]
                    if domain in link:
                        results.add(link)
            time.sleep(2)
        except Exception:
            continue
    return list(results) 
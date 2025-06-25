import requests
from bs4 import BeautifulSoup
import re

def get_emails(domain):
    """
    Scrape Hunter.io for emails related to the domain (no API key, basic scraping only).
    Returns a set of emails.
    """
    url = f'https://hunter.io/search/{domain}'
    emails = set()
    try:
        resp = requests.get(url, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        for a in soup.find_all('a', href=True):
            if 'mailto:' in a['href']:
                email = a['href'].replace('mailto:', '').strip()
                if re.match(r'^[\w\.-]+@[\w\.-]+$', email):
                    emails.add(email)
    except Exception as e:
        print(f"[!] Hunter.io exception: {e}")
    return emails 
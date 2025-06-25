import requests
from bs4 import BeautifulSoup
import re
from bs4.element import Tag

def get_dnsdumpster_data(domain):
    """
    Scrape DNSDumpster for DNS/subdomain data (no API key required).
    Returns a set of subdomains and a set of IPs.
    """
    url = 'https://dnsdumpster.com/'
    session = requests.Session()
    subdomains = set()
    ips = set()
    try:
        # Get CSRF token
        resp = session.get(url, timeout=15)
        soup = BeautifulSoup(resp.text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
        if not (csrf_input and isinstance(csrf_input, Tag) and csrf_input.has_attr('value')):
            print("[!] DNSDumpster: CSRF token not found.")
            return subdomains, ips
        csrf = csrf_input['value']
        cookies = resp.cookies.get_dict()
        headers = {'Referer': url}
        data = {'csrfmiddlewaretoken': csrf, 'targetip': domain}
        resp2 = session.post(url, data=data, headers=headers, cookies=cookies, timeout=20)
        soup2 = BeautifulSoup(resp2.text, 'html.parser')
        for td in soup2.find_all('td', {'class': 'col-md-4'}):
            text = td.get_text().strip()
            if domain in text:
                subdomains.add(text)
        for td in soup2.find_all('td', {'class': 'col-md-2'}):
            ip = td.get_text().strip()
            if re.match(r'\d+\.\d+\.\d+\.\d+', ip):
                ips.add(ip)
    except Exception as e:
        print(f"[!] DNSDumpster exception: {e}")
    return subdomains, ips 
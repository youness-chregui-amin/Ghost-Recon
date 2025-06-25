"""
wayback.py
Query Wayback Machine for archived URLs and JavaScript files.
"""
import requests

def get_archived_urls(domain):
    """
    Get archived URLs for the domain from the Wayback Machine.
    Returns a list of URLs (including JS files).
    """
    url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
    urls = []
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data[1:]:  # skip header
                urls.append(entry[0])
        else:
            print(f"[!] Wayback error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] Wayback exception: {e}")
    return urls 
import requests

def get_subdomains(domain):
    """
    Fetch subdomains for a domain from crt.sh (certificate transparency logs).
    Returns a set of subdomains.
    """
    url = f'https://crt.sh/?q=%25.{domain}&output=json'
    subdomains = set()
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            for entry in resp.json():
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        if sub.endswith(domain):
                            subdomains.add(sub.strip())
        else:
            print(f"[!] crt.sh error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] crt.sh exception: {e}")
    return subdomains 
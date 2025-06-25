import requests

def get_indicators():
    """
    Fetch public malware indicators from ThreatFox (abuse.ch).
    Returns a list of indicators (dicts).
    """
    url = 'https://threatfox.abuse.ch/api/v1/indicators'
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            return data.get('data', [])
        else:
            print(f"[!] ThreatFox error: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[!] ThreatFox exception: {e}")
    return [] 
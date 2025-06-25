import requests
import json

def get_common_crawl_urls(domain):
    """
    Query Common Crawl index for URLs related to the domain. Returns a list of URLs.
    """
    index_url = 'https://index.commoncrawl.org/collinfo.json'
    try:
        # Get latest index
        resp = requests.get(index_url, timeout=10)
        if resp.status_code == 200:
            indexes = resp.json()
            if indexes:
                latest = indexes[-1]['cdx-api']
                query_url = f"{latest}?url=*.{domain}/*&output=json"
                resp2 = requests.get(query_url, timeout=20)
                urls = []
                for line in resp2.iter_lines():
                    if line:
                        try:
                            data = json.loads(line)
                            urls.append(data.get('url'))
                        except Exception:
                            continue
                return urls
    except Exception:
        pass
    return [] 
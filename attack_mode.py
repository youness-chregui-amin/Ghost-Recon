import random
import time
import requests
from utils import ctext
from storage import save_encrypted_json
from analyzers.js_analyzer import analyze_js
from ai_engine import extract_secrets_from_text
import logging
import re
import json

COMMON_ENDPOINTS = [
    '/admin', '/login', '/dashboard', '/config', '/setup', '/manage', '/api', '/internal',
    '/robots.txt', '/favicon.ico', '/.env', '/.git', '/wp-admin', '/server-status', '/debug', '/test'
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64)',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)',
    'Mozilla/5.0 (Android 11; Mobile; rv:89.0) Gecko/89.0 Firefox/89.0'
]

HEADERS_POOL = [
    {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
    {'Accept-Language': 'en-US,en;q=0.5'},
    {'Cache-Control': 'no-cache'},
    {'Connection': 'keep-alive'}
]

ERROR_PATTERNS = [
    r'exception', r'error', r'not found', r'unauthorized', r'forbidden', r'fail', r'stacktrace',
    r'api[_-]?key', r'secret', r'token', r'password', r'credential', r'invalid', r'access denied'
]

RISKY_COOKIE_PATTERNS = [r'sess', r'token', r'auth', r'id', r'key']

def get_proxies(proxy_url=None, proxy_list_path=None):
    proxies = []
    if proxy_list_path:
        try:
            with open(proxy_list_path, 'r') as f:
                for line in f:
                    p = line.strip()
                    if p:
                        proxies.append(p)
        except Exception as e:
            logging.warning(ctext(f"[Proxy] Could not read proxy list: {e}", 'red'))
    if proxy_url:
        proxies.append(proxy_url)
    return proxies if proxies else [None]

def test_proxy(proxy_url):
    try:
        resp = requests.get('https://httpbin.org/ip', proxies={'http': proxy_url, 'https': proxy_url}, timeout=8, verify=False)
        return resp.status_code == 200
    except Exception:
        return False

def parse_cookies(cookie_str):
    cookies = {}
    for part in cookie_str.split(';'):
        if '=' in part:
            k, v = part.strip().split('=', 1)
            cookies[k.strip()] = v.strip()
    return cookies

def load_cookies_from_file(path):
    cookies = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    cookies.update(parse_cookies(line))
    except Exception as e:
        logging.warning(ctext(f"[Cookie] Could not read cookie file: {e}", 'red'))
    return cookies

def load_headers_from_file(path):
    headers = {}
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip()] = v.strip()
    except Exception as e:
        logging.warning(ctext(f"[Header] Could not read header file: {e}", 'red'))
    return headers

def highlight_risky_cookies(cookies, set_cookies):
    risky = []
    for name, value in cookies.items():
        for pat in RISKY_COOKIE_PATTERNS:
            if re.search(pat, name, re.I):
                # Check for Secure/HttpOnly in Set-Cookie
                flags = set_cookies.get(name, '')
                if 'secure' not in flags.lower() or 'httponly' not in flags.lower():
                    risky.append({'name': name, 'value': value, 'flags': flags})
    return risky

def analyze_response(resp):
    findings = {
        'status': resp.status_code,
        'length': len(resp.content),
        'headers': dict(resp.headers),
        'sensitive': False,
        'secrets': [],
        'errors': [],
        'snippet': resp.text[:500],
        'cookies': {},
        'set_cookies': {},
        'risky_cookies': []
    }
    if resp.status_code in [200, 401, 403, 500]:
        findings['sensitive'] = True
    for pat in ERROR_PATTERNS:
        if re.search(pat, resp.text, re.I):
            findings['errors'].append(pat)
            findings['sensitive'] = True
    secrets = extract_secrets_from_text(resp.text)
    if secrets:
        findings['secrets'] = list(secrets)
        findings['sensitive'] = True
    if resp.url.endswith('.js'):
        js_findings = analyze_js(resp.text)
        findings['js_findings'] = js_findings
    # Extract cookies
    findings['cookies'] = resp.cookies.get_dict()
    set_cookies = {}
    for k, v in resp.headers.items():
        if k.lower() == 'set-cookie':
            # Parse Set-Cookie flags
            for part in v.split(','):
                if '=' in part:
                    name = part.split('=', 1)[0].strip()
                    set_cookies[name] = part
    findings['set_cookies'] = set_cookies
    findings['risky_cookies'] = highlight_risky_cookies(findings['cookies'], set_cookies)
    return findings

def run_attack_mode(args):
    """
    Stealthily probe sensitive endpoints, analyze responses, and store results securely.
    Session memory: store all requests/responses for replay/export.
    Proxy rotation: rotate proxies per request, test before use.
    Cookie injection and extraction. Header injection.
    """
    domain = args.domain
    output_file = args.output
    password = args.password
    proxy = getattr(args, 'proxy', None)
    proxy_list = getattr(args, 'proxy_list', None)
    save_session = getattr(args, 'save_session', None)
    cookie_str = getattr(args, 'cookie', None)
    cookie_file = getattr(args, 'cookie_file', None)
    header_list = getattr(args, 'header', [])
    header_file = getattr(args, 'header_file', None)
    use_ai = getattr(args, 'ai', False)
    proxies = get_proxies(proxy, proxy_list)
    valid_proxies = []
    for p in proxies:
        if p is None or test_proxy(p):
            valid_proxies.append(p)
        else:
            logging.warning(ctext(f"[Proxy] Invalid proxy skipped: {p}", 'red'))
    if not valid_proxies:
        valid_proxies = [None]
    proxy_cycle = iter(valid_proxies)

    # Prepare injected cookies
    injected_cookies = {}
    if cookie_str:
        injected_cookies.update(parse_cookies(cookie_str))
    if cookie_file:
        injected_cookies.update(load_cookies_from_file(cookie_file))

    # Prepare injected headers
    injected_headers = {}
    if header_file:
        injected_headers.update(load_headers_from_file(header_file))
    if header_list:
        for h in header_list:
            if ':' in h:
                k, v = h.split(':', 1)
                injected_headers[k.strip()] = v.strip()

    results = {'domain': domain, 'scanned': [], 'findings': []}
    session_memory = []
    for idx, endpoint in enumerate(COMMON_ENDPOINTS):
        url = f"https://{domain}{endpoint}"
        headers = random.choice(HEADERS_POOL).copy()
        headers['User-Agent'] = random.choice(USER_AGENTS)
        headers.update(injected_headers)
        proxy_to_use = next(proxy_cycle, None)
        if proxy_to_use is None:
            proxy_cycle = iter(valid_proxies)
            proxy_to_use = next(proxy_cycle, None)
        try:
            delay = random.randint(10, 30)
            logging.info(ctext(f"[Attack] Probing {url} (delay {delay}s, proxy: {proxy_to_use})", 'magenta'))
            time.sleep(delay)
            req_info = {
                'url': url,
                'headers': headers,
                'proxy': proxy_to_use,
                'cookies': injected_cookies,
                'method': 'GET',
                'timestamp': time.time()
            }
            resp = requests.get(
                url,
                headers=headers,
                cookies=injected_cookies if injected_cookies else None,
                proxies={'http': proxy_to_use, 'https': proxy_to_use} if proxy_to_use else None,
                timeout=15,
                allow_redirects=False,
                verify=False
            )
            entry = {'endpoint': endpoint, 'url': url}
            entry.update(analyze_response(resp))
            results['scanned'].append(url)
            results['findings'].append(entry)
            session_memory.append({'request': req_info, 'response': entry})
        except Exception as e:
            logging.warning(ctext(f"[Attack] Error probing {url}: {e}", 'red'))
            session_memory.append({'request': req_info, 'response': {'error': str(e)}})
    # Save encrypted
    try:
        save_encrypted_json(results, output_file, password)
        logging.info(ctext(f"[Attack] Results saved to {output_file} (encrypted)", 'green'))
    except Exception as e:
        logging.error(ctext(f"[!] Error saving attack results: {e}", 'red'))
    # Save session memory if requested
    if save_session:
        try:
            with open(save_session, 'w') as f:
                json.dump(session_memory, f, indent=2)
            print(ctext(f"[Session] Full session exported to {save_session}", 'cyan'))
        except Exception as e:
            print(ctext(f"[!] Could not save session: {e}", 'red'))
    # Print stylish summary
    print(ctext(f"\n[Attack Summary]", 'cyan'))
    print(ctext(f"Endpoints scanned: {len(results['scanned'])}", 'magenta'))
    print(ctext(f"Sensitive findings: {sum(1 for f in results['findings'] if f['sensitive'])}", 'red'))
    print(ctext(f"Output: {output_file} (encrypted)", 'green')) 
"""
js_analyzer.py
Analyze JavaScript files for endpoints, secrets, and suspicious patterns.
"""
import re

def analyze_js(js_content):
    """
    Extract endpoints, hardcoded URLs, and suspicious patterns from JavaScript content.
    Returns a dict with keys: endpoints, urls, secrets.
    """
    endpoints = set(re.findall(r'/[\w\-/]+', js_content))
    urls = set(re.findall(r'https?://[\w\.-]+(?:/[\w\-./?%&=]*)?', js_content))
    secrets = set(re.findall(r'(?:api[_-]?key|secret|token)["\']?\s*[:=]\s*["\']([A-Za-z0-9\-_]{8,})["\']', js_content, re.I))
    return {
        'endpoints': list(endpoints),
        'urls': list(urls),
        'secrets': list(secrets)
    } 
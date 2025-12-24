#!/usr/bin/env python3
"""
Lightweight discovery helpers for asset and source map extraction.
"""

import re
from typing import Dict, Iterable, List, Set
from urllib.parse import urljoin, urlparse


def normalize_url(base_url: str, raw_url: str) -> str:
    if not raw_url:
        return ""
    raw_url = raw_url.strip()
    if raw_url.startswith("http://") or raw_url.startswith("https://"):
        return raw_url
    if raw_url.startswith("//"):
        scheme = urlparse(base_url).scheme or "https"
        return f"{scheme}:{raw_url}"
    return urljoin(base_url, raw_url)


def dedupe_preserve(items: Iterable[str]) -> List[str]:
    seen: Set[str] = set()
    out: List[str] = []
    for item in items:
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def extract_html_assets(html: str, base_url: str) -> List[str]:
    assets: List[str] = []
    if not html:
        return assets
    patterns = [
        r'<script[^>]+src=["\']([^"\']+)["\']',
        r'<link[^>]+href=["\']([^"\']+)["\']',
        r'<img[^>]+src=["\']([^"\']+)["\']',
    ]
    for pattern in patterns:
        for match in re.findall(pattern, html, re.IGNORECASE):
            assets.append(normalize_url(base_url, match))
    return dedupe_preserve(assets)


def extract_link_header_assets(headers: Dict[str, str], base_url: str) -> List[str]:
    if not headers:
        return []
    link_header = ""
    for k, v in headers.items():
        if str(k).lower() == "link":
            link_header = v
            break
    if not link_header:
        return []
    assets: List[str] = []
    for part in link_header.split(","):
        match = re.search(r"<([^>]+)>", part)
        if not match:
            continue
        url = match.group(1).strip()
        rel_match = re.search(r'rel="?([^\";]+)"?', part, re.IGNORECASE)
        if rel_match:
            rel = rel_match.group(1).lower()
            if rel in ["preload", "prefetch", "modulepreload", "stylesheet"]:
                assets.append(normalize_url(base_url, url))
        else:
            assets.append(normalize_url(base_url, url))
    return dedupe_preserve(assets)


def extract_sourcemap_urls(js_text: str, js_url: str) -> List[str]:
    if not js_text:
        return []
    urls: List[str] = []
    for match in re.findall(r"//#\\s*sourceMappingURL=([^\\s]+)", js_text):
        urls.append(normalize_url(js_url, match))
    for match in re.findall(r"//@\\s*sourceMappingURL=([^\\s]+)", js_text):
        urls.append(normalize_url(js_url, match))
    return dedupe_preserve(urls)


def extract_service_worker_assets(text: str) -> List[str]:
    if not text:
        return []
    assets: List[str] = []
    for match in re.findall(r'["\\\']url["\\\']\\s*:\\s*["\\\']([^"\\\']+)["\\\']', text):
        assets.append(match)
    for match in re.findall(r'["\\\'](/[^"\\\']+\\.(?:js|css|json|png|jpg|jpeg|svg|webp|ico|map))["\\\']', text):
        assets.append(match)
    return dedupe_preserve(assets)

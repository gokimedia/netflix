#!/usr/bin/env python3
"""
Next.js File Collector v2.0
Passive collection for offline analysis of Next.js applications.

Collects:
- Build manifests and config files
- JavaScript bundles and source maps
- __NEXT_DATA__ per-page payloads
- /_next/data JSON payloads
- RSC flight data (read-only)
- Inline window data blobs
- API and JS-discovered endpoint samples (GET only)

Author: Security Research Team
"""

import argparse
import hashlib
import json
import os
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3

from discovery_utils import (
    dedupe_preserve,
    extract_html_assets,
    extract_link_header_assets,
    extract_sourcemap_urls,
    normalize_url,
)
from security_checks import evaluate_security_headers, summarize_findings

urllib3.disable_warnings()


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


INLINE_KEYS = [
    "__NEXT_DATA__",
    "__INITIAL_STATE__",
    "__PRELOADED_STATE__",
    "__APOLLO_STATE__",
    "__DATA__",
    "__CONFIG__",
    "__APP_STATE__",
    "__BOOTSTRAP__",
    "__PAYLOAD__",
    "__ENV__",
    "__RUNTIME_CONFIG__",
    "__REDUX_STATE__",
    "__PUBLIC_CONFIG__",
    "__APP_CONFIG__",
    "__NUXT__",
]


STATIC_EXTENSIONS = (
    ".js",
    ".mjs",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".webp",
    ".gif",
    ".ico",
    ".map",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".webm",
)


@dataclass
class CollectorConfig:
    timeout: int = 20
    concurrency: int = 12
    output_dir: Optional[str] = None
    max_response_bytes: int = 5_000_000
    max_js_bytes: int = 5_000_000
    max_map_bytes: int = 5_000_000
    max_page_bytes: int = 5_000_000
    max_endpoint_bytes: int = 2_000_000
    max_assets: int = 400
    max_js_files: int = 200
    max_page_routes: int = 80
    max_data_routes: int = 120
    max_endpoints: int = 120
    max_api_samples: int = 80
    retries: int = 2
    backoff_factor: float = 0.3
    delay: float = 0.0
    verify_ssl: bool = False
    no_color: bool = False
    verbose: bool = False
    save_raw_html: bool = True
    collect_graphql: bool = True
    collect_api_samples: bool = True
    collect_endpoints: bool = True
    fetch_endpoints: bool = True
    collect_page_next_data: bool = True
    collect_data_routes: bool = True
    collect_rsc: bool = True
    auto_import_miner: bool = True
    import_miner_report: Optional[str] = None
    route_file: Optional[str] = None
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_suffixes: List[str] = field(default_factory=list)


class FileCollector:
    def __init__(self, target: str, config: CollectorConfig = None):
        self.config = config or CollectorConfig()
        self.target = self._normalize_target(target)
        parsed = urlparse(self.target)
        self.netloc = parsed.netloc
        self.hostname = self.netloc.replace(":", "_")

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.project_dir = self.config.output_dir or f"collected_{self.hostname}_{timestamp}"
        os.makedirs(self.project_dir, exist_ok=True)

        self.dirs = {
            'js': os.path.join(self.project_dir, 'javascript'),
            'maps': os.path.join(self.project_dir, 'sourcemaps'),
            'data': os.path.join(self.project_dir, 'data'),
            'pages': os.path.join(self.project_dir, 'pages'),
            'inline': os.path.join(self.project_dir, 'inline'),
            'graphql': os.path.join(self.project_dir, 'graphql'),
            'config': os.path.join(self.project_dir, 'config'),
            'api': os.path.join(self.project_dir, 'api_responses'),
            'endpoints': os.path.join(self.project_dir, 'endpoint_responses'),
            'data_routes': os.path.join(self.project_dir, 'data_routes'),
            'reports': os.path.join(self.project_dir, 'reports'),
        }

        for d in self.dirs.values():
            os.makedirs(d, exist_ok=True)

        self.allowed_hosts = {h.lower() for h in self.config.allowed_hosts}
        self.allowed_suffixes = {
            s.lower() if s.startswith(".") else f".{s.lower()}"
            for s in self.config.allowed_suffixes
        }

        self.session = self._build_session()
        self.request_count = 0
        self.security_findings: List[Dict] = []

        self.build_id = None
        self.routes: Set[str] = set()
        self.data_route_paths: Set[str] = set()
        self.api_paths: Set[str] = set()
        self.endpoint_candidates: Set[str] = set()
        self.endpoint_sources: Dict[str, Set[str]] = {}
        self.collected_files: List[Dict[str, object]] = []
        self.imported: Dict[str, object] = {}

        self._lock = threading.Lock()

        self.stats = {
            'js_files': 0,
            'sourcemaps': 0,
            'data_files': 0,
            'graphql_schemas': 0,
            'config_files': 0,
            'api_responses': 0,
            'endpoint_responses': 0,
            'page_next_data': 0,
            'page_html': 0,
            'inline_json': 0,
            'data_routes': 0,
            'endpoints_discovered': 0,
            'assets_discovered': 0,
            'total_bytes': 0,
        }

    @staticmethod
    def _normalize_target(target: str) -> str:
        target = target.strip()
        if not re.match(r'^https?://', target):
            target = f"https://{target}"
        return target.rstrip('/')

    def log(self, level: str, msg: str):
        if self.config.no_color or not sys.stdout.isatty():
            prefix = f"[{level.upper()}]"
        else:
            colors = {
                'info': Colors.BLUE,
                'success': Colors.GREEN,
                'warning': Colors.YELLOW,
                'critical': Colors.RED,
                'download': Colors.PURPLE,
            }
            prefix = f"{colors.get(level, '')}[{level.upper()}]{Colors.END}"
        print(f"{prefix} {msg}")

    def _build_session(self):
        session = requests.Session()
        retry = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        }
        session.verify = self.config.verify_ssl
        return session

    def _throttle(self):
        if self.config.delay <= 0:
            return
        time.sleep(self.config.delay)

    def _is_allowed_url(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if self.allowed_hosts or self.allowed_suffixes:
            if host in self.allowed_hosts:
                return True
            return any(host.endswith(suffix) for suffix in self.allowed_suffixes)
        return host == (urlparse(self.target).hostname or "").lower()

    def _request(self, url: str, headers: dict = None) -> Optional[requests.Response]:
        if not self._is_allowed_url(url):
            if self.config.verbose:
                self.log('warning', f"Blocked by scope: {url}")
            return None
        self._throttle()
        try:
            h = self.session.headers.copy()
            if headers:
                h.update(headers)
            resp = self.session.get(url, headers=h, timeout=self.config.timeout, stream=True)
            self.request_count += 1
            return resp
        except Exception as e:
            if self.config.verbose:
                self.log('warning', f"Request failed: {url} - {e}")
            return None

    def fetch(self, url: str, headers: dict = None, max_bytes: int = None) -> Optional[requests.Response]:
        resp = self._request(url, headers=headers)
        if not resp:
            return None
        limit = max_bytes or self.config.max_response_bytes
        content = b""
        try:
            for chunk in resp.iter_content(chunk_size=8192):
                content += chunk
                if len(content) >= limit:
                    break
            resp._content = content
        except Exception:
            return None
        return resp

    def _increment_stat(self, key: str, amount: int = 1):
        with self._lock:
            self.stats[key] = self.stats.get(key, 0) + amount

    def _safe_filename(self, name: str, max_len: int = 180) -> str:
        name = re.sub(r'[<>:"/\\|?*]', '_', name).strip()
        if not name:
            name = "file"
        if len(name) <= max_len:
            return name
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:10]
        base, ext = os.path.splitext(name)
        keep = max_len - len(ext) - 11
        if keep < 20:
            keep = 20
        base = base[:keep]
        return f"{base}_{digest}{ext}"

    def save_file(self, content: bytes, subdir: str, filename: str) -> str:
        filename = self._safe_filename(filename)
        filepath = os.path.join(self.dirs[subdir], filename)
        with open(filepath, 'wb') as f:
            f.write(content)
        with self._lock:
            self.stats['total_bytes'] += len(content)
            self.collected_files.append({
                'path': filepath,
                'size': len(content),
                'type': subdir,
            })
        return filepath

    def save_json(self, data: object, subdir: str, filename: str) -> str:
        content = json.dumps(data, indent=2, ensure_ascii=True, default=str).encode("utf-8")
        return self.save_file(content, subdir, filename)

    def _route_slug(self, route: str) -> str:
        if not route or route == "/":
            return "root"
        slug = route.split("?", 1)[0].split("#", 1)[0]
        slug = slug.strip("/").replace("/", "_")
        slug = re.sub(r'[^a-zA-Z0-9._-]', '_', slug)
        return slug or "root"

    def _normalize_route(self, route: str) -> Optional[str]:
        if not route:
            return None
        route = route.strip()
        if route.startswith("http://") or route.startswith("https://"):
            parsed = urlparse(route)
            if parsed.netloc and parsed.netloc != self.netloc:
                return None
            route = parsed.path or "/"
        if not route.startswith("/"):
            route = f"/{route}"
        route = route.split("?", 1)[0].split("#", 1)[0]
        if route != "/" and route.endswith("/"):
            route = route.rstrip("/")
        if route.startswith("/_"):
            return None
        if "[" in route or "]" in route:
            return None
        return route

    def _add_route(self, route: str):
        normalized = self._normalize_route(route)
        if normalized:
            self.routes.add(normalized)

    def load_routes_from_file(self, path: str):
        if not path or not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    self._add_route(line)
            self.imported['route_file'] = path
        except Exception:
            return

    def import_miner_report(self, report_path: str):
        if not report_path or not os.path.exists(report_path):
            return
        try:
            with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
        except Exception:
            return
        self.imported['miner_report'] = report_path
        if not self.build_id and data.get('build_id'):
            self.build_id = data.get('build_id')
        for route in data.get('routes', []) or []:
            self._add_route(route)
        for path in data.get('data_route_paths', []) or []:
            if isinstance(path, str):
                self.data_route_paths.add(path)
        for path in data.get('api_route_paths', []) or []:
            if isinstance(path, str):
                self.api_paths.add(path)
        self.log('info', f"Imported miner report: {report_path}")

    def auto_import_miner_report(self):
        candidates: List[str] = []
        if self.config.import_miner_report:
            candidates.append(self.config.import_miner_report)
        elif self.config.auto_import_miner:
            candidates.append(os.path.join("mined_data", self.netloc, "mining_report.json"))
            candidates.append(os.path.join("mined_data", self.hostname, "mining_report.json"))
        for path in candidates:
            if path and os.path.exists(path):
                self.import_miner_report(path)
                break

    # ==================== COLLECTION METHODS ====================

    def collect_homepage(self) -> Tuple[Optional[str], List[str]]:
        self.log('info', 'Fetching homepage...')
        resp = self.fetch(self.target, max_bytes=self.config.max_page_bytes)
        if not resp or resp.status_code >= 400:
            self.log('critical', 'Cannot fetch homepage')
            return None, []

        html = resp.content.decode("utf-8", errors="replace")

        if self.config.save_raw_html:
            self.save_file(resp.content, 'pages', 'homepage.html')
            self._increment_stat('page_html')

        self.security_findings = evaluate_security_headers(
            resp.headers,
            resp.headers.get("content-type", ""),
        )

        self._extract_build_id(html)
        self._extract_next_data(html, "homepage")
        self._extract_inline_json(html, "homepage")

        assets = extract_html_assets(html, self.target)
        assets.extend(extract_link_header_assets(resp.headers, self.target))
        assets = dedupe_preserve(assets)[:self.config.max_assets]
        if assets:
            self._increment_stat('assets_discovered', len(assets))
        return html, assets

    def _extract_build_id(self, html: str):
        patterns = [
            r'"buildId"\s*:\s*"([^"]+)"',
            r'/_next/static/([a-zA-Z0-9_-]{20,})/',
            r'"b"\s*:\s*"([a-zA-Z0-9_-]{20,})"',
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                self.build_id = match.group(1)
                self.log('success', f'Build ID: {self.build_id}')
                return

        rsc_resp = self.fetch(self.target, headers={
            'RSC': '1',
            'Next-Router-State-Tree': '%5B%22%22%5D',
        }, max_bytes=self.config.max_page_bytes)
        if rsc_resp:
            match = re.search(r'"b"\s*:\s*"([a-zA-Z0-9_-]{20,})"', rsc_resp.text)
            if match:
                self.build_id = match.group(1)
                self.log('success', f'Build ID (RSC): {self.build_id}')

    def _extract_next_data(self, html: str, label: str) -> Optional[dict]:
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.+?)</script>', html, re.DOTALL)
        if not match:
            return None
        raw = match.group(1).strip()
        try:
            data = json.loads(raw)
        except Exception:
            self.save_file(raw.encode("utf-8", errors="ignore"), 'data', f"next_data_{label}.raw.json")
            return None

        self.save_json(data, 'data', f"next_data_{label}.json")
        self._increment_stat('data_files')
        self._increment_stat('page_next_data')
        page = data.get("page")
        if isinstance(page, str):
            self._add_route(page)
        return data

    def _extract_inline_json(self, html: str, label: str) -> int:
        found = 0
        for idx, raw in enumerate(self._extract_json_script_blobs(html), start=1):
            data = self._try_json(raw)
            name = f"inline_{label}_{idx}"
            if data is None:
                self.save_file(raw.encode("utf-8", errors="ignore"), 'inline', f"{name}.txt")
            else:
                self.save_json(data, 'inline', f"{name}.json")
            found += 1

        for idx, (key, data, raw) in enumerate(self._extract_inline_assignments(html), start=1):
            name = f"window_{label}_{key}_{idx}"
            if data is None:
                self.save_file(raw.encode("utf-8", errors="ignore"), 'inline', f"{name}.txt")
            else:
                self.save_json(data, 'inline', f"{name}.json")
            found += 1

        if found:
            self._increment_stat('inline_json', found)
        return found

    def _extract_json_script_blobs(self, html: str) -> List[str]:
        blobs = []
        pattern = r'<script[^>]+type=["\']application/(?:ld\+json|json)["\'][^>]*>(.+?)</script>'
        for match in re.findall(pattern, html, re.DOTALL | re.IGNORECASE):
            if "__NEXT_DATA__" in match:
                continue
            cleaned = match.strip()
            if cleaned:
                blobs.append(cleaned)
        return blobs

    def _extract_inline_assignments(self, html: str) -> List[Tuple[str, Optional[dict], str]]:
        results: List[Tuple[str, Optional[dict], str]] = []
        scripts = re.findall(
            r'<script(?![^>]+src=)[^>]*>(.*?)</script>',
            html,
            re.DOTALL | re.IGNORECASE,
        )
        if not scripts:
            return results

        max_chars = 200000
        for script in scripts:
            if "window" not in script:
                continue
            snippet = script[:max_chars]
            for key in INLINE_KEYS:
                escaped = re.escape(key)
                pattern = (
                    rf'(?:window\.{escaped}|window\["{escaped}"\]|window\[\'{escaped}\'\])\s*=\s*'
                )
                for match in re.finditer(pattern, snippet):
                    raw = self._extract_json_blob(snippet, match.end())
                    if not raw:
                        continue
                    data = self._try_json(raw)
                    results.append((key, data, raw))
        return results

    def _extract_json_blob(self, text: str, start: int) -> str:
        limit = min(len(text), start + 200000)
        open_pos = None
        open_ch = None
        for i in range(start, limit):
            ch = text[i]
            if ch in "{[":
                open_pos = i
                open_ch = ch
                break
        if open_pos is None:
            return ""
        close_ch = "}" if open_ch == "{" else "]"
        depth = 0
        in_str = False
        str_char = ""
        escape = False
        for i in range(open_pos, limit):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if in_str:
                if ch == str_char:
                    in_str = False
                continue
            if ch in ['"', "'"]:
                in_str = True
                str_char = ch
                continue
            if ch == open_ch:
                depth += 1
            elif ch == close_ch:
                depth -= 1
                if depth == 0:
                    return text[open_pos:i + 1]
        return ""

    def _try_json(self, raw: str) -> Optional[dict]:
        try:
            return json.loads(raw)
        except Exception:
            return None

    # ==================== ROUTE DISCOVERY ====================

    def discover_routes(self, html: str):
        self._extract_routes_from_html(html)
        self._extract_routes_from_manifest()
        self._extract_routes_from_sitemap()
        self._extract_routes_from_ssg_manifest()
        self._extract_routes_from_routes_manifest()
        self._extract_routes_from_middleware_manifest()
        self.log('success', f'Found {len(self.routes)} routes')

    def _extract_routes_from_html(self, html: str):
        for match in re.findall(r'(?:href|data-href)=["\']([^"\']+)["\']', html, re.IGNORECASE):
            if match.startswith("/"):
                self._add_route(match)

        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.+?)</script>', html, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(1))
                page = data.get("page")
                if isinstance(page, str):
                    self._add_route(page)
            except Exception:
                pass

    def _extract_routes_from_manifest(self):
        if not self.build_id:
            return
        manifest_url = f"{self.target}/_next/static/{self.build_id}/_buildManifest.js"
        resp = self.fetch(manifest_url)
        if resp and resp.status_code == 200:
            for route in re.findall(r'"(/[^\"]*)"', resp.text):
                self._add_route(route)

    def _extract_routes_from_sitemap(self):
        robots = self.fetch(f"{self.target}/robots.txt")
        sitemap_urls = set()
        if robots and robots.status_code == 200:
            for line in robots.text.splitlines():
                if line.lower().startswith("sitemap:"):
                    sitemap_urls.add(line.split(":", 1)[1].strip())
        if not sitemap_urls:
            sitemap_urls.add(f"{self.target}/sitemap.xml")

        for sm_url in list(sitemap_urls)[:3]:
            resp = self.fetch(sm_url)
            if resp and resp.status_code == 200:
                for loc in re.findall(r"<loc>([^<]+)</loc>", resp.text):
                    parsed = urlparse(loc)
                    if parsed.netloc == self.netloc:
                        self._add_route(parsed.path or "/")

    def _extract_routes_from_ssg_manifest(self):
        if not self.build_id:
            return
        url = f"{self.target}/_next/static/{self.build_id}/_ssgManifest.js"
        resp = self.fetch(url)
        if resp and resp.status_code == 200:
            match = re.search(r"__SSG_MANIFEST\\s*=\\s*new Set\\((\\[.*?\\])\\)", resp.text)
            if match:
                try:
                    data = json.loads(match.group(1))
                    for route in data:
                        if isinstance(route, str):
                            self._add_route(route)
                except Exception:
                    pass

    def _extract_routes_from_routes_manifest(self):
        if not self.build_id:
            return
        candidates = [
            f"{self.target}/_next/static/{self.build_id}/_routesManifest.json",
            f"{self.target}/_next/static/{self.build_id}/routes-manifest.json",
        ]
        for url in candidates:
            resp = self.fetch(url)
            if resp and resp.status_code == 200:
                try:
                    data = resp.json()
                    for item in data.get("staticRoutes", []) or []:
                        page = item.get("page")
                        if page:
                            self._add_route(page)
                    for item in data.get("dynamicRoutes", []) or []:
                        page = item.get("page")
                        if page:
                            self._add_route(page)
                    return
                except Exception:
                    continue

    def _extract_routes_from_middleware_manifest(self):
        if not self.build_id:
            return
        url = f"{self.target}/_next/static/{self.build_id}/_middlewareManifest.json"
        resp = self.fetch(url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                for section in ["middleware", "functions", "sortedMiddleware"]:
                    value = data.get(section)
                    if isinstance(value, dict):
                        for route in value.keys():
                            self._add_route(route)
                    elif isinstance(value, list):
                        for route in value:
                            if isinstance(route, str):
                                self._add_route(route)
            except Exception:
                pass

    # ==================== JS AND ENDPOINT DISCOVERY ====================

    def collect_javascript(self, html: str, assets: List[str]):
        self.log('info', 'Collecting JavaScript files...')
        js_urls: List[str] = []

        for asset in assets:
            if asset.endswith(".js") or "/_next/static/" in asset:
                js_urls.append(asset)

        for match in re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html):
            js_urls.append(normalize_url(self.target, match))

        for match in re.findall(r'/_next/static/[^"\']+\.js', html):
            js_urls.append(self.target + match)

        js_urls = dedupe_preserve(js_urls)[:self.config.max_js_files]
        self.log('info', f'Found {len(js_urls)} JavaScript files')

        def download_js(url: str):
            resp = self.fetch(url, max_bytes=self.config.max_js_bytes)
            if not resp or resp.status_code >= 400:
                return
            filename = url.split("/")[-1].split("?")[0] or "bundle.js"
            self.save_file(resp.content, 'js', filename)
            self._increment_stat('js_files')

            text = resp.content.decode("utf-8", errors="ignore")
            if self.config.collect_endpoints:
                endpoints = self.extract_endpoints_from_js(text)
                if endpoints:
                    with self._lock:
                        for ep in endpoints:
                            self.endpoint_candidates.add(ep)
                            self.endpoint_sources.setdefault(ep, set()).add(filename)

            map_urls = extract_sourcemap_urls(text, url)
            map_urls.append(f"{url}.map")
            map_urls = dedupe_preserve(map_urls)
            for map_url in map_urls:
                map_resp = self.fetch(map_url, max_bytes=self.config.max_map_bytes)
                if not map_resp or map_resp.status_code >= 400:
                    continue
                try:
                    data = json.loads(map_resp.content)
                    if 'mappings' in data or 'sources' in data:
                        map_name = filename + '.map'
                        self.save_file(map_resp.content, 'maps', map_name)
                        self._increment_stat('sourcemaps')
                except Exception:
                    continue

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = [executor.submit(download_js, url) for url in js_urls]
            for future in futures:
                future.result()

        if self.config.collect_endpoints:
            with self._lock:
                self.stats['endpoints_discovered'] = len(self.endpoint_candidates)

    def extract_endpoints_from_js(self, text: str) -> Set[str]:
        if not text:
            return set()
        raw: Set[str] = set()
        patterns = [
            r'fetch\(\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|patch|delete)\(\s*["\']([^"\']+)["\']',
            r'\b(?:GET|POST|PUT|PATCH|DELETE)\s+["\']([^"\']+)["\']',
        ]
        for pattern in patterns:
            for match in re.findall(pattern, text):
                raw.add(match)

        for match in re.findall(r'["\'](/(?:api|graphql|gql|v\d+|internal|auth|account|user|users|search|config|settings)[^"\']*)["\']', text):
            raw.add(match)

        for match in re.findall(r'["\'](https?://[^"\']+)["\']', text):
            raw.add(match)

        endpoints = set()
        for value in raw:
            candidate = value.strip()
            if not candidate:
                continue
            if not self._looks_like_endpoint(candidate):
                continue
            endpoints.add(candidate)
        return endpoints

    def _looks_like_endpoint(self, value: str) -> bool:
        if len(value) > 300:
            return False
        lower = value.lower()
        if lower.startswith("data:") or lower.startswith("javascript:"):
            return False
        path = lower.split("?", 1)[0]
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            return False
        if value.startswith("/"):
            return True
        if value.startswith("http://") or value.startswith("https://"):
            return True
        if value.startswith("//"):
            return True
        return False

    def _normalize_endpoint(self, value: str) -> Optional[str]:
        cleaned = value.strip()
        if cleaned.startswith("//"):
            cleaned = "https:" + cleaned
        if cleaned.startswith("/"):
            cleaned = self.target + cleaned
        if not cleaned.startswith("http://") and not cleaned.startswith("https://"):
            return None
        cleaned = cleaned.split("#", 1)[0]
        if not self._is_allowed_url(cleaned):
            return None
        return cleaned

    def collect_endpoint_samples(self):
        if not self.endpoint_candidates:
            return
        if not self.config.fetch_endpoints:
            return
        self.log('info', 'Collecting endpoint response samples...')

        endpoints = []
        for value in self.endpoint_candidates:
            normalized = self._normalize_endpoint(value)
            if normalized:
                endpoints.append(normalized)

        endpoints = dedupe_preserve(endpoints)[:self.config.max_endpoints]

        def fetch_endpoint(url: str):
            resp = self.fetch(url, max_bytes=self.config.max_endpoint_bytes)
            if not resp or resp.status_code >= 400:
                return
            content_type = resp.headers.get("content-type", "")
            parsed = urlparse(url)
            path = parsed.path.strip("/") or "root"
            safe = self._safe_filename(path.replace("/", "_"))
            digest = hashlib.sha1(url.encode("utf-8")).hexdigest()[:10]
            if "json" in content_type.lower():
                try:
                    data = resp.json()
                    self.save_json(data, 'endpoints', f"endpoint_{safe}_{digest}.json")
                except Exception:
                    self.save_file(resp.content, 'endpoints', f"endpoint_{safe}_{digest}.json")
            else:
                if len(resp.text) <= 100000:
                    self.save_file(resp.content, 'endpoints', f"endpoint_{safe}_{digest}.txt")
            self._increment_stat('endpoint_responses')

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = [executor.submit(fetch_endpoint, url) for url in endpoints]
            for future in futures:
                future.result()

    # ==================== OTHER COLLECTIONS ====================

    def collect_manifests(self):
        if not self.build_id:
            return
        self.log('info', 'Collecting build manifests...')
        manifests = [
            f"/_next/static/{self.build_id}/_buildManifest.js",
            f"/_next/static/{self.build_id}/_ssgManifest.js",
            f"/_next/static/{self.build_id}/_middlewareManifest.js",
            f"/_next/static/{self.build_id}/_serverActionsManifest.json",
            f"/_next/static/{self.build_id}/server-actions-manifest.json",
            f"/_next/static/{self.build_id}/routes-manifest.json",
            f"/_next/static/{self.build_id}/_routesManifest.json",
            f"/_next/static/{self.build_id}/app-build-manifest.json",
        ]
        for manifest in manifests:
            url = self.target + manifest
            resp = self.fetch(url, max_bytes=self.config.max_response_bytes)
            if resp and resp.status_code == 200:
                filename = manifest.split('/')[-1]
                self.save_file(resp.content, 'config', filename)
                self._increment_stat('config_files')
                self.log('download', f'Manifest: {filename}')

    def collect_graphql_schema(self):
        if not self.config.collect_graphql:
            return
        self.log('info', 'Collecting GraphQL schemas...')
        endpoints = ['/graphql', '/api/graphql', '/api/gql', '/gql', '/query']
        introspection_query = """
        query IntrospectionQuery {
            __schema {
                queryType { name }
                mutationType { name }
                subscriptionType { name }
                types {
                    kind
                    name
                    description
                    fields(includeDeprecated: true) {
                        name
                        description
                        args {
                            name
                            description
                            type { name kind ofType { name kind ofType { name kind } } }
                            defaultValue
                        }
                        type { name kind ofType { name kind ofType { name kind } } }
                        isDeprecated
                        deprecationReason
                    }
                    inputFields {
                        name
                        description
                        type { name kind ofType { name kind } }
                        defaultValue
                    }
                    interfaces { name kind }
                    enumValues(includeDeprecated: true) {
                        name
                        description
                        isDeprecated
                        deprecationReason
                    }
                    possibleTypes { name kind }
                }
                directives {
                    name
                    description
                    locations
                    args {
                        name
                        description
                        type { name kind ofType { name kind } }
                        defaultValue
                    }
                }
            }
        }
        """
        for endpoint in endpoints:
            url = self.target + endpoint
            if not self._is_allowed_url(url):
                continue
            try:
                resp = self.session.post(
                    url,
                    json={'query': introspection_query},
                    headers={'Content-Type': 'application/json'},
                    timeout=self.config.timeout,
                )
                self.request_count += 1
                if resp.status_code == 200 and '__schema' in resp.text:
                    filename = f"graphql_schema_{endpoint.replace('/', '_')}.json"
                    self.save_file(resp.content, 'graphql', filename)
                    self._increment_stat('graphql_schemas')
                    self.log('download', f'GraphQL Schema: {endpoint}')
            except Exception:
                continue

    def collect_config_files(self):
        self.log('info', 'Collecting config files...')
        config_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt',
            '/package.json',
            '/vercel.json',
            '/next.config.js',
            '/manifest.json',
            '/site.webmanifest',
            '/asset-manifest.json',
            '/.env',
            '/.env.local',
            '/.env.production',
            '/env.json',
            '/config.json',
            '/.git/config',
            '/.git/HEAD',
        ]
        for config in config_files:
            url = self.target + config
            resp = self.fetch(url, max_bytes=1_000_000)
            if not resp or resp.status_code >= 400:
                continue
            if b'<!DOCTYPE' in resp.content[:500] or b'<html' in resp.content[:500]:
                continue
            filename = config.replace('/', '_').lstrip('_')
            self.save_file(resp.content, 'config', filename)
            self._increment_stat('config_files')
            self.log('download', f'Config: {config}')

    def collect_api_samples(self):
        if not self.config.collect_api_samples:
            return
        self.log('info', 'Collecting API response samples...')
        api_paths = {
            '/api/health',
            '/api/status',
            '/api/config',
            '/api/user',
            '/api/users',
            '/api/me',
            '/api/profile',
            '/api/account',
            '/api/auth/session',
            '/api/auth/csrf',
            '/api/auth/providers',
        }
        for route in self.routes:
            if '/api/' in route:
                api_paths.add(route)
        api_paths.update(self.api_paths)
        api_list = list(api_paths)[:self.config.max_api_samples]

        def fetch_api(path: str):
            url = self.target + path
            resp = self.fetch(url, max_bytes=1_000_000)
            if not resp or resp.status_code >= 400:
                return
            try:
                data = resp.json()
                filename = path.replace('/', '_').lstrip('_') + '.json'
                self.save_json(data, 'api', filename)
                self._increment_stat('api_responses')
            except Exception:
                if len(resp.text) <= 10000:
                    filename = path.replace('/', '_').lstrip('_') + '.txt'
                    self.save_file(resp.content, 'api', filename)
                    self._increment_stat('api_responses')

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = [executor.submit(fetch_api, path) for path in api_list]
            for future in futures:
                future.result()

    def collect_data_routes(self):
        if not self.config.collect_data_routes:
            return
        if not self.build_id:
            return
        self.log('info', 'Collecting /_next/data routes...')
        data_paths = set(self.data_route_paths)

        for route in self.routes:
            if "[" in route or "]" in route:
                continue
            route = route.strip('/')
            if route:
                data_paths.add(f"/_next/data/{self.build_id}/{route}.json")
                data_paths.add(f"/_next/data/{self.build_id}/{route}/index.json")
            else:
                data_paths.add(f"/_next/data/{self.build_id}/index.json")

        common_pages = [
            'index', 'home', 'about', 'contact',
            'login', 'signin', 'signup', 'register',
            'dashboard', 'admin', 'profile', 'account', 'settings',
            'user', 'users', 'search', 'products', 'orders',
        ]
        for page in common_pages:
            data_paths.add(f"/_next/data/{self.build_id}/{page}.json")

        data_list = list(data_paths)[:self.config.max_data_routes]

        def fetch_data(path: str):
            url = f"{self.target}{path}"
            resp = self.fetch(url, max_bytes=self.config.max_response_bytes)
            if not resp or resp.status_code >= 400:
                return
            try:
                data = resp.json()
                safe = self._safe_filename(path.strip("/").replace("/", "_") or "root")
                digest = hashlib.sha1(path.encode("utf-8")).hexdigest()[:10]
                self.save_json(data, 'data_routes', f"data_{safe}_{digest}.json")
                self._increment_stat('data_routes')
            except Exception:
                return

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = [executor.submit(fetch_data, path) for path in data_list]
            for future in futures:
                future.result()

    def collect_page_next_data(self):
        if not self.config.collect_page_next_data:
            return
        if not self.routes:
            return
        self.log('info', 'Collecting per-page __NEXT_DATA__...')
        routes = list(self.routes)[:self.config.max_page_routes]

        def fetch_page(route: str):
            url = f"{self.target}{route}"
            resp = self.fetch(url, max_bytes=self.config.max_page_bytes)
            if not resp or resp.status_code >= 400:
                return
            html = resp.content.decode("utf-8", errors="replace")
            label = self._route_slug(route)
            if self.config.save_raw_html:
                self.save_file(resp.content, 'pages', f"{label}.html")
                self._increment_stat('page_html')
            self._extract_next_data(html, label)
            self._extract_inline_json(html, label)

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = [executor.submit(fetch_page, route) for route in routes]
            for future in futures:
                future.result()

    def collect_rsc_data(self):
        if not self.config.collect_rsc:
            return
        if not self.routes:
            return
        self.log('info', 'Collecting RSC flight data...')
        headers = {
            'RSC': '1',
            'Next-Router-State-Tree': '%5B%22%22%5D',
            'Next-Router-Prefetch': '1',
        }
        for route in list(self.routes)[:self.config.max_page_routes]:
            url = f"{self.target}{route}"
            resp = self.fetch(url, headers=headers, max_bytes=self.config.max_page_bytes)
            if not resp or resp.status_code >= 400:
                continue
            content_type = resp.headers.get('content-type', '')
            if 'text/x-component' in content_type or resp.text.startswith('0:'):
                name = self._route_slug(route)
                self.save_file(resp.content, 'data', f"rsc_{name}.txt")
                self._increment_stat('data_files')

    # ==================== MAIN ====================

    def run(self):
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Next.js File Collector v2.0{Colors.END}")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"Output: {self.project_dir}")
        print(f"{'='*70}\n")

        self.auto_import_miner_report()
        if self.config.route_file:
            self.load_routes_from_file(self.config.route_file)

        html, assets = self.collect_homepage()
        if not html:
            return None

        self.discover_routes(html)
        self.collect_javascript(html, assets)
        self.collect_manifests()
        self.collect_config_files()
        self.collect_page_next_data()
        self.collect_data_routes()
        self.collect_api_samples()
        self.collect_graphql_schema()
        self.collect_rsc_data()
        if self.config.collect_endpoints:
            self.collect_endpoint_samples()

        return self.generate_summary()

    def generate_summary(self):
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}COLLECTION COMPLETE{Colors.END}")
        print(f"{'='*70}")

        print(f"\n{Colors.CYAN}Files Collected:{Colors.END}")
        print(f"  JavaScript Files: {self.stats['js_files']}")
        print(f"  Source Maps: {self.stats['sourcemaps']}")
        print(f"  Data Files: {self.stats['data_files']}")
        print(f"  GraphQL Schemas: {self.stats['graphql_schemas']}")
        print(f"  Config Files: {self.stats['config_files']}")
        print(f"  API Responses: {self.stats['api_responses']}")
        print(f"  Endpoint Responses: {self.stats['endpoint_responses']}")
        print(f"\n  Total Size: {self.stats['total_bytes'] / 1024 / 1024:.2f} MB")

        print(f"\n{Colors.CYAN}Discovery:{Colors.END}")
        print(f"  Routes: {len(self.routes)}")
        print(f"  Endpoints Discovered: {self.stats['endpoints_discovered']}")
        print(f"  Per-Page __NEXT_DATA__: {self.stats['page_next_data']}")
        print(f"  Inline JSON Blobs: {self.stats['inline_json']}")
        print(f"  Request Count: {self.request_count}")

        print(f"\n{Colors.CYAN}Project Directory:{Colors.END}")
        print(f"  {os.path.abspath(self.project_dir)}")

        summary = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'build_id': self.build_id,
            'request_count': self.request_count,
            'stats': self.stats,
            'routes': list(self.routes),
            'data_route_paths': list(self.data_route_paths),
            'api_paths': list(self.api_paths),
            'endpoint_candidates': list(self.endpoint_candidates),
            'endpoint_sources': {
                k: sorted(list(v))
                for k, v in self.endpoint_sources.items()
            },
            'security_findings': self.security_findings,
            'security_summary': summarize_findings(self.security_findings),
            'imports': self.imported,
        }

        summary_path = os.path.join(self.project_dir, 'collection_summary.json')
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"\n{Colors.GREEN}Summary saved: {summary_path}{Colors.END}")

        if self.stats['sourcemaps'] > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}[!] SOURCE MAPS FOUND - Review for exposed source code.{Colors.END}")

        if self.stats['graphql_schemas'] > 0:
            print(f"{Colors.YELLOW}{Colors.BOLD}[!] GRAPHQL SCHEMAS FOUND - Review schema exposure.{Colors.END}")

        return summary


def main():
    parser = argparse.ArgumentParser(description='Next.js File Collector (passive)')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-o', '--output', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=12, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=20, help='Request timeout')
    parser.add_argument('--retries', type=int, default=2, help='Retry count')
    parser.add_argument('--backoff', type=float, default=0.3, help='Retry backoff factor')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify TLS certificates')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-save-html', action='store_true', help='Do not save raw HTML pages')
    parser.add_argument('--no-graphql', action='store_true', help='Skip GraphQL introspection')
    parser.add_argument('--no-api-samples', action='store_true', help='Skip API response samples')
    parser.add_argument('--no-endpoints', action='store_true', help='Skip JS endpoint discovery')
    parser.add_argument('--no-endpoint-fetch', action='store_true', help='Do not fetch endpoint samples')
    parser.add_argument('--no-page-next-data', action='store_true', help='Skip per-page __NEXT_DATA__')
    parser.add_argument('--no-data-routes', action='store_true', help='Skip /_next/data collection')
    parser.add_argument('--no-rsc', action='store_true', help='Skip RSC flight data')
    parser.add_argument('--max-bytes', type=int, default=5_000_000, help='Max response size')
    parser.add_argument('--max-js-bytes', type=int, default=5_000_000, help='Max JS response size')
    parser.add_argument('--max-map-bytes', type=int, default=5_000_000, help='Max source map size')
    parser.add_argument('--max-page-bytes', type=int, default=5_000_000, help='Max page size')
    parser.add_argument('--max-endpoint-bytes', type=int, default=2_000_000, help='Max endpoint response size')
    parser.add_argument('--max-assets', type=int, default=400, help='Max assets to consider')
    parser.add_argument('--max-js', type=int, default=200, help='Max JS files to download')
    parser.add_argument('--max-pages', type=int, default=80, help='Max routes for page collection')
    parser.add_argument('--max-data-routes', type=int, default=120, help='Max /_next/data routes')
    parser.add_argument('--max-endpoints', type=int, default=120, help='Max endpoint samples')
    parser.add_argument('--max-api', type=int, default=80, help='Max API samples')
    parser.add_argument('--allow-host', action='append', default=[], help='Allowed hostnames')
    parser.add_argument('--allow-suffix', action='append', default=[], help='Allowed host suffixes')
    parser.add_argument('--import-miner-report', help='Path to mining_report.json')
    parser.add_argument('--no-import-miner', action='store_true', help='Disable auto import of miner report')
    parser.add_argument('--route-file', help='File with one route per line')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    config = CollectorConfig(
        output_dir=args.output,
        concurrency=args.threads,
        timeout=args.timeout,
        retries=args.retries,
        backoff_factor=args.backoff,
        delay=args.delay,
        verify_ssl=args.verify_ssl,
        no_color=args.no_color,
        verbose=args.verbose,
        save_raw_html=not args.no_save_html,
        collect_graphql=not args.no_graphql,
        collect_api_samples=not args.no_api_samples,
        collect_endpoints=not args.no_endpoints,
        fetch_endpoints=not args.no_endpoint_fetch,
        collect_page_next_data=not args.no_page_next_data,
        collect_data_routes=not args.no_data_routes,
        collect_rsc=not args.no_rsc,
        max_response_bytes=args.max_bytes,
        max_js_bytes=args.max_js_bytes,
        max_map_bytes=args.max_map_bytes,
        max_page_bytes=args.max_page_bytes,
        max_endpoint_bytes=args.max_endpoint_bytes,
        max_assets=args.max_assets,
        max_js_files=args.max_js,
        max_page_routes=args.max_pages,
        max_data_routes=args.max_data_routes,
        max_endpoints=args.max_endpoints,
        max_api_samples=args.max_api,
        allowed_hosts=args.allow_host,
        allowed_suffixes=args.allow_suffix,
        auto_import_miner=not args.no_import_miner,
        import_miner_report=args.import_miner_report,
        route_file=args.route_file,
    )

    collector = FileCollector(args.target, config)
    collector.run()


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
DNA Hunter v2.0
Extract unique DNA fingerprint from web applications

DNA Components:
1. Technology Stack - Frameworks, libraries, versions
2. Build Configuration - Webpack config, chunk patterns
3. Route DNA - All routes including hidden/lazy-loaded
4. State DNA - Redux/MobX store shape, initial state
5. API DNA - All endpoints, parameters, response patterns
6. Error DNA - Error messages, stack traces, internal paths
7. Auth DNA - Session handling, token patterns
8. Data Flow DNA - Input sources -> Processing -> Sinks

Author: Security Research Team
"""

import requests
import json
import re
import os
import sys
import hashlib
import base64
import time
from urllib.parse import urlparse, urljoin, parse_qs, unquote
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Set, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
urllib3.disable_warnings()

from discovery_utils import (
    dedupe_preserve,
    extract_html_assets,
    extract_link_header_assets,
    normalize_url,
)
from security_checks import evaluate_security_headers, summarize_findings


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


@dataclass
class DNAConfig:
    timeout: int = 20
    concurrency: int = 10
    max_js_files: int = 100
    max_js_bytes: int = 3_000_000
    max_html_bytes: int = 2_000_000
    max_config_bytes: int = 2_000_000
    max_chunks: int = 200
    max_secrets: int = 200
    retries: int = 2
    backoff_factor: float = 0.3
    delay: float = 0.0
    verify_ssl: bool = False
    no_color: bool = False
    redact_secrets: bool = True
    verbose: bool = False
    output_dir: str = "dna_analysis"
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_suffixes: List[str] = field(default_factory=list)


class DNAHunter:
    def __init__(self, target: str, config: DNAConfig = None):
        self.target = target.rstrip('/')
        self.config = config or DNAConfig()
        self.hostname = urlparse(target).netloc
        self.allowed_hosts = {h.lower() for h in self.config.allowed_hosts}
        self.allowed_suffixes = {
            s.lower() if s.startswith(".") else f".{s.lower()}"
            for s in self.config.allowed_suffixes
        }

        self.session = self._build_session()
        self.request_count = 0
        self.security_findings: List[Dict] = []

        # DNA Storage
        self.dna = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'technology': {},
            'build': {},
            'routes': {},
            'state': {},
            'api': {},
            'errors': {},
            'auth': {},
            'data_flow': {},
            'secrets': [],
            'unique_patterns': [],
            'security_findings': [],
            'security_summary': {},
            'request_count': 0,
            'risk_assessment': [],
        }

        # Collected data
        self.js_content = {}
        self.html_content = {}
        self.config_files = {}
        self.api_responses = {}
        self.errors_collected = []

        # Output
        self.output_path = os.path.join(self.config.output_dir, self.hostname)
        os.makedirs(self.output_path, exist_ok=True)

    def log(self, level: str, msg: str):
        if self.config.no_color or not sys.stdout.isatty():
            prefix = f"[{level.upper()}]"
        else:
            colors = {
                'info': Colors.BLUE,
                'success': Colors.GREEN,
                'warning': Colors.YELLOW,
                'critical': Colors.RED,
                'dna': Colors.PURPLE,
                'found': Colors.CYAN,
            }
            prefix = f"{colors.get(level, '')}[{level.upper()}]{Colors.END}"
        print(f"{prefix} {msg}")

    def _build_session(self) -> requests.Session:
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
        limit = max_bytes or self.config.max_html_bytes
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

    def _load_text_file(self, path: str, max_bytes: int) -> Optional[str]:
        try:
            if os.path.getsize(path) > max_bytes:
                return None
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception:
            return None

    def _load_collected_assets(self, collected_dir: str) -> Tuple[Optional[str], Dict[str, str], Dict[str, str]]:
        html = None
        js_files: Dict[str, str] = {}
        config_files: Dict[str, str] = {}
        if not collected_dir or not os.path.exists(collected_dir):
            return html, js_files, config_files

        page_dirs = [
            os.path.join(collected_dir, "pages"),
            os.path.join(collected_dir, "01_html"),
            collected_dir,
        ]
        for page_dir in page_dirs:
            candidate = os.path.join(page_dir, "homepage.html")
            if os.path.exists(candidate):
                html = self._load_text_file(candidate, self.config.max_html_bytes)
                if html:
                    break

        js_dirs = [
            os.path.join(collected_dir, "javascript"),
            os.path.join(collected_dir, "01_javascript"),
        ]
        for js_dir in js_dirs:
            if not os.path.exists(js_dir):
                continue
            for filename in os.listdir(js_dir):
                if not filename.endswith(".js"):
                    continue
                if len(js_files) >= self.config.max_js_files:
                    break
                content = self._load_text_file(
                    os.path.join(js_dir, filename),
                    self.config.max_js_bytes,
                )
                if content is not None:
                    js_files[filename] = content

        config_dirs = [
            os.path.join(collected_dir, "config"),
            os.path.join(collected_dir, "02_config"),
        ]
        for cfg_dir in config_dirs:
            if not os.path.exists(cfg_dir):
                continue
            for filename in os.listdir(cfg_dir):
                if len(config_files) >= 50:
                    break
                if not any(filename.endswith(ext) for ext in [".json", ".js", ".txt"]):
                    continue
                content = self._load_text_file(
                    os.path.join(cfg_dir, filename),
                    self.config.max_config_bytes,
                )
                if content is not None:
                    config_files[filename] = content

        return html, js_files, config_files

    def _extract_build_id_hint(self, html: str) -> Optional[str]:
        if not html:
            return None
        patterns = [
            r'"buildId"\s*:\s*"([^"]+)"',
            r'/_next/static/([a-zA-Z0-9_-]{20,})/',
            r'"b"\s*:\s*"([a-zA-Z0-9_-]{20,})"',
        ]
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                return match.group(1)
        return None

    def _discover_js_urls(self, html: str, headers: Dict[str, str]) -> List[str]:
        assets = extract_html_assets(html, self.target)
        assets.extend(extract_link_header_assets(headers, self.target))
        js_urls = []
        for asset in assets:
            if asset.endswith(".js") or "/_next/static/" in asset:
                js_urls.append(asset)
        for match in re.findall(r'/_next/static/[^"\']+\.js', html):
            js_urls.append(self.target + match)
        return dedupe_preserve(js_urls)[:self.config.max_js_files]

    def _fetch_js_files(self, urls: List[str]) -> Dict[str, str]:
        js_files: Dict[str, str] = {}
        if not urls:
            return js_files

        def fetch_one(url: str) -> Optional[Tuple[str, str]]:
            resp = self.fetch(url, max_bytes=self.config.max_js_bytes)
            if not resp or resp.status_code >= 400:
                return None
            filename = url.split("/")[-1].split("?")[0] or "bundle.js"
            text = resp.content.decode("utf-8", errors="replace")
            return filename, text

        with ThreadPoolExecutor(max_workers=self.config.concurrency) as executor:
            futures = {executor.submit(fetch_one, url): url for url in urls}
            for future in as_completed(futures):
                result = future.result()
                if not result:
                    continue
                filename, text = result
                if filename not in js_files:
                    js_files[filename] = text
                if len(js_files) >= self.config.max_js_files:
                    break

        return js_files

    def collect_config_files(self, build_id: Optional[str]):
        config_paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/.well-known/security.txt",
            "/manifest.json",
            "/site.webmanifest",
            "/asset-manifest.json",
            "/package.json",
            "/vercel.json",
            "/next.config.js",
        ]
        if build_id:
            config_paths.extend([
                f"/_next/static/{build_id}/_buildManifest.js",
                f"/_next/static/{build_id}/_ssgManifest.js",
                f"/_next/static/{build_id}/_middlewareManifest.json",
                f"/_next/static/{build_id}/routes-manifest.json",
                f"/_next/static/{build_id}/_routesManifest.json",
                f"/_next/static/{build_id}/app-build-manifest.json",
                f"/_next/static/{build_id}/_serverActionsManifest.json",
                f"/_next/static/{build_id}/server-actions-manifest.json",
            ])

        for path in config_paths:
            url = f"{self.target}{path}"
            resp = self.fetch(url, max_bytes=self.config.max_config_bytes)
            if not resp or resp.status_code >= 400:
                continue
            if b'<!DOCTYPE' in resp.content[:500] or b'<html' in resp.content[:500]:
                continue
            name = path.strip("/").replace("/", "_") or "root"
            if name not in self.config_files:
                self.config_files[name] = resp.content.decode("utf-8", errors="replace")

    def _redact_value(self, value: str, keep: int = 4) -> str:
        if not value:
            return value
        if len(value) <= keep * 2:
            return value[:keep] + "..." if len(value) > keep else value
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
        return f"{value[:keep]}...{value[-keep:]}:{digest}"

    def _normalize_endpoint(self, endpoint: str) -> Optional[str]:
        if not endpoint:
            return None
        endpoint = endpoint.strip()
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            parsed = urlparse(endpoint)
            if parsed.netloc and parsed.netloc != self.hostname:
                return None
            endpoint = parsed.path or "/"
        if not endpoint.startswith("/"):
            return None
        endpoint = endpoint.split("?", 1)[0].split("#", 1)[0]
        return endpoint

    def assess_risks(self) -> List[Dict[str, object]]:
        risks: List[Dict[str, object]] = []
        if self.dna.get('secrets'):
            risks.append({
                "risk": "Exposed secrets indicators",
                "reason": "Potential secret patterns detected in public assets",
                "count": len(self.dna.get('secrets', [])),
            })
        if self.dna.get('routes', {}).get('hidden'):
            risks.append({
                "risk": "Hidden routes present",
                "reason": "Hidden or internal routes detected in assets",
                "count": len(self.dna.get('routes', {}).get('hidden', [])),
            })
        if self.dna.get('errors', {}).get('debug_endpoints'):
            risks.append({
                "risk": "Debug endpoints referenced",
                "reason": "Debug or internal endpoints referenced in assets",
                "count": len(self.dna.get('errors', {}).get('debug_endpoints', [])),
            })
        if self.dna.get('data_flow', {}).get('potential_vulns'):
            risks.append({
                "risk": "Potential client-side data flow risks",
                "reason": "Source-to-sink patterns detected in client code",
                "count": len(self.dna.get('data_flow', {}).get('potential_vulns', [])),
            })
        if self.security_findings:
            high = [f for f in self.security_findings if f.get("severity") == "HIGH"]
            medium = [f for f in self.security_findings if f.get("severity") == "MEDIUM"]
            if high:
                risks.append({
                    "risk": "Security header weakness",
                    "reason": "High severity header findings detected",
                    "count": len(high),
                })
            elif medium:
                risks.append({
                    "risk": "Security header gaps",
                    "reason": "Medium severity header findings detected",
                    "count": len(medium),
                })
        return risks

    # ==================== TECHNOLOGY DNA ====================

    def extract_technology_dna(self, html: str, js_files: Dict[str, str]):
        """Extract technology stack fingerprint"""
        self.log('info', '=== EXTRACTING TECHNOLOGY DNA ===')

        tech = {
            'frameworks': [],
            'libraries': [],
            'versions': {},
            'build_tools': [],
            'cdn': [],
            'analytics': [],
            'unique_markers': [],
        }

        # Framework detection
        framework_patterns = [
            (r'__NEXT_DATA__', 'Next.js'),
            (r'__NEXT_ROUTER__', 'Next.js'),
            (r'__NUXT__', 'Nuxt.js'),
            (r'ng-version', 'Angular'),
            (r'data-reactroot', 'React'),
            (r'data-v-[a-f0-9]+', 'Vue.js'),
            (r'ember-view', 'Ember.js'),
            (r'data-svelte', 'Svelte'),
            (r'_sveltekit', 'SvelteKit'),
            (r'__remix', 'Remix'),
            (r'gatsby', 'Gatsby'),
            (r'astro-island', 'Astro'),
            (r'__qwik', 'Qwik'),
            (r'solid-start', 'SolidStart'),
        ]

        for pattern, name in framework_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                tech['frameworks'].append(name)

        # Next.js specific version detection
        if 'Next.js' in tech['frameworks']:
            # From build manifest
            match = re.search(r'"version"\s*:\s*"([^"]+)"', html)
            if match:
                tech['versions']['next'] = match.group(1)

            # App Router vs Pages Router
            if 'self.__next_f' in html:
                tech['build_tools'].append('Next.js App Router (RSC)')
            else:
                tech['build_tools'].append('Next.js Pages Router')

        # React version from JS
        for filename, content in js_files.items():
            # React version
            match = re.search(r'React\.version\s*=\s*["\']([^"\']+)["\']', content)
            if match:
                tech['versions']['react'] = match.group(1)

            # Bundler/build hints
            if 'webpackChunk' in content:
                tech['build_tools'].append('Webpack 5')
            elif 'webpackJsonp' in content:
                tech['build_tools'].append('Webpack 4')
            if 'vite/client' in content or '__vite' in content:
                tech['build_tools'].append('Vite')
            if 'esbuild' in content:
                tech['build_tools'].append('esbuild')
            if 'rollup' in content:
                tech['build_tools'].append('Rollup')
            if 'parcelRequire' in content:
                tech['build_tools'].append('Parcel')
            if '__turbopack' in content or 'turbopack' in content:
                tech['build_tools'].append('Turbopack')
            if '__swc' in content or 'swc' in content:
                tech['build_tools'].append('SWC')

            # Popular libraries
            lib_patterns = [
                (r'axios', 'axios'),
                (r'lodash', 'lodash'),
                (r'moment', 'moment.js'),
                (r'dayjs', 'dayjs'),
                (r'apollo', 'Apollo GraphQL'),
                (r'@tanstack/react-query', 'TanStack Query'),
                (r'swr', 'SWR'),
                (r'zustand', 'Zustand'),
                (r'redux', 'Redux'),
                (r'mobx', 'MobX'),
                (r'recoil', 'Recoil'),
                (r'jotai', 'Jotai'),
                (r'framer-motion', 'Framer Motion'),
                (r'@emotion', 'Emotion'),
                (r'styled-components', 'styled-components'),
                (r'tailwindcss', 'Tailwind CSS'),
                (r'next-auth', 'NextAuth.js'),
                (r'auth0', 'Auth0'),
                (r'clerk', 'Clerk'),
                (r'contentful', 'Contentful'),
                (r'sanity', 'Sanity'),
                (r'strapi', 'Strapi'),
                (r'prismic', 'Prismic'),
            ]

            for pattern, name in lib_patterns:
                if re.search(pattern, content, re.IGNORECASE) and name not in tech['libraries']:
                    tech['libraries'].append(name)

        # CDN detection from HTML
        cdn_patterns = [
            (r'cdn\.jsdelivr\.net', 'jsDelivr'),
            (r'cdnjs\.cloudflare\.com', 'cdnjs'),
            (r'unpkg\.com', 'unpkg'),
            (r'fonts\.googleapis\.com', 'Google Fonts'),
            (r'ajax\.googleapis\.com', 'Google CDN'),
            (r'cdn\.shopify\.com', 'Shopify CDN'),
            (r'assets\.vercel\.com', 'Vercel'),
            (r'netlify', 'Netlify'),
        ]

        for pattern, name in cdn_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                tech['cdn'].append(name)

        # Analytics
        analytics_patterns = [
            (r'google-analytics\.com|gtag|ga\(', 'Google Analytics'),
            (r'segment\.com|analytics\.js', 'Segment'),
            (r'hotjar', 'Hotjar'),
            (r'mixpanel', 'Mixpanel'),
            (r'amplitude', 'Amplitude'),
            (r'heap', 'Heap'),
            (r'fullstory', 'FullStory'),
            (r'sentry', 'Sentry'),
            (r'datadog', 'Datadog'),
            (r'newrelic', 'New Relic'),
        ]

        for pattern, name in analytics_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                tech['analytics'].append(name)
        for filename, content in js_files.items():
            for pattern, name in analytics_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    tech['analytics'].append(name)

        # package.json dependency hints
        pkg = None
        for name, content in self.config_files.items():
            if name.endswith("package.json"):
                try:
                    pkg = json.loads(content)
                except Exception:
                    pkg = None
                break
        if pkg:
            deps = {}
            deps.update(pkg.get("dependencies", {}) or {})
            deps.update(pkg.get("devDependencies", {}) or {})
            for dep_name, dep_version in deps.items():
                if dep_name in ["next", "react", "react-dom", "vue", "nuxt", "svelte", "@sveltejs/kit"]:
                    tech['versions'][dep_name] = str(dep_version)
                if dep_name in ["next", "nuxt", "react", "vue", "svelte", "@sveltejs/kit", "astro", "remix"]:
                    tech['frameworks'].append(dep_name)
                if dep_name in [
                    "axios", "lodash", "moment", "dayjs", "graphql", "apollo-client",
                    "@tanstack/react-query", "swr", "zustand", "redux", "mobx", "recoil",
                    "jotai", "next-auth", "@auth0/auth0-spa-js", "@clerk/clerk-js"
                ]:
                    tech['libraries'].append(dep_name)

        tech['frameworks'] = dedupe_preserve(tech['frameworks'])
        tech['libraries'] = dedupe_preserve(tech['libraries'])
        tech['build_tools'] = dedupe_preserve(tech['build_tools'])
        tech['cdn'] = dedupe_preserve(tech['cdn'])
        tech['analytics'] = dedupe_preserve(tech['analytics'])

        self.dna['technology'] = tech

        self.log('dna', f"Frameworks: {', '.join(tech['frameworks']) or 'Unknown'}")
        self.log('dna', f"Libraries: {len(tech['libraries'])} detected")
        self.log('dna', f"Versions: {tech['versions']}")

        return tech

    # ==================== BUILD DNA ====================

    def extract_build_dna(self, html: str, js_files: Dict[str, str]):
        """Extract build configuration DNA"""
        self.log('info', '=== EXTRACTING BUILD DNA ===')

        build = {
            'build_id': None,
            'chunk_pattern': None,
            'chunk_names': [],
            'dynamic_imports': [],
            'feature_flags': [],
            'environment': None,
            'deploy_id': None,
            'asset_prefix': None,
            'base_path': None,
            'i18n_locales': [],
            'default_locale': None,
            'trailing_slash': None,
            'runtime_config_keys': [],
            'output': None,
        }

        # Build ID
        match = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
        if match:
            build['build_id'] = match.group(1)
        else:
            match = re.search(r'/_next/static/([a-zA-Z0-9_-]{20,})/', html)
            if match:
                build['build_id'] = match.group(1)
        if not build['build_id']:
            for _, content in self.config_files.items():
                match = re.search(r'"buildId"\s*:\s*"([^"]+)"', content)
                if match:
                    build['build_id'] = match.group(1)
                    break

        # Chunk patterns - extract all chunk names
        chunk_patterns = set()
        for filename, content in js_files.items():
            # Webpack chunk names
            for match in re.findall(r'["\']([a-zA-Z0-9_-]+)["\']\s*:\s*\[\s*["\'][a-f0-9]+["\']', content):
                chunk_patterns.add(match)

            # Dynamic imports
            for match in re.findall(r'import\s*\(\s*["\']([^"\']+)["\']', content):
                build['dynamic_imports'].append(match)

            # Lazy routes
            for match in re.findall(r'React\.lazy\s*\(\s*\(\)\s*=>\s*import\s*\(["\']([^"\']+)["\']', content):
                build['dynamic_imports'].append(match)

        # Chunk names from manifests
        for name, content in self.config_files.items():
            if name.endswith("_buildManifest.js") or name.endswith("app-build-manifest.json"):
                for match in re.findall(r'["\']([a-zA-Z0-9_-]+)["\']\s*:\s*\[', content):
                    chunk_patterns.add(match)

        build['chunk_names'] = list(chunk_patterns)[:50]  # Limit

        # Feature flags
        for filename, content in js_files.items():
            # Common feature flag patterns
            flag_patterns = [
                r'FEATURE_([A-Z_]+)',
                r'feature\.([a-zA-Z_]+)',
                r'featureFlags\.([a-zA-Z_]+)',
                r'isEnabled\(["\']([^"\']+)["\']',
                r'hasFeature\(["\']([^"\']+)["\']',
                r'__DEV__',
                r'__PROD__',
                r'process\.env\.([A-Z_]+)',
            ]

            for pattern in flag_patterns:
                for match in re.findall(pattern, content):
                    if match and match not in build['feature_flags']:
                        build['feature_flags'].append(match)

        # Environment hints
        env_hints = []
        for filename, content in js_files.items():
            if 'development' in content.lower():
                env_hints.append('development')
            if 'staging' in content.lower():
                env_hints.append('staging')
            if 'production' in content.lower():
                env_hints.append('production')

        if env_hints:
            build['environment'] = list(set(env_hints))

        # __NEXT_DATA__ build hints
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.+?)</script>', html or "", re.DOTALL)
        if match:
            try:
                next_data = json.loads(match.group(1))
                if next_data.get("assetPrefix"):
                    build['asset_prefix'] = str(next_data.get("assetPrefix"))
                if next_data.get("basePath"):
                    build['base_path'] = str(next_data.get("basePath"))
                if isinstance(next_data.get("locales"), list):
                    build['i18n_locales'] = next_data.get("locales")
                if next_data.get("defaultLocale"):
                    build['default_locale'] = str(next_data.get("defaultLocale"))
                if next_data.get("trailingSlash") is not None:
                    build['trailing_slash'] = bool(next_data.get("trailingSlash"))
                runtime_config = next_data.get("runtimeConfig") or {}
                if isinstance(runtime_config, dict):
                    build['runtime_config_keys'] = list(runtime_config.keys())[:30]
            except Exception:
                pass

        # next.config.js hints
        for name, content in self.config_files.items():
            if name.endswith("next.config.js"):
                match = re.search(r'basePath\s*:\s*["\']([^"\']+)["\']', content)
                if match:
                    build['base_path'] = match.group(1)
                match = re.search(r'assetPrefix\s*:\s*["\']([^"\']+)["\']', content)
                if match:
                    build['asset_prefix'] = match.group(1)
                match = re.search(r'trailingSlash\s*:\s*(true|false)', content)
                if match:
                    build['trailing_slash'] = match.group(1) == "true"
                match = re.search(r'output\s*:\s*["\']([^"\']+)["\']', content)
                if match:
                    build['output'] = match.group(1)

        # Vercel/Deploy ID
        match = re.search(r'VERCEL_DEPLOYMENT_ID["\']?\s*[:=]\s*["\']([^"\']+)["\']', html)
        if match:
            build['deploy_id'] = match.group(1)

        build['dynamic_imports'] = dedupe_preserve(build['dynamic_imports'])
        build['feature_flags'] = dedupe_preserve(build['feature_flags'])

        self.dna['build'] = build

        self.log('dna', f"Build ID: {build['build_id']}")
        self.log('dna', f"Chunks: {len(build['chunk_names'])}")
        self.log('dna', f"Dynamic imports: {len(build['dynamic_imports'])}")
        self.log('dna', f"Feature flags: {build['feature_flags'][:10]}")

        return build

    # ==================== ROUTE DNA ====================

    def extract_route_dna(self, html: str, js_files: Dict[str, str]):
        """Extract all routes including hidden ones"""
        self.log('info', '=== EXTRACTING ROUTE DNA ===')

        routes = {
            'static': [],
            'dynamic': [],
            'api': [],
            'hidden': [],
            'lazy': [],
            'admin': [],
            'auth': [],
        }

        # From collected manifest files
        for name, content in self.config_files.items():
            if name.endswith("routes-manifest.json") or name.endswith("_routesManifest.json"):
                try:
                    data = json.loads(content)
                    for item in data.get("staticRoutes", []) or []:
                        page = item.get("page")
                        if page and page not in routes['static']:
                            routes['static'].append(page)
                    for item in data.get("dynamicRoutes", []) or []:
                        page = item.get("page")
                        if page and page not in routes['dynamic']:
                            routes['dynamic'].append(page)
                except Exception:
                    pass
            elif name.endswith("_middlewareManifest.json"):
                try:
                    data = json.loads(content)
                    for section in ["middleware", "functions", "sortedMiddleware"]:
                        value = data.get(section)
                        if isinstance(value, dict):
                            for key in value.keys():
                                if key not in routes['hidden']:
                                    routes['hidden'].append(key)
                        elif isinstance(value, list):
                            for key in value:
                                if isinstance(key, str) and key not in routes['hidden']:
                                    routes['hidden'].append(key)
                except Exception:
                    pass
            elif name.endswith("_ssgManifest.js"):
                match = re.search(r"__SSG_MANIFEST\\s*=\\s*new Set\\((\\[.*?\\])\\)", content)
                if match:
                    try:
                        data = json.loads(match.group(1))
                        for route in data:
                            if isinstance(route, str) and route not in routes['static']:
                                routes['static'].append(route)
                    except Exception:
                        pass
            elif name.endswith("_buildManifest.js") or name.endswith("app-build-manifest.json"):
                for route in re.findall(r'\"(/[^\\\"]*)\"', content):
                    if route.startswith("/api"):
                        if route not in routes['api']:
                            routes['api'].append(route)
                    elif "[" in route:
                        if route not in routes['dynamic']:
                            routes['dynamic'].append(route)
                    else:
                        if route not in routes['static']:
                            routes['static'].append(route)
            elif name.endswith("sitemap.xml"):
                for loc in re.findall(r"<loc>([^<]+)</loc>", content):
                    parsed = urlparse(loc)
                    if parsed.netloc == self.hostname and parsed.path:
                        if parsed.path not in routes['static']:
                            routes['static'].append(parsed.path)

        # From build manifest
        match = re.search(r'self\.__BUILD_MANIFEST\s*=\s*(\{.+?\});', html, re.DOTALL)
        if match:
            try:
                manifest_text = match.group(1)
                for route in re.findall(r'"(/[^"]*)":', manifest_text):
                    if '[' in route:
                        routes['dynamic'].append(route)
                    elif route.startswith('/api'):
                        routes['api'].append(route)
                    else:
                        routes['static'].append(route)
            except:
                pass

        # From JS files
        route_patterns = [
            (r'path:\s*["\']([^"\']+)["\']', 'static'),
            (r'route:\s*["\']([^"\']+)["\']', 'static'),
            (r'href:\s*["\']([^"\']+)["\']', 'static'),
            (r'to:\s*["\']([^"\']+)["\']', 'static'),
            (r'navigate\(["\']([^"\']+)["\']', 'static'),
            (r'push\(["\']([^"\']+)["\']', 'static'),
            (r'replace\(["\']([^"\']+)["\']', 'static'),
        ]

        for filename, content in js_files.items():
            for pattern, rtype in route_patterns:
                for match in re.findall(pattern, content):
                    if match.startswith('/') and match not in routes[rtype]:
                        # Categorize
                        if '/admin' in match.lower():
                            routes['admin'].append(match)
                        elif any(p in match.lower() for p in ['/auth', '/login', '/signin', '/signup', '/register']):
                            routes['auth'].append(match)
                        elif '/api/' in match:
                            routes['api'].append(match)
                        elif match not in routes['static']:
                            routes['static'].append(match)

        # Hidden routes (from lazy imports)
        for filename, content in js_files.items():
            for match in re.findall(r'import\s*\(\s*["\'][./]*pages?(/[^"\']+)["\']', content):
                if match not in routes['lazy']:
                    routes['lazy'].append(match)

            # Hidden admin/internal routes
            for match in re.findall(r'["\']/(internal|_internal|__internal|debug|_debug|admin|_admin|backstage|dashboard)[^"\']*["\']', content):
                if match not in routes['hidden']:
                    routes['hidden'].append(match)

        # Dedupe
        for key in routes:
            routes[key] = dedupe_preserve(routes[key])

        self.dna['routes'] = routes

        total = sum(len(v) for v in routes.values())
        self.log('dna', f"Total routes: {total}")
        self.log('dna', f"API routes: {len(routes['api'])}")
        self.log('dna', f"Admin routes: {routes['admin']}")
        self.log('dna', f"Hidden routes: {routes['hidden']}")

        return routes

    # ==================== STATE DNA ====================

    def extract_state_dna(self, html: str, js_files: Dict[str, str]):
        """Extract state management DNA"""
        self.log('info', '=== EXTRACTING STATE DNA ===')

        state = {
            'type': None,  # redux, mobx, zustand, etc.
            'initial_state': {},
            'reducers': [],
            'actions': [],
            'stores': [],
            'sensitive_keys': [],
        }

        # Detect state management type
        for filename, content in js_files.items():
            if 'createStore' in content or 'configureStore' in content:
                state['type'] = 'Redux'
            elif 'makeAutoObservable' in content or 'observable' in content:
                state['type'] = 'MobX'
            elif 'create(' in content and 'zustand' in content.lower():
                state['type'] = 'Zustand'
            elif 'atom(' in content or 'selector(' in content:
                state['type'] = 'Recoil'

        # Extract __NEXT_DATA__ initial state
        match = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.+?)</script>', html, re.DOTALL)
        if match:
            try:
                next_data = json.loads(match.group(1))
                props = next_data.get('props', {}).get('pageProps', {})

                # Look for sensitive keys
                sensitive_patterns = ['user', 'auth', 'token', 'session', 'email', 'phone',
                                     'password', 'secret', 'key', 'api', 'credential', 'private']

                def find_sensitive(obj, path=''):
                    if isinstance(obj, dict):
                        for k, v in obj.items():
                            new_path = f"{path}.{k}" if path else k
                            for pattern in sensitive_patterns:
                                if pattern in k.lower():
                                    state['sensitive_keys'].append({
                                        'path': new_path,
                                        'key': k,
                                        'type': type(v).__name__,
                                        'sample': str(v)[:100] if not any(p in k.lower() for p in ['password', 'secret', 'token', 'key']) else '[REDACTED]'
                                    })
                            find_sensitive(v, new_path)
                    elif isinstance(obj, list):
                        for i, item in enumerate(obj[:5]):  # Limit
                            find_sensitive(item, f"{path}[{i}]")

                find_sensitive(props)
                state['initial_state'] = {'keys': list(props.keys())[:20]}

            except:
                pass

        # Extract Redux action types
        for filename, content in js_files.items():
            # Action types
            for match in re.findall(r'type:\s*["\']([A-Z_]+)["\']', content):
                if match not in state['actions']:
                    state['actions'].append(match)

            # Reducer names
            for match in re.findall(r'(\w+)Reducer', content):
                if match not in state['reducers']:
                    state['reducers'].append(match)

        self.dna['state'] = state

        self.log('dna', f"State type: {state['type']}")
        self.log('dna', f"Sensitive keys found: {len(state['sensitive_keys'])}")
        if state['sensitive_keys']:
            for sk in state['sensitive_keys'][:5]:
                self.log('found', f"  {sk['path']}: {sk['type']}")

        return state

    # ==================== API DNA ====================

    def extract_api_dna(self, js_files: Dict[str, str]):
        """Extract complete API DNA"""
        self.log('info', '=== EXTRACTING API DNA ===')

        api = {
            'endpoints': [],
            'methods': {},
            'parameters': {},
            'headers': [],
            'auth_patterns': [],
            'graphql': {
                'queries': [],
                'mutations': [],
                'fragments': [],
            }
        }

        for filename, content in js_files.items():
            # REST endpoints with methods
            rest_patterns = [
                (r'\.get\s*\(\s*[`"\']([^`"\']+)[`"\']', 'GET'),
                (r'\.post\s*\(\s*[`"\']([^`"\']+)[`"\']', 'POST'),
                (r'\.put\s*\(\s*[`"\']([^`"\']+)[`"\']', 'PUT'),
                (r'\.patch\s*\(\s*[`"\']([^`"\']+)[`"\']', 'PATCH'),
                (r'\.delete\s*\(\s*[`"\']([^`"\']+)[`"\']', 'DELETE'),
                (r'fetch\s*\(\s*[`"\']([^`"\']+)[`"\']', 'FETCH'),
            ]

            for pattern, method in rest_patterns:
                for match in re.findall(pattern, content):
                    endpoint = self._normalize_endpoint(match)
                    if endpoint:
                        if endpoint not in api['endpoints']:
                            api['endpoints'].append(endpoint)
                            api['methods'][endpoint] = method

            # Parameters from URLs
            for match in re.findall(r'\?([^"\'`]+)["\'\`]', content):
                params = parse_qs(match)
                for param in params.keys():
                    if param not in api['parameters']:
                        api['parameters'][param] = []
                    # Sample value
                    val = params[param][0] if params[param] else ''
                    if val and val not in api['parameters'][param]:
                        api['parameters'][param].append(val[:50])

            # Auth headers
            auth_patterns = [
                r'Authorization["\']?\s*:\s*[`"\']([^`"\']+)',
                r'Bearer\s+([^"\'`\s]+)',
                r'x-api-key["\']?\s*:\s*[`"\']([^`"\']+)',
                r'X-Auth-Token["\']?\s*:\s*[`"\']([^`"\']+)',
            ]

            for pattern in auth_patterns:
                for match in re.findall(pattern, content, re.IGNORECASE):
                    if match and match not in api['auth_patterns']:
                        api['auth_patterns'].append(self._redact_value(match))

            # GraphQL
            # Queries
            for match in re.findall(r'query\s+(\w+)\s*[\(\{]', content):
                if match not in api['graphql']['queries']:
                    api['graphql']['queries'].append(match)

            # Mutations
            for match in re.findall(r'mutation\s+(\w+)\s*[\(\{]', content):
                if match not in api['graphql']['mutations']:
                    api['graphql']['mutations'].append(match)

            # Fragments
            for match in re.findall(r'fragment\s+(\w+)\s+on', content):
                if match not in api['graphql']['fragments']:
                    api['graphql']['fragments'].append(match)

        if self.dna.get('routes'):
            for route in self.dna['routes'].get('api', []) or []:
                normalized = self._normalize_endpoint(route)
                if normalized and normalized not in api['endpoints']:
                    api['endpoints'].append(normalized)

        api['endpoints'] = dedupe_preserve(api['endpoints'])
        api['auth_patterns'] = dedupe_preserve(api['auth_patterns'])
        api['graphql']['queries'] = dedupe_preserve(api['graphql']['queries'])
        api['graphql']['mutations'] = dedupe_preserve(api['graphql']['mutations'])
        api['graphql']['fragments'] = dedupe_preserve(api['graphql']['fragments'])

        self.dna['api'] = api

        self.log('dna', f"Endpoints: {len(api['endpoints'])}")
        self.log('dna', f"Parameters: {list(api['parameters'].keys())[:10]}")
        self.log('dna', f"GraphQL queries: {api['graphql']['queries'][:10]}")
        self.log('dna', f"Auth patterns: {len(api['auth_patterns'])}")

        return api

    # ==================== ERROR DNA ====================

    def extract_error_dna(self, js_files: Dict[str, str]):
        """Extract error handling patterns for information disclosure"""
        self.log('info', '=== EXTRACTING ERROR DNA ===')

        errors = {
            'error_messages': [],
            'stack_patterns': [],
            'internal_paths': [],
            'debug_endpoints': [],
            'error_handlers': [],
        }

        for filename, content in js_files.items():
            # Error messages that might leak info
            for match in re.findall(r'(?:throw\s+new\s+Error|console\.error|\.message)\s*\(\s*[`"\']([^`"\']{10,})[`"\']', content):
                if match not in errors['error_messages']:
                    errors['error_messages'].append(match[:200])

            # Internal paths in errors
            for match in re.findall(r'["\']([/\\][a-zA-Z0-9_/\\.-]+(?:\.ts|\.js|\.tsx|\.jsx))["\']', content):
                if match not in errors['internal_paths'] and '/node_modules/' not in match:
                    errors['internal_paths'].append(match)

            # Debug/dev endpoints
            for match in re.findall(r'["\']/(debug|dev|test|internal|_internal|__[a-z]+)[/a-zA-Z0-9_-]*["\']', content):
                if match not in errors['debug_endpoints']:
                    errors['debug_endpoints'].append(match)

        self.dna['errors'] = errors

        self.log('dna', f"Error messages: {len(errors['error_messages'])}")
        self.log('dna', f"Internal paths: {errors['internal_paths'][:5]}")
        self.log('dna', f"Debug endpoints: {errors['debug_endpoints']}")

        return errors

    # ==================== DATA FLOW DNA ====================

    def extract_dataflow_dna(self, js_files: Dict[str, str]):
        """Extract data flow patterns - sources to sinks"""
        self.log('info', '=== EXTRACTING DATA FLOW DNA ===')

        flow = {
            'sources': {
                'url_params': [],
                'form_inputs': [],
                'cookies': [],
                'storage': [],
                'user_input': [],
            },
            'sinks': {
                'dom': [],
                'eval': [],
                'redirect': [],
                'fetch': [],
                'storage': [],
            },
            'transforms': [],
            'potential_vulns': [],
        }

        for filename, content in js_files.items():
            # Sources - where user input enters
            source_patterns = [
                (r'location\.search', 'url_params'),
                (r'location\.hash', 'url_params'),
                (r'URLSearchParams', 'url_params'),
                (r'useSearchParams', 'url_params'),
                (r'query\s*\.\s*(\w+)', 'url_params'),
                (r'params\s*\.\s*(\w+)', 'url_params'),
                (r'document\.cookie', 'cookies'),
                (r'localStorage\.getItem', 'storage'),
                (r'sessionStorage\.getItem', 'storage'),
                (r'\.value', 'form_inputs'),
                (r'e\.target\.value', 'form_inputs'),
                (r'event\.target\.value', 'form_inputs'),
            ]

            for pattern, source_type in source_patterns:
                if re.search(pattern, content):
                    if pattern not in flow['sources'][source_type]:
                        flow['sources'][source_type].append(pattern)

            # Sinks - dangerous operations
            sink_patterns = [
                (r'\.innerHTML\s*=', 'dom', 'XSS'),
                (r'\.outerHTML\s*=', 'dom', 'XSS'),
                (r'dangerouslySetInnerHTML', 'dom', 'XSS'),
                (r'document\.write', 'dom', 'XSS'),
                (r'insertAdjacentHTML', 'dom', 'XSS'),
                (r'\beval\s*\(', 'eval', 'Code Injection'),
                (r'new\s+Function\s*\(', 'eval', 'Code Injection'),
                (r'setTimeout\s*\(\s*["\']', 'eval', 'Code Injection'),
                (r'setInterval\s*\(\s*["\']', 'eval', 'Code Injection'),
                (r'location\.href\s*=', 'redirect', 'Open Redirect'),
                (r'location\.replace\s*\(', 'redirect', 'Open Redirect'),
                (r'window\.open\s*\(', 'redirect', 'Open Redirect'),
                (r'\.src\s*=', 'dom', 'Resource Injection'),
            ]

            for pattern, sink_type, vuln in sink_patterns:
                matches = re.findall(pattern, content)
                if matches:
                    flow['sinks'][sink_type].append({
                        'pattern': pattern,
                        'count': len(matches),
                        'file': filename,
                        'vuln_type': vuln,
                    })

            # Look for direct source->sink flows
            # This is a simplified check - real taint tracking is much more complex
            dangerous_patterns = [
                (r'innerHTML\s*=\s*[^;]*(?:location|query|params|search)', 'URL param to innerHTML'),
                (r'innerHTML\s*=\s*[^;]*(?:\.value|input)', 'Form input to innerHTML'),
                (r'dangerouslySetInnerHTML[^}]*(?:query|params|props)', 'Props to dangerouslySetInnerHTML'),
                (r'location\.href\s*=\s*[^;]*(?:query|params|input)', 'User input to redirect'),
                (r'eval\s*\([^)]*(?:query|params|input)', 'User input to eval'),
            ]

            for pattern, desc in dangerous_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    flow['potential_vulns'].append({
                        'type': desc,
                        'file': filename,
                        'pattern': pattern,
                    })

        self.dna['data_flow'] = flow

        # Dedupe sources and potential findings
        for key, values in flow['sources'].items():
            flow['sources'][key] = dedupe_preserve(values)
        seen = set()
        uniq_vulns = []
        for item in flow['potential_vulns']:
            key = f"{item.get('type')}:{item.get('file')}"
            if key in seen:
                continue
            seen.add(key)
            uniq_vulns.append(item)
        flow['potential_vulns'] = uniq_vulns

        # Summary
        total_sinks = sum(len(v) for v in flow['sinks'].values())
        self.log('dna', f"Total sinks: {total_sinks}")
        self.log('dna', f"Potential vulns: {len(flow['potential_vulns'])}")

        if flow['potential_vulns']:
            self.log('critical', "POTENTIAL DATA FLOW VULNERABILITIES:")
            for v in flow['potential_vulns'][:5]:
                self.log('critical', f"  {v['type']} in {v['file']}")

        return flow

    # ==================== SECRETS DNA ====================

    def extract_secrets_dna(self, js_files: Dict[str, str]):
        """Extract potential secrets"""
        self.log('info', '=== EXTRACTING SECRETS DNA ===')

        secrets = []

        secret_patterns = [
            ('AWS Access Key', r'AKIA[0-9A-Z]{16}'),
            ('AWS Secret Key', r'(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)[^\\n]{0,40}["\\\']([A-Za-z0-9/+=]{40})["\\\']'),
            ('GitHub Token', r'gh[pousr]_[A-Za-z0-9_]{36,}'),
            ('GitLab Token', r'glpat-[A-Za-z0-9_-]{20,}'),
            ('Slack Token', r'xox[baprs]-[0-9A-Za-z-]+'),
            ('Slack Webhook', r'https://hooks\\.slack\\.com/services/[A-Za-z0-9/]+'),
            ('Google API Key', r'AIza[0-9A-Za-z_-]{35}'),
            ('Stripe Live Key', r'sk_live_[0-9a-zA-Z]{24,}'),
            ('Stripe Publishable', r'pk_live_[0-9a-zA-Z]{24,}'),
            ('Square Token', r'sq0[a-z]{3}-[0-9A-Za-z_-]{22,}'),
            ('Twilio', r'SK[0-9a-fA-F]{32}'),
            ('SendGrid', r'SG\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9_-]{43}'),
            ('Mailchimp', r'[0-9a-f]{32}-us[0-9]{1,2}'),
            ('Firebase', r'["\\\'][a-z0-9-]+\\.firebaseio\\.com["\\\']'),
            ('JWT', r'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]*'),
            ('Private Key', r'-----BEGIN[A-Z ]+PRIVATE KEY-----'),
            ('OAuth Token', r'ya29\\.[0-9A-Za-z_-]+'),
            ('Basic Auth', r'Basic [A-Za-z0-9+/=]{20,}'),
            ('Bearer Token', r'Bearer [A-Za-z0-9._-]{20,}'),
            ('API Key Generic', r'api[_-]?key["\\\']?\\s*[:=]\\s*["\\\'][a-zA-Z0-9_-]{20,}["\\\']'),
            ('Secret Generic', r'secret["\\\']?\\s*[:=]\\s*["\\\'][a-zA-Z0-9_-]{20,}["\\\']'),
            ('Password', r'password["\\\']?\\s*[:=]\\s*["\\\'][^"\\\']{8,}["\\\']'),
            ('Database URL', r'(?:mongodb|postgres|mysql|redis)://[^\\s"\\\']+'),
        ]

        seen = set()
        sources = list(js_files.items()) + list(self.config_files.items())
        for filename, content in sources:
            for name, pattern in secret_patterns:
                for match in re.findall(pattern, content, re.IGNORECASE):
                    if isinstance(match, tuple):
                        match = next((m for m in match if m), "")
                    if not match:
                        continue
                    if match in ['password', 'secret', 'api_key', 'API_KEY']:
                        continue
                    token = f"{name}:{match}"
                    if token in seen:
                        continue
                    seen.add(token)
                    if len(secrets) >= self.config.max_secrets:
                        break

                    display = self._redact_value(match) if self.config.redact_secrets else match
                    secrets.append({
                        'type': name,
                        'value': display,
                        'hash': hashlib.sha256(match.encode("utf-8")).hexdigest()[:12],
                        'file': filename,
                    })

        self.dna['secrets'] = secrets

        self.log('dna', f"Potential secrets: {len(secrets)}")
        for s in secrets[:5]:
            self.log('critical', f"  [{s['type']}] {s['value']} in {s['file']}")

        return secrets

    # ==================== MAIN ====================

    def run(self, collected_dir: str = None):
        """Run full DNA extraction"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}DNA Hunter v2.0{Colors.END}")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"{'='*70}\n")

        # Collect base data
        self.log('info', 'Collecting base data...')

        html, js_files, config_files = self._load_collected_assets(collected_dir)
        headers = {}

        if html is None:
            resp = self.fetch(self.target, max_bytes=self.config.max_html_bytes)
            if not resp or resp.status_code >= 400:
                self.log('critical', 'Cannot fetch target')
                return None
            html = resp.content.decode("utf-8", errors="replace")
            headers = dict(resp.headers)
            self.security_findings = evaluate_security_headers(
                resp.headers,
                resp.headers.get("content-type", ""),
            )

        if html:
            self.html_content['homepage'] = html

        if config_files:
            self.config_files.update(config_files)
        build_hint = self._extract_build_id_hint(html)
        if not self.config_files:
            self.collect_config_files(build_hint)

        if not js_files:
            js_urls = self._discover_js_urls(html or "", headers)
            js_files = self._fetch_js_files(js_urls)

        self.js_content = js_files
        self.log('success', f'Collected {len(js_files)} JS files')

        # Extract all DNA
        self.extract_technology_dna(html, js_files)
        self.extract_build_dna(html, js_files)
        self.extract_route_dna(html, js_files)
        self.extract_state_dna(html, js_files)
        self.extract_api_dna(js_files)
        self.extract_error_dna(js_files)
        self.extract_dataflow_dna(js_files)
        self.extract_secrets_dna(js_files)

        # Generate report
        return self.generate_report()

    def generate_report(self):
        """Generate DNA report"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}DNA EXTRACTION COMPLETE{Colors.END}")
        print(f"{'='*70}")

        self.dna['security_findings'] = self.security_findings
        self.dna['security_summary'] = summarize_findings(self.security_findings)
        self.dna['request_count'] = self.request_count

        unique_patterns = []
        build_id = self.dna.get('build', {}).get('build_id')
        if build_id:
            unique_patterns.append(f"build:{build_id}")
        for name in sorted(self.js_content.keys())[:50]:
            unique_patterns.append(f"js:{name}")
        for route in self.dna.get('routes', {}).get('hidden', [])[:20]:
            unique_patterns.append(f"hidden:{route}")
        self.dna['unique_patterns'] = dedupe_preserve(unique_patterns)

        self.dna['risk_assessment'] = self.assess_risks()

        # Create unique fingerprint hash
        fingerprint_data = json.dumps({
            'tech': self.dna['technology'],
            'build_id': self.dna['build'].get('build_id'),
            'routes': len(self.dna['routes'].get('static', [])),
        }, sort_keys=True)
        fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

        self.dna['fingerprint'] = fingerprint

        print(f"\n{Colors.PURPLE}DNA FINGERPRINT: {fingerprint}{Colors.END}")

        print(f"\n{Colors.CYAN}DNA Summary:{Colors.END}")
        print(f"  Technology: {', '.join(self.dna['technology'].get('frameworks', []))}")
        print(f"  Build ID: {self.dna['build'].get('build_id', 'Unknown')}")
        print(f"  Total Routes: {sum(len(v) for v in self.dna['routes'].values())}")
        print(f"  API Endpoints: {len(self.dna['api'].get('endpoints', []))}")
        print(f"  State Type: {self.dna['state'].get('type', 'Unknown')}")
        print(f"  Secrets Found: {len(self.dna['secrets'])}")
        print(f"  Potential Vulns: {len(self.dna['data_flow'].get('potential_vulns', []))}")
        if self.security_findings:
            summary = self.dna.get('security_summary', {})
            print(f"  Security Headers: {summary}")

        # Critical findings
        if self.dna['secrets']:
            print(f"\n{Colors.RED}CRITICAL - Secrets Found:{Colors.END}")
            for s in self.dna['secrets'][:5]:
                print(f"  [{s['type']}] in {s['file']}")

        if self.dna['data_flow'].get('potential_vulns'):
            print(f"\n{Colors.RED}CRITICAL - Potential Vulnerabilities:{Colors.END}")
            for v in self.dna['data_flow']['potential_vulns'][:5]:
                print(f"  {v['type']} in {v['file']}")

        if self.dna['routes'].get('hidden'):
            print(f"\n{Colors.YELLOW}Hidden Routes:{Colors.END}")
            for r in self.dna['routes']['hidden'][:10]:
                print(f"  {r}")

        if self.dna['routes'].get('admin'):
            print(f"\n{Colors.YELLOW}Admin Routes:{Colors.END}")
            for r in self.dna['routes']['admin'][:10]:
                print(f"  {r}")

        # Save report
        report_path = os.path.join(self.output_path, 'dna_report.json')
        with open(report_path, 'w') as f:
            json.dump(self.dna, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved: {report_path}{Colors.END}")

        return self.dna


def main():
    import argparse

    parser = argparse.ArgumentParser(description='DNA Hunter - Extract unique fingerprint')
    parser.add_argument('target', help='Target URL')
    parser.add_argument('-c', '--collected', help='Pre-collected directory from master_collector')
    parser.add_argument('-o', '--output', default='dna_analysis', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=20, help='Request timeout')
    parser.add_argument('--max-js', type=int, default=100, help='Max JS files to analyze')
    parser.add_argument('--max-js-bytes', type=int, default=3000000, help='Max JS size in bytes')
    parser.add_argument('--max-html-bytes', type=int, default=2000000, help='Max HTML size in bytes')
    parser.add_argument('--max-config-bytes', type=int, default=2000000, help='Max config size in bytes')
    parser.add_argument('--max-secrets', type=int, default=200, help='Max secrets to record')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests')
    parser.add_argument('--retries', type=int, default=2, help='Retry count')
    parser.add_argument('--backoff', type=float, default=0.3, help='Retry backoff factor')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify TLS certificates')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--no-redact', action='store_true', help='Do not redact secret values')
    parser.add_argument('--allow-host', action='append', default=[], help='Allowed hostnames')
    parser.add_argument('--allow-suffix', action='append', default=[], help='Allowed host suffixes')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    config = DNAConfig(
        output_dir=args.output,
        concurrency=args.threads,
        timeout=args.timeout,
        max_js_files=args.max_js,
        max_js_bytes=args.max_js_bytes,
        max_html_bytes=args.max_html_bytes,
        max_config_bytes=args.max_config_bytes,
        max_secrets=args.max_secrets,
        delay=args.delay,
        retries=args.retries,
        backoff_factor=args.backoff,
        verify_ssl=args.verify_ssl,
        no_color=args.no_color,
        redact_secrets=not args.no_redact,
        allowed_hosts=args.allow_host,
        allowed_suffixes=args.allow_suffix,
        verbose=args.verbose,
    )

    hunter = DNAHunter(args.target, config)
    hunter.run(collected_dir=args.collected)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Sensitive Data Miner v1.0 - Deep Secret & Data Extraction
Extracts ALL sensitive data from Next.js applications

What this tool does:
1. Downloads ALL JavaScript files and source maps
2. Extracts original source code from source maps
3. Scans for 50+ secret patterns (AWS, API keys, tokens, etc.)
4. Extracts __NEXT_DATA__ and analyzes props for PII
5. Decodes RSC (React Server Components) payloads
6. Finds internal URLs, admin endpoints, debug routes
7. Extracts environment variables and config
8. Saves everything to disk for manual analysis

Author: Security Research Team
"""

import requests
import re
import json
import sys
import os
import base64
import hashlib
from urllib.parse import urljoin, urlparse, unquote
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
import urllib3
urllib3.disable_warnings()


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


@dataclass
class SensitiveData:
    """A piece of sensitive data found"""
    category: str  # secret, pii, internal_url, config, credential
    type: str      # aws_key, jwt, email, ssn, internal_api, etc.
    value: str
    source_file: str
    context: str
    confidence: str
    line_number: Optional[int] = None


class SensitiveDataMiner:
    """
    Comprehensive sensitive data extractor - v2.0 with parallel downloads
    """

    def __init__(self, target: str, output_dir: str = ".", verbose: bool = False, threads: int = 10):
        self.target = target.rstrip('/')
        self.output_dir = output_dir
        self.verbose = verbose
        self.threads = threads

        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
        }
        self.session.verify = False

        # Storage
        self.js_files: Dict[str, str] = {}
        self.source_maps: Dict[str, Dict] = {}
        self.original_sources: Dict[str, str] = {}  # Extracted from source maps
        self.next_data: Dict = {}
        self.rsc_payloads: List[str] = []
        self.findings: List[SensitiveData] = []

        # Create output directories
        self.dump_dir = os.path.join(output_dir, self._safe_dirname())
        os.makedirs(os.path.join(self.dump_dir, 'js'), exist_ok=True)
        os.makedirs(os.path.join(self.dump_dir, 'sourcemaps'), exist_ok=True)
        os.makedirs(os.path.join(self.dump_dir, 'original_source'), exist_ok=True)
        os.makedirs(os.path.join(self.dump_dir, 'data'), exist_ok=True)

        # SECRET PATTERNS - 50+ patterns
        self.secret_patterns = {
            # Cloud Provider Keys
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'AWS Secret Key': r'(?i)aws.{0,20}[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'AWS MWS Key': r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
            'Azure Storage Key': r'(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
            'Azure SAS Token': r'\?sv=\d{4}-\d{2}-\d{2}&s[a-z]=.*&sig=[A-Za-z0-9%]+',
            'GCP API Key': r'AIza[0-9A-Za-z_-]{35}',
            'GCP Service Account': r'"type"\s*:\s*"service_account"',

            # API Keys & Tokens
            'GitHub Token': r'gh[pousr]_[A-Za-z0-9_]{36,}',
            'GitHub OAuth': r'gho_[A-Za-z0-9]{36}',
            'GitLab Token': r'glpat-[A-Za-z0-9_-]{20,}',
            'Slack Token': r'xox[baprs]-[0-9]{10,}-[0-9a-zA-Z]{24,}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
            'Discord Token': r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
            'Discord Webhook': r'https://discord\.com/api/webhooks/\d+/[A-Za-z0-9_-]+',
            'Stripe Live Key': r'sk_live_[0-9a-zA-Z]{24,}',
            'Stripe Test Key': r'sk_test_[0-9a-zA-Z]{24,}',
            'Stripe Publishable': r'pk_live_[0-9a-zA-Z]{24,}',
            'PayPal Client ID': r'(?i)paypal.{0,20}client.{0,5}id.{0,10}[\'"]A[A-Za-z0-9_-]{20,}[\'"]',
            'Square Access Token': r'sq0atp-[0-9A-Za-z_-]{22}',
            'Square OAuth': r'sq0csp-[0-9A-Za-z_-]{43}',
            'Twilio Account SID': r'AC[0-9a-f]{32}',
            'Twilio Auth Token': r'(?i)twilio.{0,20}[\'"][0-9a-f]{32}[\'"]',
            'SendGrid API Key': r'SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}',
            'Mailgun API Key': r'key-[0-9a-zA-Z]{32}',
            'Mailchimp API Key': r'[0-9a-f]{32}-us\d{1,2}',
            'Firebase API Key': r'(?i)firebase.{0,20}[\'"][A-Za-z0-9_-]{39}[\'"]',
            'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
            'Algolia API Key': r'(?i)algolia.{0,20}[\'"][a-f0-9]{32}[\'"]',
            'Shopify Access Token': r'shpat_[a-fA-F0-9]{32}',
            'Shopify Shared Secret': r'shpss_[a-fA-F0-9]{32}',

            # Authentication
            'JWT Token': r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
            'Bearer Token': r'Bearer\s+[A-Za-z0-9_-]{20,}',
            'Basic Auth': r'Basic\s+[A-Za-z0-9+/=]{20,}',
            'OAuth Token': r'ya29\.[0-9A-Za-z_-]+',
            'Session Token': r'(?i)session.{0,10}[\'"][a-zA-Z0-9_-]{20,}[\'"]',

            # Cryptographic
            'RSA Private Key': r'-----BEGIN RSA PRIVATE KEY-----',
            'DSA Private Key': r'-----BEGIN DSA PRIVATE KEY-----',
            'EC Private Key': r'-----BEGIN EC PRIVATE KEY-----',
            'OpenSSH Private Key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'PGP Private Key': r'-----BEGIN PGP PRIVATE KEY BLOCK-----',

            # Database
            'MongoDB Connection': r'mongodb(\+srv)?://[^\s<>"\']+',
            'PostgreSQL Connection': r'postgres(ql)?://[^\s<>"\']+',
            'MySQL Connection': r'mysql://[^\s<>"\']+',
            'Redis URL': r'redis://[^\s<>"\']+',

            # Generic Secrets
            'API Key Generic': r'(?i)(api[_-]?key|apikey)[\'"\s:=]+[\'"][a-zA-Z0-9_-]{16,}[\'"]',
            'Secret Key Generic': r'(?i)(secret[_-]?key|secretkey)[\'"\s:=]+[\'"][a-zA-Z0-9_-]{16,}[\'"]',
            'Access Token Generic': r'(?i)(access[_-]?token)[\'"\s:=]+[\'"][a-zA-Z0-9_-]{16,}[\'"]',
            'Auth Token Generic': r'(?i)(auth[_-]?token)[\'"\s:=]+[\'"][a-zA-Z0-9_-]{16,}[\'"]',
            'Password in Code': r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{8,}[\'"]',

            # Heroku & Vercel
            'Heroku API Key': r'(?i)heroku.{0,20}[\'"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'"]',
            'Vercel Token': r'(?i)vercel.{0,20}[\'"][a-zA-Z0-9]{24}[\'"]',

            # NPM
            'NPM Token': r'//registry\.npmjs\.org/:_authToken=[A-Za-z0-9_-]+',
        }

        # PII Patterns
        self.pii_patterns = {
            'Email Address': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'Phone Number': r'(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'Credit Card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
            'IP Address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'Private IP': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b',
        }

        # Internal URL Patterns
        self.internal_patterns = {
            'Internal API': r'(?i)(?:internal|private|admin|staging|dev|test)[.-]?api[^\s"\'<>]*',
            'Admin Panel': r'(?i)/(?:admin|dashboard|manage|control|backend|cms)[^\s"\'<>]*',
            'Debug Endpoint': r'(?i)/(?:debug|test|dev|staging|_debug|_test)[^\s"\'<>]*',
            'GraphQL Endpoint': r'/(?:graphql|api/graphql|gql)[^\s"\'<>]*',
            'Internal Domain': r'(?i)(?:internal|private|corp|staging|dev|test|local)\.[a-z0-9-]+\.[a-z]{2,}',
            'Localhost URL': r'(?:localhost|127\.0\.0\.1|0\.0\.0\.0):\d+[^\s"\'<>]*',
        }

    def _safe_dirname(self) -> str:
        """Create safe directory name from target URL"""
        parsed = urlparse(self.target)
        name = parsed.netloc.replace(':', '_').replace('.', '_')
        return f"dump_{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'error': Colors.RED,
            'secret': Colors.RED + Colors.BOLD,
            'pii': Colors.PURPLE,
            'internal': Colors.CYAN,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def run(self):
        """Run the full mining operation"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.PURPLE}   SENSITIVE DATA MINER v1.0{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"Target: {self.target}")
        print(f"Output: {self.dump_dir}")
        print()

        # Phase 1: Collect all assets
        print(f"\n{Colors.CYAN}[PHASE 1] ASSET COLLECTION{Colors.END}")
        self._collect_assets()

        # Phase 2: Download source maps and extract original source
        print(f"\n{Colors.CYAN}[PHASE 2] SOURCE MAP EXTRACTION{Colors.END}")
        self._extract_source_maps()

        # Phase 3: Extract __NEXT_DATA__ and RSC payloads
        print(f"\n{Colors.CYAN}[PHASE 3] NEXT.JS DATA EXTRACTION{Colors.END}")
        self._extract_nextjs_data()

        # Phase 4: Scan for secrets
        print(f"\n{Colors.CYAN}[PHASE 4] SECRET SCANNING{Colors.END}")
        self._scan_for_secrets()

        # Phase 5: Scan for PII
        print(f"\n{Colors.CYAN}[PHASE 5] PII SCANNING{Colors.END}")
        self._scan_for_pii()

        # Phase 6: Find internal URLs
        print(f"\n{Colors.CYAN}[PHASE 6] INTERNAL URL DISCOVERY{Colors.END}")
        self._find_internal_urls()

        # Phase 7: Extract ALL URLs
        print(f"\n{Colors.CYAN}[PHASE 7] COMPREHENSIVE URL EXTRACTION{Colors.END}")
        self._extract_all_urls()

        # Phase 8: GraphQL Analysis
        print(f"\n{Colors.CYAN}[PHASE 8] GRAPHQL ANALYSIS{Colors.END}")
        self._extract_graphql_info()

        # Phase 9: Config & Feature Flags
        print(f"\n{Colors.CYAN}[PHASE 9] CONFIG & FEATURE FLAGS{Colors.END}")
        self._extract_config_and_features()

        # Phase 10: Generate report
        print(f"\n{Colors.CYAN}[PHASE 10] REPORT GENERATION{Colors.END}")
        self._generate_report()

    def _download_js(self, url: str) -> Tuple[str, Optional[str]]:
        """Download a single JS file - used for parallel downloading"""
        try:
            resp = self.session.get(url, timeout=20)
            if resp.status_code == 200:
                return (url, resp.text)
        except requests.RequestException:
            pass
        return (url, None)

    def _collect_assets(self):
        """Collect all JavaScript files with parallel downloading"""
        self.log('info', 'Fetching main page...')

        try:
            resp = self.session.get(self.target, timeout=30)
            html = resp.text

            # Save HTML
            with open(os.path.join(self.dump_dir, 'index.html'), 'w', encoding='utf-8') as f:
                f.write(html)

            # IMPROVED: More comprehensive JS discovery patterns for Next.js 12/13/14+
            js_patterns = [
                # Standard script tags
                r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']',
                # Next.js static paths
                r'"([^"]+/_next/static/[^"]+\.js)"',
                r"'([^']+/_next/static/[^']+\.js)'",
                # Webpack chunks referenced in code
                r'["\'](/(?:_next/)?static/chunks/[^"\']+\.js)["\']',
                r'["\']([^"\']+/chunks/[^"\']+\.js)["\']',
                # Build manifest references
                r'"([^"]+buildManifest\.js)"',
                r'"([^"]+ssgManifest\.js)"',
                r'"([^"]+_buildManifest\.js)"',
                r'"([^"]+_ssgManifest\.js)"',
                # Pages and app router chunks
                r'"([^"]+/pages/[^"]+\.js)"',
                r'"([^"]+/app/[^"]+\.js)"',
                # Framework chunks
                r'"([^"]+framework[^"]*\.js)"',
                r'"([^"]+main[^"]*\.js)"',
                r'"([^"]+webpack[^"]*\.js)"',
                r'"([^"]+polyfills[^"]*\.js)"',
            ]

            js_urls = set()
            for pattern in js_patterns:
                for match in re.findall(pattern, html):
                    url = urljoin(self.target, match)
                    js_urls.add(url)

            # Also try to discover build ID and fetch known chunk patterns
            build_id_match = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
            if build_id_match:
                build_id = build_id_match.group(1)
                self.log('info', f'Found build ID: {build_id}')
                # Try common chunk names with this build ID
                base = urljoin(self.target, f'/_next/static/{build_id}/')
                for chunk in ['_buildManifest.js', '_ssgManifest.js']:
                    js_urls.add(base + chunk)

            # Try common Next.js paths
            common_paths = [
                '/_next/static/chunks/main.js',
                '/_next/static/chunks/webpack.js',
                '/_next/static/chunks/framework.js',
                '/_next/static/chunks/polyfills.js',
                '/_next/static/chunks/pages/_app.js',
                '/_next/static/chunks/pages/_error.js',
            ]
            for path in common_paths:
                js_urls.add(urljoin(self.target, path))

            self.log('info', f'Found {len(js_urls)} potential JavaScript files')

            # PARALLEL DOWNLOAD with ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._download_js, url): url for url in js_urls}
                for future in as_completed(futures):
                    url, content = future.result()
                    if content:
                        self.js_files[url] = content
                        # Save to disk
                        filename = url.split('/')[-1].split('?')[0]
                        if filename:
                            filepath = os.path.join(self.dump_dir, 'js', filename)
                            try:
                                with open(filepath, 'w', encoding='utf-8') as f:
                                    f.write(content)
                            except OSError:
                                pass

            # Second pass: find more JS from downloaded files
            additional_urls = set()
            for content in self.js_files.values():
                for pattern in js_patterns[:6]:  # Use main patterns
                    for match in re.findall(pattern, content):
                        url = urljoin(self.target, match)
                        if url not in self.js_files:
                            additional_urls.add(url)

            if additional_urls:
                self.log('info', f'Found {len(additional_urls)} additional JS files from chunks')
                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    futures = {executor.submit(self._download_js, url): url for url in additional_urls}
                    for future in as_completed(futures):
                        url, content = future.result()
                        if content:
                            self.js_files[url] = content
                            filename = url.split('/')[-1].split('?')[0]
                            if filename:
                                filepath = os.path.join(self.dump_dir, 'js', filename)
                                try:
                                    with open(filepath, 'w', encoding='utf-8') as f:
                                        f.write(content)
                                except OSError:
                                    pass

            self.log('success', f'Downloaded {len(self.js_files)} JavaScript files')

        except requests.RequestException as e:
            self.log('error', f'Asset collection failed: {e}')

    def _extract_source_maps(self):
        """Extract and download ALL source maps"""
        self.log('info', 'Finding source maps...')

        sourcemap_urls = set()

        # Find source map references in JS files
        for url, content in self.js_files.items():
            # Standard source map comment
            matches = re.findall(r'//[#@]\s*sourceMappingURL=(.+)', content)
            for match in matches:
                map_url = match.strip()
                if not map_url.startswith('http'):
                    map_url = urljoin(url, map_url)
                sourcemap_urls.add(map_url)

            # Also try .map extension
            if not url.endswith('.map'):
                sourcemap_urls.add(url + '.map')

        self.log('info', f'Found {len(sourcemap_urls)} potential source maps')

        # Download ALL source maps
        for map_url in sourcemap_urls:
            try:
                resp = self.session.get(map_url, timeout=20)
                if resp.status_code == 200 and resp.text.startswith('{'):
                    try:
                        map_data = resp.json()
                        self.source_maps[map_url] = map_data

                        # Save source map
                        filename = map_url.split('/')[-1].split('?')[0]
                        filepath = os.path.join(self.dump_dir, 'sourcemaps', filename)
                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump(map_data, f, indent=2)

                        # Extract original sources
                        sources = map_data.get('sources', [])
                        sources_content = map_data.get('sourcesContent', [])

                        for i, source_name in enumerate(sources):
                            if i < len(sources_content) and sources_content[i]:
                                content = sources_content[i]
                                self.original_sources[source_name] = content

                                # Save original source
                                safe_name = source_name.replace('/', '_').replace('\\', '_').replace('..', '')
                                safe_name = re.sub(r'[<>:"|?*]', '_', safe_name)
                                filepath = os.path.join(self.dump_dir, 'original_source', safe_name)
                                try:
                                    with open(filepath, 'w', encoding='utf-8') as f:
                                        f.write(content)
                                except:
                                    pass
                    except json.JSONDecodeError:
                        pass
            except:
                pass

        self.log('success', f'Extracted {len(self.source_maps)} source maps')
        self.log('success', f'Recovered {len(self.original_sources)} original source files')

    def _extract_nextjs_data(self):
        """Extract __NEXT_DATA__ and RSC payloads - IMPROVED v2"""
        self.log('info', 'Extracting Next.js data...')

        try:
            resp = self.session.get(self.target, timeout=30)
            html = resp.text

            # IMPROVED: Extract __NEXT_DATA__ - handle JSON with < characters
            # Use a more robust pattern that captures everything between script tags
            next_data_patterns = [
                r'<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
                r'<script\s+id=\'__NEXT_DATA__\'[^>]*>(.*?)</script>',
                r'<script[^>]+id="__NEXT_DATA__"[^>]*>(.*?)</script>',
            ]

            for pattern in next_data_patterns:
                match = re.search(pattern, html, re.DOTALL)
                if match:
                    try:
                        self.next_data = json.loads(match.group(1))
                        # Save
                        filepath = os.path.join(self.dump_dir, 'data', 'next_data.json')
                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump(self.next_data, f, indent=2)
                        self.log('success', 'Extracted __NEXT_DATA__')
                        break
                    except json.JSONDecodeError:
                        continue

            # IMPROVED: Extract RSC payloads - multiple patterns for different Next.js versions
            rsc_patterns = [
                # Next.js 13+
                r'self\.__next_f\.push\(\s*\[\s*[\d,\s]*"([^"]+)"\s*\]\s*\)',
                # Next.js 14+
                r'self\.__next_f\.push\(\s*\[\s*\d+\s*,\s*"([^"]+)"\s*\]\s*\)',
                # Alternative format
                r'self\.__next_f\.push\(\["([^"]+)"\]\)',
                # With escaped quotes
                r'self\.__next_f\.push\(\[[\d,\s]*\\?"([^"\\]+)\\?"\]\)',
                # Inline script data
                r'<script>self\.__next_f\.push\(\[[\d,]*"([^"]+)"\]\)</script>',
            ]

            seen_payloads = set()
            for pattern in rsc_patterns:
                for match in re.findall(pattern, html, re.DOTALL):
                    try:
                        decoded = unquote(match)
                        if decoded not in seen_payloads:
                            seen_payloads.add(decoded)
                            self.rsc_payloads.append(decoded)
                    except Exception:
                        if match not in seen_payloads:
                            seen_payloads.add(match)
                            self.rsc_payloads.append(match)

            if self.rsc_payloads:
                filepath = os.path.join(self.dump_dir, 'data', 'rsc_payloads.json')
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(self.rsc_payloads, f, indent=2)
                self.log('success', f'Extracted {len(self.rsc_payloads)} RSC payloads')

            # Also extract any inline JSON data blocks
            inline_json_patterns = [
                r'type="application/json"[^>]*>(.*?)</script>',
                r'__NUXT__\s*=\s*(\{.*?\});',  # Nuxt.js support
                r'window\.__INITIAL_STATE__\s*=\s*(\{.*?\});',  # Redux initial state
                r'window\.__DATA__\s*=\s*(\{.*?\});',
            ]

            for pattern in inline_json_patterns:
                for match in re.findall(pattern, html, re.DOTALL):
                    try:
                        data = json.loads(match)
                        # Save if it's substantial
                        if len(str(data)) > 100:
                            filename = f'inline_data_{len(self.rsc_payloads)}.json'
                            filepath = os.path.join(self.dump_dir, 'data', filename)
                            with open(filepath, 'w', encoding='utf-8') as f:
                                json.dump(data, f, indent=2)
                            self.rsc_payloads.append(json.dumps(data))
                    except json.JSONDecodeError:
                        pass

        except requests.RequestException as e:
            self.log('error', f'Next.js data extraction failed: {e}')

    def _scan_for_secrets(self):
        """Scan all content for secrets"""
        self.log('info', 'Scanning for secrets...')

        # Combine all content to scan
        all_content = {}

        # JS files
        for url, content in self.js_files.items():
            all_content[url] = content

        # Original sources from source maps
        for name, content in self.original_sources.items():
            all_content[f"[SOURCE_MAP] {name}"] = content

        # Next.js data
        if self.next_data:
            all_content['[NEXT_DATA]'] = json.dumps(self.next_data)

        # RSC payloads
        for i, payload in enumerate(self.rsc_payloads):
            all_content[f'[RSC_PAYLOAD_{i}]'] = payload

        # Scan
        secret_count = 0
        for source, content in all_content.items():
            for secret_type, pattern in self.secret_patterns.items():
                try:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        value = match.group(0)

                        # Skip obvious false positives
                        if self._is_false_positive_secret(value, secret_type):
                            continue

                        # Get context
                        start = max(0, match.start() - 50)
                        end = min(len(content), match.end() + 50)
                        context = content[start:end]

                        finding = SensitiveData(
                            category='secret',
                            type=secret_type,
                            value=value[:100] + '...' if len(value) > 100 else value,
                            source_file=source.split('/')[-1] if '/' in source else source,
                            context=context,
                            confidence='high' if 'Key' in secret_type or 'Token' in secret_type else 'medium'
                        )
                        self.findings.append(finding)
                        secret_count += 1

                        self.log('secret', f'Found {secret_type} in {source.split("/")[-1]}')
                except:
                    pass

        self.log('success', f'Found {secret_count} potential secrets')

    def _is_false_positive_secret(self, value: str, secret_type: str) -> bool:
        """Check if a secret is likely a false positive - IMPROVED v2"""
        value_lower = value.lower()

        # Common false positive indicators
        fp_indicators = [
            'example', 'test', 'demo', 'sample', 'placeholder',
            'xxx', 'your_', 'my_', '${', '{{', 'process.env',
            'undefined', 'null', 'true', 'false', 'localhost',
            'dummy', 'fake', 'mock', 'default', '0000000', '1111111',
        ]

        if any(fp in value_lower for fp in fp_indicators):
            return True

        # Password field references (not actual passwords)
        if secret_type == 'Password in Code':
            # These are form field names, action types, or code references - NOT passwords
            fp_password_patterns = [
                'type=', ':!0', ':!1', ':true', ':false',
                'changepassword', 'createpassword', 'enterpassword',
                'setpassword', 'resetpassword', 'forgotpassword',
                'password:', 'password":', "password':",  # Object keys
                'notifysetpassword', 'editmemberpassword',
                'validatepassword', 'confirmpassword', 'newpassword',
                'passwordfield', 'passwordinput', 'passwordform',
                '"password"', "'password'",  # String literals
            ]
            if any(x in value_lower for x in fp_password_patterns):
                return True

        # Session Token false positives - React/Next.js hooks and state names
        if secret_type == 'Session Token':
            # These are code constructs, not actual session tokens
            fp_session_patterns = [
                'session(', 'session":', "session':",  # Function calls or object keys
                'processstates', 'rendernavigation', 'statedefinition',
                'sessionprovider', 'sessioncontext', 'sessionstate',
                'usesession', 'getsession', 'setsession',
                'createportal', 'statetransition', 'navigationlevel',
            ]
            if any(x in value_lower for x in fp_session_patterns):
                return True

        # JWT false positives - base64 encoded but not actual JWTs
        if secret_type == 'JWT Token':
            # Valid JWTs have 3 parts separated by dots
            parts = value.split('.')
            if len(parts) != 3:
                return True
            # Check if header decodes to valid JSON with alg field
            try:
                import base64
                header = parts[0] + '=' * (4 - len(parts[0]) % 4)  # Pad for base64
                decoded = base64.urlsafe_b64decode(header).decode('utf-8')
                if '"alg"' not in decoded and "'alg'" not in decoded:
                    return True
            except Exception:
                return True  # Can't decode = probably not a valid JWT

        # Generic API Key false positives
        if 'Generic' in secret_type or 'API Key' in secret_type:
            # Skip if it's just a config key name reference
            if any(x in value_lower for x in [
                'apikey":', 'api_key":', 'secretkey":', 'secret_key":',
                'getapikey', 'setapikey', 'validateapikey',
                'process.env', 'config.', 'env.',
            ]):
                return True

        # Bearer token false positives
        if secret_type == 'Bearer Token':
            # Check if it's just the word "Bearer" followed by placeholder
            if any(x in value_lower for x in ['bearer token', 'bearer auth', 'bearer ${', 'bearer {{']):
                return True

        return False

    def _scan_for_pii(self):
        """Scan for personally identifiable information"""
        self.log('info', 'Scanning for PII...')

        # Scan Next.js data (most likely to contain PII)
        content_to_scan = {}

        if self.next_data:
            content_to_scan['[NEXT_DATA]'] = json.dumps(self.next_data)

        for i, payload in enumerate(self.rsc_payloads):
            content_to_scan[f'[RSC_PAYLOAD_{i}]'] = payload

        pii_count = 0
        for source, content in content_to_scan.items():
            for pii_type, pattern in self.pii_patterns.items():
                try:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        value = match.group(0)

                        # Skip common false positives
                        if pii_type == 'Email Address' and '@example' in value.lower():
                            continue

                        finding = SensitiveData(
                            category='pii',
                            type=pii_type,
                            value=value,
                            source_file=source,
                            context='',
                            confidence='medium'
                        )
                        self.findings.append(finding)
                        pii_count += 1

                        self.log('pii', f'Found {pii_type}: {value[:30]}...')
                except:
                    pass

        self.log('success', f'Found {pii_count} potential PII items')

    def _find_internal_urls(self):
        """Find internal/admin/debug URLs"""
        self.log('info', 'Finding internal URLs...')

        all_content = '\n'.join(self.js_files.values())
        all_content += '\n'.join(self.original_sources.values())

        internal_count = 0
        found_urls = set()

        for url_type, pattern in self.internal_patterns.items():
            try:
                matches = re.finditer(pattern, all_content, re.IGNORECASE)
                for match in matches:
                    value = match.group(0)

                    if value in found_urls:
                        continue
                    found_urls.add(value)

                    finding = SensitiveData(
                        category='internal_url',
                        type=url_type,
                        value=value,
                        source_file='combined',
                        context='',
                        confidence='medium'
                    )
                    self.findings.append(finding)
                    internal_count += 1

                    self.log('internal', f'{url_type}: {value[:60]}')
            except:
                pass

        self.log('success', f'Found {internal_count} internal URLs')

    def _extract_all_urls(self):
        """Extract ALL URLs from JS files - comprehensive URL mining"""
        self.log('info', 'Extracting all URLs from JavaScript...')

        all_content = '\n'.join(self.js_files.values())
        all_content += '\n'.join(self.original_sources.values())

        # URL patterns
        url_patterns = [
            # Full URLs
            (r'https?://[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}[a-zA-Z0-9./_?&=#%-]*', 'Full URL'),
            # API endpoints with version
            (r'/v[0-9]+/[a-zA-Z0-9/_-]+', 'Versioned API'),
            # GraphQL endpoints
            (r'/graphql[a-zA-Z0-9/_-]*', 'GraphQL'),
            # REST-like paths
            (r'/api/[a-zA-Z0-9/_-]+', 'API Endpoint'),
        ]

        extracted_urls = {}  # url -> type

        for pattern, url_type in url_patterns:
            for match in re.finditer(pattern, all_content):
                url = match.group(0).strip('"\'')
                # Clean up
                url = url.rstrip('.,;:')
                if len(url) > 10 and url not in extracted_urls:
                    extracted_urls[url] = url_type

        # Categorize URLs
        categories = {
            'internal_apis': [],
            'external_services': [],
            'cdn_assets': [],
            'interesting': [],
        }

        for url, url_type in extracted_urls.items():
            # Skip common noise
            if any(x in url for x in ['w3.org', 'schema.org', 'xmlns', 'reactjs.org']):
                continue

            # Categorize
            if any(x in url.lower() for x in ['prod.cloud', 'internal', 'staging', 'dev.', 'test.', 'corp.']):
                categories['internal_apis'].append((url, url_type))
            elif any(x in url.lower() for x in ['graphql', '/api/', '/v1/', '/v2/']):
                categories['interesting'].append((url, url_type))
            elif any(x in url.lower() for x in ['cdn', 'assets', 'static', '.woff', '.css', '.png', '.ico']):
                categories['cdn_assets'].append((url, url_type))
            else:
                categories['external_services'].append((url, url_type))

        # Save to file
        urls_file = os.path.join(self.dump_dir, 'data', 'extracted_urls.json')
        with open(urls_file, 'w', encoding='utf-8') as f:
            json.dump(categories, f, indent=2)

        # Add interesting ones to findings
        for url, url_type in categories['internal_apis'] + categories['interesting']:
            finding = SensitiveData(
                category='discovered_url',
                type=url_type,
                value=url,
                source_file='js_analysis',
                context='',
                confidence='medium'
            )
            self.findings.append(finding)
            self.log('info', f'[URL] {url_type}: {url[:70]}')

        total = sum(len(v) for v in categories.values())
        self.log('success', f'Extracted {total} URLs ({len(categories["internal_apis"])} internal, {len(categories["interesting"])} interesting)')

    def _extract_graphql_info(self):
        """Extract GraphQL queries, mutations, and schema info"""
        self.log('info', 'Analyzing GraphQL usage...')

        all_content = '\n'.join(self.js_files.values())
        all_content += '\n'.join(self.original_sources.values())

        graphql_data = {
            'endpoints': [],
            'operations': [],
            'fragments': [],
            'types': [],
        }

        # Find GraphQL endpoints
        endpoints = set(re.findall(r'https?://[^"\'\\s]+/graphql[^"\'\\s]*', all_content))
        graphql_data['endpoints'] = list(endpoints)

        # Find operation names (query/mutation names)
        operations = set(re.findall(r'(?:query|mutation)\s+([A-Z][a-zA-Z0-9_]+)', all_content))
        graphql_data['operations'] = list(operations)

        # Find fragment names
        fragments = set(re.findall(r'fragment\s+([A-Z][a-zA-Z0-9_]+)\s+on', all_content))
        graphql_data['fragments'] = list(fragments)

        # Find type names (often in __typename)
        types = set(re.findall(r'__typename["\']?\s*[=:]\s*["\']([A-Z][a-zA-Z0-9_]+)["\']', all_content))
        graphql_data['types'] = list(types)

        # Save
        graphql_file = os.path.join(self.dump_dir, 'data', 'graphql_info.json')
        with open(graphql_file, 'w', encoding='utf-8') as f:
            json.dump(graphql_data, f, indent=2)

        # Add to findings
        for endpoint in graphql_data['endpoints']:
            finding = SensitiveData(
                category='graphql',
                type='GraphQL Endpoint',
                value=endpoint,
                source_file='js_analysis',
                context='',
                confidence='high'
            )
            self.findings.append(finding)
            self.log('info', f'[GraphQL] Endpoint: {endpoint}')

        for op in list(graphql_data['operations'])[:20]:  # Limit output
            self.log('info', f'[GraphQL] Operation: {op}')

        self.log('success', f'Found {len(graphql_data["endpoints"])} endpoints, {len(graphql_data["operations"])} operations, {len(graphql_data["types"])} types')

    def _extract_config_and_features(self):
        """Extract configuration values and feature flags"""
        self.log('info', 'Extracting config and feature flags...')

        all_content = '\n'.join(self.js_files.values())

        config_data = {
            'feature_flags': [],
            'config_keys': [],
            'environment_hints': [],
        }

        # Feature flags (common patterns)
        feature_patterns = [
            r'["\'](?:is|enable|disable|show|hide|allow|has)[A-Z][a-zA-Z0-9_]+["\']',
            r'["\'](?:feature|flag|experiment|test|beta)[._][a-zA-Z0-9_]+["\']',
            r'["\'][a-zA-Z]+(?:Enabled|Disabled|Active|Hidden|Visible)["\']',
        ]

        for pattern in feature_patterns:
            matches = set(re.findall(pattern, all_content))
            for m in matches:
                flag = m.strip('"\'')
                if len(flag) > 5 and flag not in config_data['feature_flags']:
                    config_data['feature_flags'].append(flag)

        # Environment hints
        env_patterns = [
            r'(?:prod|production|staging|dev|development|test|local)[._-](?:api|url|host|server|endpoint)',
            r'(?:API|APP|SERVICE)[._](?:URL|HOST|ENDPOINT|KEY)',
        ]

        for pattern in env_patterns:
            matches = set(re.findall(pattern, all_content, re.IGNORECASE))
            config_data['environment_hints'].extend(list(matches))

        # Save
        config_file = os.path.join(self.dump_dir, 'data', 'config_features.json')
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=2)

        self.log('success', f'Found {len(config_data["feature_flags"])} feature flags, {len(config_data["environment_hints"])} env hints')

    def _generate_report(self):
        """Generate final report"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.PURPLE}   MINING RESULTS{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}")

        # Summary
        by_category = defaultdict(list)
        for f in self.findings:
            by_category[f.category].append(f)

        print(f"\n{Colors.CYAN}Summary:{Colors.END}")
        print(f"  JavaScript files: {len(self.js_files)}")
        print(f"  Source maps extracted: {len(self.source_maps)}")
        print(f"  Original sources recovered: {len(self.original_sources)}")
        print(f"  RSC payloads: {len(self.rsc_payloads)}")
        print()
        print(f"  {Colors.RED}Secrets found: {len(by_category['secret'])}{Colors.END}")
        print(f"  {Colors.PURPLE}PII found: {len(by_category['pii'])}{Colors.END}")
        print(f"  {Colors.CYAN}Internal URLs: {len(by_category['internal_url'])}{Colors.END}")

        # Save report
        report = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'stats': {
                'js_files': len(self.js_files),
                'source_maps': len(self.source_maps),
                'original_sources': len(self.original_sources),
                'rsc_payloads': len(self.rsc_payloads),
                'secrets': len(by_category['secret']),
                'pii': len(by_category['pii']),
                'internal_urls': len(by_category['internal_url']),
            },
            'findings': [
                {
                    'category': f.category,
                    'type': f.type,
                    'value': f.value,
                    'source_file': f.source_file,
                    'confidence': f.confidence,
                }
                for f in self.findings
            ]
        }

        report_path = os.path.join(self.dump_dir, 'report.json')
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        print(f"\n{Colors.GREEN}All data saved to: {self.dump_dir}{Colors.END}")
        print(f"Report: {report_path}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python sensitive_data_miner.py <target_url> [-v]")
        print("\nExample:")
        print("  python sensitive_data_miner.py https://example.com")
        print("\nThis tool will:")
        print("  1. Download ALL JavaScript files")
        print("  2. Extract and save ALL source maps")
        print("  3. Recover original source code")
        print("  4. Scan for 50+ secret patterns")
        print("  5. Find PII (emails, SSNs, credit cards)")
        print("  6. Discover internal/admin URLs")
        print("  7. Save everything to disk for analysis")
        sys.exit(1)

    target = sys.argv[1]
    verbose = '-v' in sys.argv

    miner = SensitiveDataMiner(target, verbose=verbose)
    miner.run()


if __name__ == "__main__":
    main()

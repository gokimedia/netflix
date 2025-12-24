#!/usr/bin/env python3
"""
Wayback Hunter v1.0
Find old/unprotected versions of files via Wayback Machine

Features:
- Search Wayback Machine for historical versions
- Find old source maps that are now protected
- Discover removed endpoints
- Download historical versions

Author: Security Research Team
"""

import requests
import sys
import os
import json
import time
from urllib.parse import urlparse, quote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
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
    END = "\033[0m"


@dataclass
class WaybackConfig:
    timeout: int = 30
    delay: float = 0.5  # Be nice to archive.org
    verbose: bool = False
    output_dir: str = "."
    download_files: bool = False
    analyze_secrets: bool = False
    detect_only: bool = True
    max_download_bytes: int = 5_000_000
    verify_ssl: bool = False
    max_results: int = 100
    retries: int = 2
    backoff_factor: float = 0.3
    allowed_domains: List[str] = field(default_factory=list)


class WaybackHunter:
    def __init__(self, target: str, config: WaybackConfig = None):
        self.target = target.rstrip('/')
        self.config = config or WaybackConfig()
        self.parsed = urlparse(target)
        self.domain = self.parsed.netloc
        self.allowed_domains = {d.lower() for d in self.config.allowed_domains}

        self.session = self._build_session()
        self.request_count = 0

        self.snapshots = []
        self.interesting_files = []

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'critical': Colors.RED,
            'found': Colors.PURPLE,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def _build_session(self):
        session = requests.Session()
        retry = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) WaybackHunter/1.0'
        }
        session.verify = self.config.verify_ssl
        return session

    def _is_allowed_domain(self, domain: str) -> bool:
        if not self.allowed_domains:
            return True
        return domain.lower() in self.allowed_domains

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault("timeout", self.config.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
            self.request_count += 1
            return resp
        except Exception as e:
            if self.config.verbose:
                self.log('warning', f'Request failed: {url} - {e}')
            return None

    def search_cdx(self, url_pattern: str, filters: List[str] = None) -> List[Dict]:
        """Search Wayback Machine CDX API"""
        cdx_url = "https://web.archive.org/cdx/search/cdx"

        params = {
            'url': url_pattern,
            'output': 'json',
            'fl': 'timestamp,original,mimetype,statuscode,digest,length',
            'collapse': 'digest',  # Remove duplicates
            'limit': self.config.max_results,
        }

        if filters:
            params['filter'] = filters

        try:
            resp = self._request("GET", cdx_url, params=params)
            if not resp or resp.status_code != 200:
                return []

            data = resp.json()
            if len(data) <= 1:  # Only header row
                return []

            # Parse results (skip header row)
            results = []
            headers = data[0]
            for row in data[1:]:
                result = dict(zip(headers, row))
                results.append(result)

            return results

        except Exception as e:
            if self.config.verbose:
                self.log('warning', f'CDX search error: {e}')
            return []

    def find_source_maps(self) -> List[Dict]:
        """Find historical source maps"""
        self.log('info', 'Searching for source maps in Wayback Machine...')

        patterns = [
            f"{self.domain}/*.js.map",
            f"{self.domain}/_next/*.map",
            f"{self.domain}/static/*.map",
        ]

        all_maps = []
        for pattern in patterns:
            results = self.search_cdx(pattern)
            for r in results:
                if r.get('statuscode') == '200':
                    all_maps.append(r)

        self.log('success', f'Found {len(all_maps)} historical source maps')
        return all_maps

    def find_js_files(self) -> List[Dict]:
        """Find historical JavaScript files"""
        self.log('info', 'Searching for JavaScript files...')

        patterns = [
            f"{self.domain}/*.js",
            f"{self.domain}/_next/static/*.js",
            f"{self.domain}/static/js/*.js",
        ]

        all_js = []
        for pattern in patterns:
            results = self.search_cdx(pattern, filters=['statuscode:200'])
            all_js.extend(results)

        # Deduplicate by URL
        seen = set()
        unique = []
        for js in all_js:
            url = js.get('original', '')
            if url not in seen:
                seen.add(url)
                unique.append(js)

        self.log('success', f'Found {len(unique)} historical JS files')
        return unique

    def find_config_files(self) -> List[Dict]:
        """Find exposed config files from the past"""
        self.log('info', 'Searching for config files...')

        sensitive_patterns = [
            f"{self.domain}/.env*",
            f"{self.domain}/config*.json",
            f"{self.domain}/package.json",
            f"{self.domain}/vercel.json",
            f"{self.domain}/.git/*",
            f"{self.domain}/env.js",
            f"{self.domain}/settings.json",
        ]

        all_configs = []
        for pattern in sensitive_patterns:
            results = self.search_cdx(pattern, filters=['statuscode:200'])
            all_configs.extend(results)

        self.log('success', f'Found {len(all_configs)} historical config files')
        return all_configs

    def find_api_endpoints(self) -> List[Dict]:
        """Find historical API endpoints"""
        self.log('info', 'Searching for API endpoints...')

        patterns = [
            f"{self.domain}/api/*",
            f"{self.domain}/v1/*",
            f"{self.domain}/v2/*",
            f"{self.domain}/graphql*",
        ]

        all_apis = []
        for pattern in patterns:
            results = self.search_cdx(pattern)
            all_apis.extend(results)

        self.log('success', f'Found {len(all_apis)} historical API endpoints')
        return all_apis

    def download_snapshot(self, timestamp: str, original_url: str, output_dir: str) -> Optional[str]:
        """Download a specific Wayback snapshot"""
        wayback_url = f"https://web.archive.org/web/{timestamp}id_/{original_url}"

        try:
            time.sleep(self.config.delay)
            resp = self._request("GET", wayback_url)

            if resp and resp.status_code == 200:
                if len(resp.content) > self.config.max_download_bytes:
                    return None
                # Generate filename
                parsed = urlparse(original_url)
                filename = parsed.path.replace('/', '_').lstrip('_')
                if not filename:
                    filename = 'index'
                filename = f"{timestamp}_{filename}"

                filepath = os.path.join(output_dir, filename)
                with open(filepath, 'wb') as f:
                    f.write(resp.content)

                return filepath

        except Exception as e:
            if self.config.verbose:
                self.log('warning', f'Download failed: {e}')

        return None

    def analyze_for_secrets(self, content: str, source: str) -> List[Dict]:
        """Analyze content for secrets"""
        import re

        secrets = []
        patterns = [
            ('AWS Key', r'AKIA[0-9A-Z]{16}'),
            ('Stripe Key', r'sk_live_[0-9a-zA-Z]{24,}'),
            ('GitHub Token', r'ghp_[0-9A-Za-z]{36}'),
            ('JWT', r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'),
            ('MongoDB URI', r'mongodb(\+srv)?://[^\s"\']+'),
            ('Private Key', r'-----BEGIN.*PRIVATE KEY-----'),
        ]

        for name, pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                secrets.append({
                    'type': name,
                    'value': match[:50] + '...' if len(match) > 50 else match,
                    'source': source,
                })

        return secrets

    def assess_risks(self, results: Dict) -> List[Dict]:
        risks = []
        if results.get('source_maps'):
            risks.append({
                'risk': 'Historical source maps',
                'reason': 'Archived source maps may expose original source code',
                'count': len(results.get('source_maps', [])),
            })
        if results.get('config_files'):
            risks.append({
                'risk': 'Historical config exposure',
                'reason': 'Archived config files may disclose settings or keys',
                'count': len(results.get('config_files', [])),
            })
        if results.get('api_endpoints'):
            risks.append({
                'risk': 'Historical API surface',
                'reason': 'Archived API endpoints can reveal hidden routes',
                'count': len(results.get('api_endpoints', [])),
            })
        if results.get('secrets_found'):
            risks.append({
                'risk': 'Historical secrets',
                'reason': 'Archived files contain patterns resembling secrets',
                'count': len(results.get('secrets_found', [])),
            })
        return risks

    def run(self) -> Dict:
        """Run full Wayback analysis"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Wayback Hunter v1.0{Colors.END}")
        print(f"{'='*70}")
        print(f"Target: {self.target}")
        print(f"{'='*70}\n")

        if not self._is_allowed_domain(self.domain):
            self.log('critical', f"Domain blocked by allowlist: {self.domain}")
            return {'status': 'blocked'}

        results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'detect_only': self.config.detect_only,
            'source_maps': [],
            'js_files': [],
            'config_files': [],
            'api_endpoints': [],
            'secrets_found': [],
            'downloaded_files': [],
            'request_count': self.request_count,
        }

        # Create output directory
        output_dir = os.path.join(self.config.output_dir, f"wayback_{self.domain}")
        os.makedirs(output_dir, exist_ok=True)

        # Find all file types
        results['source_maps'] = self.find_source_maps()
        results['js_files'] = self.find_js_files()
        results['config_files'] = self.find_config_files()
        results['api_endpoints'] = self.find_api_endpoints()

        # Download and analyze interesting files
        if self.config.detect_only or not self.config.download_files:
            self.log('info', 'Detect-only mode enabled; skipping downloads')
        else:
            self.log('info', '\nDownloading interesting files...')

            # Prioritize source maps and config files
            priority_files = results['source_maps'][:10] + results['config_files'][:10]

            for file_info in priority_files:
                timestamp = file_info.get('timestamp', '')
                original = file_info.get('original', '')

                filepath = self.download_snapshot(timestamp, original, output_dir)
                if filepath:
                    self.log('found', f'Downloaded: {os.path.basename(filepath)}')
                    results['downloaded_files'].append(filepath)

                    # Analyze for secrets (opt-in)
                    if self.config.analyze_secrets:
                        try:
                            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                                content = f.read()
                                secrets = self.analyze_for_secrets(content, filepath)
                                if secrets:
                                    results['secrets_found'].extend(secrets)
                                    for s in secrets:
                                        self.log('critical', f"SECRET FOUND [{s['type']}]: {s['value'][:30]}...")
                        except:
                            pass

        # Summary
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}WAYBACK ANALYSIS COMPLETE{Colors.END}")
        print(f"{'='*70}")

        print(f"\n{Colors.CYAN}Historical Files Found:{Colors.END}")
        print(f"  Source Maps: {len(results['source_maps'])}")
        print(f"  JS Files: {len(results['js_files'])}")
        print(f"  Config Files: {len(results['config_files'])}")
        print(f"  API Endpoints: {len(results['api_endpoints'])}")
        print(f"  Files Downloaded: {len(results['downloaded_files'])}")
        print(f"  Secrets Found: {len(results['secrets_found'])}")

        # Print interesting findings
        if results['source_maps']:
            print(f"\n{Colors.PURPLE}Historical Source Maps:{Colors.END}")
            for sm in results['source_maps'][:5]:
                print(f"  [{sm.get('timestamp', '')[:8]}] {sm.get('original', '')}")

        if results['config_files']:
            print(f"\n{Colors.YELLOW}Historical Config Files:{Colors.END}")
            for cf in results['config_files'][:5]:
                print(f"  [{cf.get('timestamp', '')[:8]}] {cf.get('original', '')}")

        if results['secrets_found']:
            print(f"\n{Colors.RED}SECRETS FOUND IN HISTORICAL FILES:{Colors.END}")
            for s in results['secrets_found']:
                print(f"  [{s['type']}] {s['value']}")

        # Save report
        results['risk_summary'] = self.assess_risks(results)

        report_path = os.path.join(output_dir, 'wayback_report.json')
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)

        print(f"\n{Colors.GREEN}Report saved: {report_path}{Colors.END}")
        print(f"Files saved: {output_dir}")

        return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Wayback Hunter - Find historical files')
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('-o', '--output', default='.', help='Output directory')
    parser.add_argument('--max-results', type=int, default=100, help='Max results per query')
    parser.add_argument('--download', action='store_true', help='Download archived files')
    parser.add_argument('--no-download', action='store_true', help='Skip downloading files')
    parser.add_argument('--analyze-secrets', action='store_true', help='Scan downloaded files for secrets')
    parser.add_argument('--max-download-bytes', type=int, default=5000000, help='Max downloaded file size')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify TLS certificates')
    parser.add_argument('--retries', type=int, default=2, help='Retry count')
    parser.add_argument('--backoff', type=float, default=0.3, help='Retry backoff factor')
    parser.add_argument('--allow-domain', action='append', default=[], help='Allowed domains')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    download_files = args.download and not args.no_download
    config = WaybackConfig(
        output_dir=args.output,
        max_results=args.max_results,
        download_files=download_files,
        detect_only=not download_files,
        analyze_secrets=args.analyze_secrets,
        max_download_bytes=args.max_download_bytes,
        verify_ssl=args.verify_ssl,
        retries=args.retries,
        backoff_factor=args.backoff,
        allowed_domains=args.allow_domain,
        verbose=args.verbose,
    )

    hunter = WaybackHunter(args.target, config)
    hunter.run()


if __name__ == '__main__':
    main()

